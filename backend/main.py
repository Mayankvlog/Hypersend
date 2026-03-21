import json
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request, status, HTTPException, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Match
import logging
from pathlib import Path
import os
import sys
import asyncio
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta, timezone

# Setup logger EARLY - before any other imports that might need logging
logger = logging.getLogger("zaply")
logger.setLevel(logging.INFO)

# CRITICAL: Add parent directory to sys.path so 'backend' module can be imported
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.models import MessageCreate

# WhatsApp-Grade Cryptographic Imports
try:
    import redis.asyncio as redis
except ImportError:
    logger.warning("[WARNING] Redis not available - using fallback cache")
    redis = None
from backend.crypto.signal_protocol import SignalProtocol
from backend.crypto.multi_device import MultiDeviceManager
from backend.crypto.delivery_semantics import DeliveryManager
from backend.crypto.media_encryption import MediaEncryptionService
from backend.workers.fan_out_worker import MessageFanOutWorker
from backend.websocket.websocket_manager import websocket_manager

# Add current directory to Python path for Docker
# CRITICAL: Do NOT reload .env files - config.py handles initialization only once!
sys.path.insert(0, str(Path(__file__).parent))

# SECURITY: Prevent importing config with missing secrets in production
debug_mode = os.getenv("DEBUG", "false").lower() in ("true", "1")
if not os.getenv("SECRET_KEY") and not debug_mode:
    raise RuntimeError("PRODUCTION SAFETY: SECRET_KEY must be set in production")

# CRITICAL: Import config ONCE - module handles .env loading internally
from backend.config import settings

# Import routes
from backend.routes import (
    auth,
    files,
    chats,
    users,
    updates,
    p2p_transfer,
    groups,
    messages,
    channels,
    debug,
    devices,
    e2ee_messages,
    presence,
    status as status_router,
)

from backend.auth.utils import get_current_user

# Import database initialization function
from backend.database import init_database

try:
    from backend.security import SecurityConfig
except Exception as e:
    raise

try:
    from backend.error_handlers import register_exception_handlers
except Exception as e:
    raise

try:
    from backend.redis_cache import init_cache, cleanup_cache
except Exception as e:
    raise


async def _wait_for_redis_with_retry():
    """Wait for Redis to be reachable with retry mechanism and health verification.

    CRITICAL: This function ensures Redis is fully operational before
    the application continues startup. Implements 5 retries with exponential backoff.

    Returns:
        Redis client instance that is guaranteed to be connected and healthy

    Raises:
        RuntimeError: If Redis cannot be connected to after all retries
    """
    from backend.config import settings
    import time

    max_retries = 5
    base_delay = 2  # Base delay in seconds

    # CRITICAL: Use docker service name only, never localhost
    redis_host = getattr(settings, "REDIS_HOST", "redis")
    redis_port = getattr(settings, "REDIS_PORT", 6379)
    redis_password = getattr(settings, "REDIS_PASSWORD", None)
    redis_db = getattr(settings, "REDIS_DB", 0)

    # Enforce docker service name in production
    if redis_host in ("localhost", "127.0.0.1", "::1"):
        logger.error(
            f"[REDIS-HEALTH] CRITICAL: Redis host is {redis_host} - forcing to 'redis'"
        )
        redis_host = "redis"
        logger.info(
            f"[REDIS-HEALTH] Forced Redis host to docker service name: {redis_host}"
        )

    # Clean up empty password
    if redis_password == "":
        redis_password = None

    logger.info(
        f"[REDIS-HEALTH] Starting Redis connection attempts to {redis_host}:{redis_port}/{redis_db}"
    )

    for attempt in range(max_retries):
        try:
            logger.info(
                f"[REDIS-HEALTH] Connection attempt {attempt + 1}/{max_retries} to {redis_host}:{redis_port}"
            )

            # Import Redis here to avoid import issues
            try:
                import redis.asyncio as redis
            except ImportError:
                raise RuntimeError(
                    "Redis library not available - install redis package"
                )

            # Create Redis client with production-safe configuration
            redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                password=redis_password,
                db=redis_db,
                decode_responses=True,  # CRITICAL: Returns strings not bytes
                socket_connect_timeout=10,
                socket_timeout=30,
                health_check_interval=30,  # Reconnect check every 30s
                socket_keepalive=True,
                retry_on_timeout=True,
            )

            try:
                # CRITICAL: Test connection with timeout
                ping_result = await asyncio.wait_for(redis_client.ping(), timeout=15.0)

                if ping_result:
                    logger.info(
                        f"[REDIS-HEALTH] Successfully connected to {redis_host}:{redis_port}/{redis_db}"
                    )

                    # Verify Redis server info
                    try:
                        info = await asyncio.wait_for(
                            redis_client.info("server"), timeout=5.0
                        )
                        logger.info(
                            f"[REDIS-HEALTH] Redis server version: {info.get('redis_version', 'unknown')}"
                        )
                    except Exception as e:
                        logger.warning(
                            f"[REDIS-HEALTH] Could not fetch server info: {e}"
                        )

                    # CRITICAL: Test Redis functionality with actual operations
                    await _verify_redis_functionality(redis_client)

                    logger.info(f"[REDIS-HEALTH] Redis fully verified and ready")
                    return redis_client
                else:
                    raise RuntimeError(
                        f"Redis ping returned False for {redis_host}:{redis_port}"
                    )

            except (asyncio.TimeoutError, Exception) as e:
                # CRITICAL: Cleanup redis_client if initialization fails
                try:
                    await redis_client.aclose()
                except Exception:
                    try:
                        redis_client.close()
                    except Exception:
                        pass

                if isinstance(e, asyncio.TimeoutError):
                    logger.error(
                        f"[REDIS-HEALTH] Connection timeout attempt {attempt + 1}: {e}"
                    )
                else:
                    logger.error(
                        f"[REDIS-HEALTH] Connection error attempt {attempt + 1}: {type(e).__name__}: {e}"
                    )

                # Re-raise to go to outer exception handler
                raise

        except asyncio.TimeoutError as e:
            logger.error(
                f"[REDIS-HEALTH] Connection timeout attempt {attempt + 1}: {e}"
            )
        except Exception as e:
            logger.error(
                f"[REDIS-HEALTH] Connection error attempt {attempt + 1}: {type(e).__name__}: {e}"
            )

        # Retry logic with exponential backoff
        if attempt < max_retries - 1:
            delay = base_delay * (2**attempt)  # Exponential backoff: 2s, 4s, 8s, 16s
            logger.warning(f"[REDIS-HEALTH] Retrying in {delay} seconds...")
            await asyncio.sleep(delay)

    # All retries failed
    error_msg = f"Redis connection failed after {max_retries} attempts to {redis_host}:{redis_port}/{redis_db}"
    logger.error(f"[REDIS-HEALTH] CRITICAL: {error_msg}")
    raise RuntimeError(error_msg)


async def _verify_redis_functionality(redis_client):
    """Verify Redis functionality with test operations.

    CRITICAL: This function ensures Redis is not just connected but fully operational.
    Tests basic operations, pub/sub, and memory usage.

    Args:
        redis_client: Connected Redis client instance

    Raises:
        RuntimeError: If any Redis functionality test fails
    """
    import time
    import uuid

    test_key = f"__redis_functionality_test__{int(time.time())}__{uuid.uuid4().hex[:8]}"
    test_value = {"test": True, "timestamp": time.time(), "data": "verification"}

    try:
        # Test 1: Basic SET/GET operation
        await asyncio.wait_for(
            redis_client.setex(test_key, 60, json.dumps(test_value)), timeout=5.0
        )

        retrieved = await asyncio.wait_for(redis_client.get(test_key), timeout=5.0)

        if not retrieved:
            raise RuntimeError("Redis GET returned None for test key")

        # Verify JSON serialization
        retrieved_data = json.loads(retrieved)
        if retrieved_data.get("test") != True:
            raise RuntimeError("Redis data corruption detected")

        logger.info(f"[REDIS-HEALTH] ✓ Basic SET/GET operations verified")

        # Test 2: Pub/Sub functionality
        test_channel = f"__test_channel__{uuid.uuid4().hex[:8]}"
        test_message = {"type": "test", "data": "pubsub_verification"}

        pubsub = redis_client.pubsub()
        await asyncio.wait_for(pubsub.subscribe(test_channel), timeout=5.0)

        # Publish test message
        await asyncio.wait_for(
            redis_client.publish(test_channel, json.dumps(test_message)), timeout=5.0
        )

        # Helper coroutine to consume pubsub messages with timeout protection
        async def _consume_pubsub(pubsub_obj):
            """Consume pubsub messages and wait for test message."""
            async for message in pubsub_obj.listen():
                if message["type"] == "message":
                    data = json.loads(message["data"])
                    if data.get("type") == "test":
                        return True
            return False

        # Listen for message with timeout
        message_received = False
        try:
            message_received = await asyncio.wait_for(
                _consume_pubsub(pubsub), timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.warning(f"[REDIS-HEALTH] Pub/Sub message receive timed out")
            message_received = False
        finally:
            await pubsub.close()

        if not message_received:
            raise RuntimeError("Redis Pub/Sub functionality test failed")

        logger.info(f"[REDIS-HEALTH] ✓ Pub/Sub functionality verified")

        # Test 3: Memory usage check
        try:
            memory_info = await asyncio.wait_for(
                redis_client.info("memory"), timeout=5.0
            )
            used_memory = memory_info.get("used_memory", 0)
            logger.info(f"[REDIS-HEALTH] ✓ Memory usage: {used_memory} bytes")
        except Exception as e:
            logger.warning(f"[REDIS-HEALTH] Memory info check failed: {e}")

        # Cleanup test key
        await asyncio.wait_for(redis_client.delete(test_key), timeout=5.0)

        logger.info(f"[REDIS-HEALTH] ✓ All Redis functionality tests passed")

    except asyncio.TimeoutError as e:
        raise RuntimeError(f"Redis functionality test timeout: {e}")
    except Exception as e:
        raise RuntimeError(f"Redis functionality test failed: {type(e).__name__}: {e}")


async def _cleanup_redis_cache(app):
    """Cleanup Redis cache on shutdown with proper error handling"""
    try:
        redis_client = getattr(app.state, "redis_client", None)
        if redis_client:
            try:
                await asyncio.wait_for(redis_client.aclose(), timeout=5.0)
                logger.info("[SHUTDOWN] Redis client closed gracefully")
            except asyncio.TimeoutError:
                logger.warning("[SHUTDOWN] Redis client close timed out")
            except Exception as e:
                logger.debug(f"[SHUTDOWN] Error closing Redis client: {e}")

        # Also cleanup cache module if available
        try:
            from backend.redis_cache import cache

            if cache:
                try:
                    await asyncio.wait_for(cache.disconnect(), timeout=5.0)
                except (AttributeError, Exception):
                    # disconnect() may not exist, ignore
                    pass
                logger.info("[SHUTDOWN] Redis cache disconnected")
        except Exception as e:
            logger.debug(f"[SHUTDOWN] Redis cache cleanup: {e}")
    except asyncio.TimeoutError:
        logger.warning("[SHUTDOWN] Redis cleanup timed out")
    except Exception as e:
        logger.error(f"[SHUTDOWN] Error during Redis cleanup: {e}")


def init_storage():
    """Initialize and validate storage system - must run before routes load"""
    logger.info("[STARTUP] Initializing storage system...")
    try:
        # Validate S3_BUCKET is configured for production
        if not settings.S3_BUCKET or settings.S3_BUCKET.strip() == "":
            raise RuntimeError(
                "S3_BUCKET environment variable is required but not set or empty. "
                "Please configure S3_BUCKET in your .env file or environment variables."
            )
        logger.info(f"[STARTUP] S3 Bucket validated: {settings.S3_BUCKET}")

        # settings module automatically initializes storage directories in __init__
        # Just validate that it's properly set up
        if not settings.SERVER_STORAGE_ENABLED:
            logger.warning(
                "[STARTUP] WARNING: SERVER_STORAGE_ENABLED is False - storage may be disabled"
            )

        from pathlib import Path

        # Verify paths are accessible
        temp_path = Path(settings.TEMP_STORAGE_PATH)
        upload_path = Path(settings.UPLOAD_DIR)

        if not temp_path.exists():
            raise RuntimeError(
                f"TEMP_STORAGE_PATH does not exist: {settings.TEMP_STORAGE_PATH}"
            )
        if not upload_path.exists():
            raise RuntimeError(f"UPLOAD_DIR does not exist: {settings.UPLOAD_DIR}")

        # Check writability
        try:
            test_file_temp = temp_path / ".write_test"
            test_file_temp.touch(exist_ok=True)
            test_file_temp.unlink(missing_ok=True)
            logger.info(
                f"[STARTUP] Storage validated - TEMP_STORAGE_PATH is writable: {settings.TEMP_STORAGE_PATH}"
            )
        except Exception as e:
            raise RuntimeError(f"TEMP_STORAGE_PATH is not writable: {str(e)}")

        try:
            test_file_upload = upload_path / ".write_test"
            test_file_upload.touch(exist_ok=True)
            test_file_upload.unlink(missing_ok=True)
            logger.info(
                f"[STARTUP] Storage validated - UPLOAD_DIR is writable: {settings.UPLOAD_DIR}"
            )
        except Exception as e:
            raise RuntimeError(f"UPLOAD_DIR is not writable: {str(e)}")

        logger.info("[STARTUP] Storage system initialized successfully")
        return True
    except Exception as e:
        logger.error(
            f"[STARTUP] CRITICAL: Storage initialization failed: {type(e).__name__}: {str(e)}"
        )
        import traceback

        logger.error(f"[STARTUP] Traceback: {traceback.format_exc()}")
        raise RuntimeError(f"Storage initialization failed: {str(e)}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan event handler - initialize storage, database and cleanup"""

    # Import pytest detection from centralized location
    from database import _is_pytest_running

    is_test_mode = _is_pytest_running()
    if is_test_mode:
        logger.info(
            "[STARTUP] Pytest detected - running in test mode with mock cache only"
        )

    # Startup - CRITICAL: Storage must initialize first, before all other systems
    # Call synchronous storage init function
    try:
        init_storage()
    except Exception as e:
        logger.error(
            f"[STARTUP] CRITICAL: Storage initialization failed, cannot start application: {str(e)}"
        )
        raise

    # Database initialization - only initialize if not already done by conftest or external setup
    from database import is_database_initialized

    if not is_database_initialized():
        await init_database()

    # Store database connection in app state for reliable access
    from database import db, client

    app.state.db = db
    app.state.client = client
    logger.info(f"[STARTUP] Database available in app.state")

    # Initialize Redis cache (with fallback to mock cache for local development)
    redis_client = None
    cache = None

    if not is_test_mode:
        try:
            # CRITICAL: Initialize module-level cache with retry mechanism
            # This ensures all cache operations throughout the app use authenticated connection
            logger.info(
                "[STARTUP] Initializing Redis cache module with retry mechanism"
            )
            cache_initialized = await init_cache()

            if not cache_initialized:
                logger.error("[STARTUP] CRITICAL: Cache initialization returned False")
                raise RuntimeError("Cache initialization failed - returned False")

            # Store cache instance in app state for reliable access
            try:
                from backend.redis_cache import cache as redis_cache_module

                cache = redis_cache_module
                app.state.cache = cache
                redis_client = cache.redis_client
                app.state.redis_client = redis_client

                if redis_client and cache.is_connected:
                    logger.info(
                        "[STARTUP] Redis cache initialized successfully and stored in app.state"
                    )
                else:
                    # Redis not available - use mock cache for local development
                    logger.warning(
                        "[STARTUP] Redis not available - using in-memory mock cache for local development"
                    )
                    # Mock cache is already initialized in init_cache()

            except Exception as e:
                logger.error(
                    f"[STARTUP] CRITICAL: Failed to access cache module after init: {type(e).__name__}: {e}"
                )
                import traceback

                logger.error(f"[STARTUP] Traceback: {traceback.format_exc()}")
                # Fall back to mock cache instead of failing
                logger.warning("[STARTUP] Falling back to mock cache")
                try:
                    from backend.redis_cache import cache as redis_cache_module

                    app.state.cache = redis_cache_module
                    app.state.redis_client = None
                except Exception:
                    app.state.cache = None
                    app.state.redis_client = None

        except Exception as e:
            logger.error(
                f"[STARTUP] Redis initialization failed - falling back to mock cache: {type(e).__name__}: {e}"
            )
            # Fall back to mock cache instead of failing completely
            try:
                from backend.redis_cache import cache as redis_cache_module

                await redis_cache_module.clear_mock_cache()
                app.state.cache = redis_cache_module
                app.state.redis_client = None
                logger.info("[STARTUP] Mock cache initialized as fallback")
            except Exception as cache_error:
                logger.error(f"[STARTUP] Mock cache also failed: {cache_error}")
                app.state.cache = None
                app.state.redis_client = None
    else:
        # In test mode, initialize mock cache only
        try:
            from backend.redis_cache import cache as redis_cache_module

            cache = redis_cache_module
            await cache.clear_mock_cache()
            app.state.cache = cache
            app.state.redis_client = None  # Explicitly None in test mode
            logger.info("[STARTUP] Mock cache initialized for test mode")
        except Exception as e:
            logger.error(
                f"[STARTUP] ERROR: Mock cache initialization failed: {type(e).__name__}: {e}"
            )
            # Still allow test mode to continue with empty cache
            app.state.cache = None
            app.state.redis_client = None

    # Verify redis_client is always set in app.state before WebSocket manager initialization
    if not hasattr(app.state, "redis_client"):
        app.state.redis_client = None
    if not hasattr(app.state, "cache"):
        app.state.cache = None

    # NOTE: Redis Pub/Sub subscriber is now managed by WebSocket manager singleton
    # No need for separate subscriber - WebSocket manager handles it

    # CRITICAL: Initialize WebSocket manager singleton (AFTER Redis is ready)
    websocket_manager_initialization_started = False
    websocket_manager_initialized = False
    if not is_test_mode:
        try:
            # Get Redis client from app.state
            redis_client = getattr(app.state, "redis_client", None)

            if not redis_client:
                # Redis not available - run without WebSocket pub/sub for local development
                logger.warning(
                    "[STARTUP] Redis client is None - WebSocket manager will run in degraded mode"
                )
                logger.warning(
                    "[STARTUP] Real-time features may be limited without Redis"
                )
                # Skip WebSocket initialization but continue startup
                # WebSocket connections will still work but without Redis pub/sub
            else:
                logger.info(
                    "[STARTUP] Initializing WebSocket manager with Redis client..."
                )
                # Initialize WebSocket manager with Redis client
                websocket_manager_initialization_started = True
                await asyncio.wait_for(
                    websocket_manager.initialize(redis_client), timeout=10.0
                )
                websocket_manager_initialized = True
                logger.info("[STARTUP] WebSocket manager initialization completed")

                # Start global Pub/Sub subscriber
                logger.info("[STARTUP] Starting global Pub/Sub subscriber...")
                await websocket_manager.start_global_pubsub()

                logger.info(
                    "[STARTUP] WebSocket manager initialized and ready for connections"
                )
        except asyncio.TimeoutError as e:
            logger.error(f"[STARTUP] WebSocket manager initialization timed out: {e}")
            # Cleanup if initialization was started (even if not completed)
            if websocket_manager_initialization_started:
                try:
                    await websocket_manager.shutdown()
                except Exception as cleanup_e:
                    logger.warning(
                        f"[STARTUP] Failed to cleanup WebSocket manager: {cleanup_e}"
                    )
            logger.warning("[STARTUP] Continuing without WebSocket pub/sub")
        except Exception as e:
            logger.error(
                f"[STARTUP] WebSocket manager initialization failed: {type(e).__name__}: {e}"
            )
            import traceback

            logger.error(f"[STARTUP] Traceback: {traceback.format_exc()}")
            # Cleanup if initialization was started (even if not completed)
            if websocket_manager_initialization_started:
                try:
                    await websocket_manager.shutdown()
                except Exception as cleanup_e:
                    logger.warning(
                        f"[STARTUP] Failed to cleanup WebSocket manager: {cleanup_e}"
                    )
            logger.warning("[STARTUP] Continuing without WebSocket pub/sub")

    # Initialize background file cleanup task (CRITICAL for production)
    cleanup_task = None
    if settings.AUTO_CLEANUP_ENABLED:
        try:
            from backend.services.file_cleanup_service import periodic_file_cleanup

            # Create cleanup task that runs periodically
            cleanup_task = asyncio.create_task(
                periodic_file_cleanup(
                    interval_minutes=settings.FILE_CLEANUP_INTERVAL_MINUTES
                )
            )
            app.state.cleanup_task = cleanup_task
            logger.info(
                f"[STARTUP] File cleanup task initialized (interval={settings.FILE_CLEANUP_INTERVAL_MINUTES}min, "
                f"retention={settings.FILE_RETENTION_HOURS}h)"
            )
        except Exception as e:
            logger.error(f"[STARTUP] Failed to initialize file cleanup task: {e}")
            # Continue even if cleanup fails - not critical for operation
    else:
        logger.info("[STARTUP] File cleanup is disabled (AUTO_CLEANUP_ENABLED=false)")

    # Initialize background status cleanup task (CRITICAL for 24-hour status expiry)
    status_cleanup_task = None
    try:
        from backend.routes.status import periodic_status_cleanup

        status_cleanup_task = asyncio.create_task(
            periodic_status_cleanup(interval_minutes=5)  # Run every 5 minutes
        )
        app.state.status_cleanup_task = status_cleanup_task
        logger.info("[STARTUP] Status cleanup task initialized (interval=5min)")
    except Exception as e:
        logger.error(f"[STARTUP] Failed to initialize status cleanup task: {e}")
        # Continue even if cleanup fails - not critical for operation

    logger.info("[STARTUP] Application startup complete")

    yield

    # Graceful shutdown sequence - CRITICAL ORDER
    # 1. Cancel background cleanup tasks
    # 2. Shutdown WebSocket manager
    # 3. Cleanup Redis
    # 4. Close database

    # Cancel background file cleanup task first
    cleanup_task = getattr(app.state, "cleanup_task", None)
    if cleanup_task and not cleanup_task.done():
        try:
            logger.info("[SHUTDOWN] Cancelling file cleanup task...")
            cleanup_task.cancel()
            await asyncio.wait_for(cleanup_task, timeout=5.0)
        except asyncio.CancelledError:
            logger.info("[SHUTDOWN] File cleanup task cancelled")
        except asyncio.TimeoutError:
            logger.warning("[SHUTDOWN] File cleanup task cancellation timed out")
        except Exception as e:
            logger.debug(f"[SHUTDOWN] Error cancelling cleanup task: {e}")

    # Cancel background status cleanup task
    status_cleanup_task = getattr(app.state, "status_cleanup_task", None)
    if status_cleanup_task and not status_cleanup_task.done():
        try:
            logger.info("[SHUTDOWN] Cancelling status cleanup task...")
            status_cleanup_task.cancel()
            await asyncio.wait_for(status_cleanup_task, timeout=5.0)
        except asyncio.CancelledError:
            logger.info("[SHUTDOWN] Status cleanup task cancelled")
        except asyncio.TimeoutError:
            logger.warning("[SHUTDOWN] Status cleanup task cancellation timed out")
        except Exception as e:
            logger.debug(f"[SHUTDOWN] Error cancelling status cleanup task: {e}")

    # Shutdown WebSocket manager (singleton instance)
    try:
        # Use the module-level websocket_manager imported at top
        await asyncio.wait_for(websocket_manager.shutdown(), timeout=10.0)
        logger.info("[SHUTDOWN] WebSocket manager shut down gracefully")
    except asyncio.TimeoutError:
        logger.warning("[SHUTDOWN] WebSocket manager shutdown timed out")
    except Exception as e:
        logger.debug(f"[SHUTDOWN] Error shutting down WebSocket manager: {e}")

    # Cleanup Redis cache (must happen before DB)
    try:
        redis_client = getattr(app.state, "redis_client", None)
        if redis_client:
            try:
                await asyncio.wait_for(redis_client.aclose(), timeout=5.0)
                logger.info("[SHUTDOWN] Redis client closed gracefully")
            except asyncio.TimeoutError:
                logger.warning("[SHUTDOWN] Redis client close timed out")
            except Exception as e:
                logger.debug(f"[SHUTDOWN] Error closing Redis client: {e}")

        # Also cleanup cache module if available
        try:
            from backend.redis_cache import cache

            if cache:
                try:
                    await asyncio.wait_for(cache.disconnect(), timeout=5.0)
                except (AttributeError, Exception):
                    # disconnect() may not exist, ignore
                    pass
                logger.info("[SHUTDOWN] Redis cache disconnected")
        except Exception as e:
            logger.debug(f"[SHUTDOWN] Redis cache cleanup: {e}")
    except asyncio.TimeoutError:
        logger.warning("[SHUTDOWN] Redis cleanup timed out")
    except Exception as e:
        logger.error(f"[SHUTDOWN] Error during Redis cleanup: {e}")

    # Shutdown database connection (last)
    try:
        from database import client

        if client:
            try:
                client.close()
            except Exception:
                pass
            logger.info("[SHUTDOWN] Database connection closed")

        # Reset database module state
        try:
            import database as _database

            _database.client = None
            _database.db = None
            _database._database_initialized = False
        except Exception:
            pass
    except Exception as e:
        logger.error(f"[SHUTDOWN] Error closing database: {e}")

    logger.info("[SHUTDOWN] Application shutdown complete")


# Custom JSON encoder for MongoDB ObjectId serialization
import json
from bson import ObjectId


class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle MongoDB ObjectId serialization and UTC timestamps.

    CRITICAL FIXES:
    - All timestamps returned as ISO 8601 with Z suffix (UTC only)
    - No timezone conversion on backend
    - ObjectId converted to string
    """

    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        # Handle datetime objects - always return Z suffix for UTC
        if isinstance(obj, datetime):
            iso_str = obj.isoformat()
            # Ensure Z suffix for UTC timestamps
            if iso_str.endswith("+00:00"):
                return iso_str.replace("+00:00", "Z")
            elif not iso_str.endswith("Z") and obj.tzinfo:
                # Check if UTC timestamp without Z suffix
                offset = obj.tzinfo.utcoffset(obj)
                if offset is not None and offset == timedelta(0):
                    return iso_str + "Z"
            return iso_str
        # Handle timezone-aware datetime with isoformat
        if hasattr(obj, "isoformat") and callable(obj.isoformat):
            iso_str = obj.isoformat()
            if iso_str.endswith("+00:00"):
                return iso_str.replace("+00:00", "Z")
            return iso_str
        return super().default(obj)


# Custom FastAPI JSON response that uses the custom encoder
from fastapi.responses import JSONResponse
from typing import Any


class CustomJSONResponse(JSONResponse):
    """Custom JSON response that properly serializes MongoDB ObjectId"""

    def render(self, content: Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
            cls=CustomJSONEncoder,
        ).encode("utf-8")


app = FastAPI(
    title="Hypersend API",
    description="Secure peer-to-peer file transfer and messaging application",
    version="1.0.0",
    redirect_slashes=False,  # Fix: Prevent automatic trailing slash redirects
    lifespan=lifespan,
    default_response_class=CustomJSONResponse,  # Use custom JSON encoder
)

# Register custom exception handlers
register_exception_handlers(app)


# ============================================================================
# GLOBAL REDIS CLIENT ACCESSOR - CRITICAL FOR ASYNC OPERATIONS
# ============================================================================


def get_redis_client():
    """
    Get the global Redis client instance from app state.

    CRITICAL: This function provides safe access to Redis client after startup.
    Returns None if Redis is not available (test mode).

    Returns:
        Redis client instance or None if not initialized

    Raises:
        RuntimeError: If called during startup before Redis is initialized
    """
    try:
        redis_client = getattr(app.state, "redis_client", None)
        if redis_client is None:
            logger.debug(
                "[REDIS-ACCESSOR] Redis client not available (test mode or not yet initialized)"
            )
        return redis_client
    except AttributeError:
        # app.state not available (shouldn't happen in normal operation)
        logger.warning(
            "[REDIS-ACCESSOR] app.state not available - Redis client cannot be accessed"
        )
        return None


# Add validation middleware for 4XX error handling (DISABLED FOR PRODUCTION)
# ===== VALIDATION MIDDLEWARE FOR 4XX ERROR HANDLING (DISABLED) =====
# app.add_middleware(RequestValidationMiddleware)
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime, timezone


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Enhanced middleware to validate requests and prevent common 4xx errors with security"""

    async def dispatch(self, request, call_next):
        """Validate request before processing with enhanced security checks"""
        # CRITICAL FIX: Always allow OPTIONS requests for CORS preflight
        # Options requests bypass ALL middleware validation for CORS compatibility
        if request.method == "OPTIONS":
            # OPTIONS requests MUST pass through immediately without any validation
            # They are handled by the OPTIONS handler in the app routes
            try:
                return await call_next(request)
            except Exception as e:
                # Even if there's an error, return 200 for OPTIONS
                logger.debug(f"[OPTIONS] Exception during processing: {e}")
                try:
                    allowed_origin = (
                        settings.CORS_ORIGINS[0]
                        if getattr(settings, "CORS_ORIGINS", None)
                        else "https://zaply.in.net"
                    )
                except Exception:
                    allowed_origin = "https://zaply.in.net"
                return Response(
                    status_code=200,
                    headers={
                        "Access-Control-Allow-Origin": allowed_origin,
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
                        "Access-Control-Allow-Headers": "*",
                    },
                )

        try:
            # SECURITY: Check for malicious request patterns
            url_path = str(request.url.path)

            # Enhanced suspicious pattern detection with more comprehensive coverage
            def is_internal_request(request):
                """Check if request is from internal Docker network or explicit service hostnames."""
                client_host = request.client.host if request.client else ""
                host_header = request.headers.get("host", "").lower()
                internal_patterns = [
                    "hypersend_frontend",
                    "hypersend_backend",
                    "frontend",
                    "backend",
                    "0.0.0.0",
                ]
                return any(
                    pattern in client_host for pattern in internal_patterns
                ) or any(pattern in host_header for pattern in internal_patterns)

            # CRITICAL FIX: Less aggressive security patterns to avoid false positives
            # Focus on actual attacks, not normal text containing keywords
            suspicious_patterns = [
                # Path traversal attacks (more specific)
                "../",
                "..\\",
                "%2e%2e",
                "%2e%2e%2f",
                "%2e%2e%5c",
                "..%2f",
                "..%5c",
                "%2e%2e/",
                "%2e%2e\\",
                "....//",
                "....\\\\",
                "%252e%252e%252f",
                # Script injection attacks (more specific)
                "<script",
                "</script>",
                "javascript:",
                "vbscript:",
                "onload=",
                "onerror=",
                "onclick=",
                "onmouseover=",
                "eval(",
                "alert(",
                "confirm(",
                "prompt(",
                # SQL injection attacks (only clear attack patterns)
                "drop table",
                "delete from",
                "exec sp_",
                "admin'--",
                "'; drop table--",
                # XML/XXE injection attacks
                "<?xml",
                "<!doctype",
                "<!entity",
                "xlink:href=",
                "<xsl:stylesheet",
                "external-entitiy",
                "<!ATTLIST",
                # System file access attempts (only clear malicious paths)
                "../../etc/passwd",
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "c:\\windows\\system32",
                "c:\\windows\\system32\\config",
                "/proc/version",
                "/proc/self/environ",
                "/etc/passwd%00",
                "cmd.exe",
                "powershell",
                "bash",
                "sh",
                # Command injection attempts (only clear command chains)
                "; rm -rf",
                "| cat /etc/passwd",
                "&& ls -la",
                "|| id",
                "`whoami`",
                "$(id)",
                "${jndi:ldap",
                "${env:HOME}",
                # NoSQL/Document injection (only clear injection patterns)
                "{$ne:}",
                "{$gt:}",
                "{$where:}",
                "$regex:",
                "$expr:",
                '{"$gt":""}',
                '{"$ne":null}',
                # LDAP injection (only clear LDAP injection)
                "*)(",
                "*)(uid=*",
                "*)(|(uid=",
                "*)(password=*",
                "*)%00",
                "*)(&(objectClass=",
                # Log4j/RCE attempts (only clear log4j patterns)
                "${jndi:",
                "${lower:jndi:",
                "${upper:jndi:",
                "${::-:j",
                "${env:",
                "${java:",
                "${sys:",
                "${log4j:",
                # Server-Side Template Injection (only clear SSTI patterns)
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%=7*7%>",
                "{{config}}",
                "${config}",
                "#{config}",
                # XXE payload variants (only clear XXE patterns)
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test',
                # Common web shell patterns
                "webshell",
                "shell.php",
                "cmd.jsp",
                "aspshell",
                "eval(base64",
                "system($_POST",
                "passthru($_",
                "shell_exec($_",
                "exec($_POST",
                "preg_replace eval",
                # SSRF patterns (only clear SSRF)
                "169.254.169.254",
                "metadata.google.internal",
                "file:///",
                "gopher://",
                "dict://",
                # Deserialization attacks (only clear patterns)
                'O:4:"User"',
                "ACED0005",
                "rO0ABX",
                "80ACED0",
                "ys0yPC",
                "base64_decode",
                "unserialize(",
                # Header injection
                "CRLF-injection",
                "%0d%0a",
                "\r\n",
                "%0D%0A",
            ]

            url_lower = url_path.lower()
            headers_lower = {
                k.lower(): v.lower() if v else ""
                for k, v in dict(request.headers).items()
            }

            # Enhanced security check with internal Docker exception for legitimate requests
            def is_internal_or_service_host():
                """Check if request is from internal Docker network"""
                client_host = request.client.host if request.client else ""

                internal_patterns = [
                    "hypersend_frontend",
                    "hypersend_backend",
                    "frontend",
                    "backend",
                    "0.0.0.0",
                ]

                host_header = request.headers.get("host", "").lower()

                return any(
                    pattern in client_host for pattern in internal_patterns
                ) or any(pattern in host_header for pattern in internal_patterns)

            is_internal = is_internal_or_service_host()

            # Check URL path for suspicious patterns
            # Always allow health check and API root endpoints
            if url_path in ["/health", "/api/v1/health", "/api/v1/", "/api/v1/test"]:
                is_internal = True  # Force internal for health checks and API root

            for pattern in suspicious_patterns:
                # No special-case bypass for loopback hosts

                if pattern in url_lower and not is_internal:
                    logger.warning(
                        f"[SECURITY] Suspicious URL blocked: {pattern} in {url_path}"
                    )
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "status_code": 400,
                            "error": "Bad Request - Malicious request detected",
                            "detail": "Request contains potentially malicious content",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "path": "/api/v1/files/invalid_path",  # Don't echo malicious path
                            "method": request.method,
                            "hints": [
                                "Remove malicious content",
                                "Check request format",
                                "Ensure proper encoding",
                            ],
                        },
                    )

            # Check headers for suspicious patterns
            for header_name, header_value in headers_lower.items():
                # Skip checking certain safe headers
                safe_headers = [
                    "user-agent",
                    "accept",
                    "content-type",
                    "authorization",
                    "host",
                    "x-forwarded-for",
                    "x-real-ip",
                ]
                if header_name in safe_headers:
                    continue

                # Special handling for host header - less strict for testing
                if header_name == "host":
                    # Extract hostname without port - handle both IPv4 and IPv6
                    hostname = header_value.lower()

                    # Handle IPv6 format: [::1]:8000 or [::1]
                    if hostname.startswith("["):
                        # IPv6 address in brackets
                        if "]" in hostname:
                            # Extract address between brackets, ignore port after ]
                            hostname = hostname[1 : hostname.index("]")]
                        else:
                            # Malformed IPv6 - missing closing bracket
                            hostname = hostname[1:]
                    else:
                        # IPv4 or hostname - remove port if present
                        # Use rpartition to split on last ':' to handle edge cases
                        hostname = (
                            hostname.rpartition(":")[0] if ":" in hostname else hostname
                        )

                    # Allow internal service hostnames
                    allowed_hostnames = {
                        "hypersend_frontend",
                        "hypersend_backend",
                        "frontend",
                        "backend",
                        "0.0.0.0",  # Docker
                    }

                    # Reject IP addresses and link-local ranges
                    if hostname.startswith("169.254.") and hostname not in [
                        "169.254.169.254"
                    ]:
                        logger.warning(
                            f"[SECURITY] SSRF attempt blocked - metadata IP in host header: {hostname}"
                        )
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={
                                "status_code": 400,
                                "error": "Bad Request - Invalid host",
                                "detail": "Request contains invalid host header",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "path": "/api/v1/files/invalid_path",
                                "method": request.method,
                                "hints": [
                                    "Use valid hostname",
                                    "Avoid metadata IPs",
                                    "Check host header",
                                ],
                            },
                        )

                    # Skip validation for allowed/trusted hosts
                    # Only block truly malicious patterns
                    if hostname in allowed_hostnames:
                        continue

                    # For unknown hosts, only log warning, don't reject
                    # Tests might use various hostnames
                    if hostname not in allowed_hostnames and not settings.DEBUG:
                        logger.warning(f"[SECURITY] Unknown host header: {hostname}")
                    continue

                for pattern in suspicious_patterns:
                    if pattern in header_value:
                        logger.warning(
                            f"[SECURITY] Suspicious pattern found in header {header_name}: {pattern}"
                        )
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={
                                "status_code": 400,
                                "error": "Bad Request - Malicious header detected",
                                "detail": "Request header contains potentially malicious content",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "path": url_path,
                                "method": request.method,
                                "hints": [
                                    "Remove malicious content",
                                    "Check request headers",
                                    "Ensure proper encoding",
                                ],
                            },
                        )

            # Check Content-Length for POST/PUT/PATCH (411)
            if request.method in ["POST", "PUT", "PATCH"]:
                content_length_header = request.headers.get("content-length")

                if not content_length_header and request.method != "GET":
                    # Log missing Content-Length but don't consume body
                    logger.warning(
                        f"[411] Missing Content-Length for {request.method} {request.url.path}"
                    )

                # Check payload size (413)
                if content_length_header:
                    try:
                        content_length = int(content_length_header)
                        max_size = settings.MAX_FILE_SIZE_BYTES
                        if content_length > max_size:
                            return JSONResponse(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                content={
                                    "status_code": 413,
                                    "error": "Payload Too Large - Request body is too big",
                                    "detail": f"Request size {content_length} bytes exceeds maximum {max_size} bytes",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "path": url_path,
                                    "method": request.method,
                                    "hints": [
                                        "Reduce file size",
                                        "Use chunked uploads",
                                        "Check server limits",
                                    ],
                                },
                            )
                    except ValueError:
                        return JSONResponse(
                            status_code=status.HTTP_411_LENGTH_REQUIRED,
                            content={
                                "status_code": 411,
                                "error": "Length Required - Content-Length header is invalid",
                                "detail": "Content-Length header must be a valid integer",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "path": url_path,
                                "method": request.method,
                                "hints": [
                                    "Provide valid Content-Length",
                                    "Ensure header is a number",
                                ],
                            },
                        )

            # Check URL length (414)
            url_length = len(str(request.url))
            if url_length > 8000:  # RFC 7230 recommendation
                return JSONResponse(
                    status_code=status.HTTP_414_URI_TOO_LONG,
                    content={
                        "status_code": 414,
                        "error": "URI Too Long - The requested URL is too long",
                        "detail": f"URL length {url_length} exceeds maximum 8000 characters",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": url_path,
                        "method": request.method,
                        "hints": ["Shorten the URL", "Use POST for complex queries"],
                    },
                )

            # Enhanced Content-Type validation for POST/PUT/PATCH
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if not content_type:
                    # Some requests can work without explicit Content-Type, but log for security
                    logger.debug(
                        f"[SECURITY] No Content-Type for {request.method} {request.url.path}"
                    )
                else:
                    # Check for dangerous content types
                    dangerous_content_types = [
                        "application/x-msdownload",  # Executable download
                        "application/x-msdos-program",  # DOS executable
                        "application/x-executable",  # Generic executable
                        "application/x-shockwave-flash",  # Flash (deprecated, risky)
                        "text/html",  # HTML in API requests (XSS risk)
                        "application/javascript",  # JavaScript in non-JS endpoints
                        "text/javascript",  # JavaScript in non-JS endpoints
                    ]

                    content_type_lower = content_type.lower()
                    for dangerous_type in dangerous_content_types:
                        if dangerous_type in content_type_lower:
                            logger.warning(
                                f"[SECURITY] Dangerous content-type blocked: {content_type}"
                            )
                            return JSONResponse(
                                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                                content={
                                    "status_code": 415,
                                    "error": "Unsupported Media Type - Content type not allowed",
                                    "detail": f"Content type '{content_type}' is not permitted for security reasons",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "path": str(request.url.path),
                                    "method": request.method,
                                    "hints": [
                                        "Use supported content types",
                                        "Check API documentation",
                                        "Ensure proper file format",
                                    ],
                                },
                            )

            # Enhanced request size validation for different endpoints
            if request.method in ["POST", "PUT", "PATCH"]:
                content_length = request.headers.get("content-length")
                if content_length:
                    try:
                        size = int(content_length)
                        # Endpoint-specific size limits
                        url_path = str(request.url.path).lower()

                        # Login/register endpoints - smaller limit
                        if (
                            "/auth/" in url_path
                            or "/login" in url_path
                            or "/register" in url_path
                        ):
                            max_size = 1024 * 1024  # 1MB
                            if size > max_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - Auth request too big",
                                        "detail": f"Authentication requests must be less than {max_size} bytes",
                                        "timestamp": datetime.now(
                                            timezone.utc
                                        ).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": [
                                            "Reduce request size",
                                            "Check for file uploads",
                                            "Use appropriate endpoints",
                                        ],
                                    },
                                )

                        # Profile/Settings endpoints - medium limit
                        elif "/profile" in url_path or "/settings" in url_path:
                            max_size = 5 * 1024 * 1024  # 5MB
                            if size > max_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - Profile data too big",
                                        "detail": f"Profile requests must be less than {max_size} bytes",
                                        "timestamp": datetime.now(
                                            timezone.utc
                                        ).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": [
                                            "Reduce profile data size",
                                            "Compress images",
                                            "Remove unnecessary data",
                                        ],
                                    },
                                )

                        # File upload endpoints - handled by file-specific logic
                        # This is just an additional safety net for very large requests
                        elif "/files/" in url_path and (
                            "/upload" in url_path or "/chunk" in url_path
                        ):
                            max_size = settings.MAX_FILE_SIZE_BYTES
                            if size > max_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - File too big",
                                        "detail": f"File uploads must be less than {max_size} bytes",
                                        "timestamp": datetime.now(
                                            timezone.utc
                                        ).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": [
                                            "Use smaller files",
                                            "Compress large files",
                                            "Split large files",
                                        ],
                                    },
                                )

                        # Chunk upload endpoints - check chunk size specifically
                        elif "/files/" in url_path and "/chunk" in url_path:
                            max_chunk_size = settings.CHUNK_SIZE
                            if size > max_chunk_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - Chunk too big",
                                        "detail": f"Chunk {url_path.split('/')[-2]} exceeds maximum size of {max_chunk_size} bytes",
                                        "actual_size": size,
                                        "max_size": max_chunk_size,
                                        "actual_size_mb": round(
                                            size / (1024 * 1024), 2
                                        ),
                                        "max_size_mb": round(
                                            max_chunk_size / (1024 * 1024), 2
                                        ),
                                        "guidance": f"Please split your data into chunks of max {round(max_chunk_size / (1024 * 1024), 0)}MB each",
                                        "timestamp": datetime.now(
                                            timezone.utc
                                        ).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": [
                                            "Reduce chunk size",
                                            "Check file chunking logic",
                                            "Use smaller chunk sizes",
                                        ],
                                    },
                                )
                    except ValueError:
                        pass  # Invalid content-length handled elsewhere

            response = await call_next(request)

            # Enhanced response security headers
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "X-Permitted-Cross-Domain-Policies": "none",
                "Permissions-Policy": "microphone=(), camera=()",
            }

            # Add security headers to response
            for header, value in security_headers.items():
                response.headers[header] = value

            return response

        except HTTPException:
            # Re-raise HTTPException to be handled by specific handlers
            raise
        except Exception as e:
            # Enhanced error logging with security context
            client_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("User-Agent", "unknown")

            logger.error(
                f"[MIDDLEWARE_ERROR] {request.method} {request.url.path} | "
                f"Client: {client_ip} | User-Agent: {user_agent[:100]} | "
                f"Error: {type(e).__name__}: {str(e)}",
                exc_info=True,
            )

            # Enhanced error classification
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in ["validation", "json", "parse", "syntax"]
            ):
                return JSONResponse(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    content={
                        "status_code": 422,
                        "error": "Unprocessable Entity - Invalid input data",
                        "detail": str(e) if settings.DEBUG else "Invalid input data",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": [
                            "Check request format",
                            "Verify JSON syntax",
                            "Review API documentation",
                        ],
                    },
                )
            elif any(
                keyword in error_str
                for keyword in ["timeout", "deadline", "deadlineexceeded"]
            ):
                return JSONResponse(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    content={
                        "status_code": 504,
                        "error": "Gateway Timeout - Request took too long",
                        "detail": str(e) if settings.DEBUG else "Request timeout",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": [
                            "Try again later",
                            "Reduce request complexity",
                            "Check server load",
                        ],
                    },
                )
            elif any(
                keyword in error_str
                for keyword in ["connection", "network", "unreachable"]
            ):
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "status_code": 503,
                        "error": "Service Unavailable - Connection issue",
                        "detail": str(e)
                        if settings.DEBUG
                        else "Service temporarily unavailable",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": [
                            "Check network connection",
                            "Try again later",
                            "Verify server status",
                        ],
                    },
                )
            else:
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={
                        "status_code": 500,
                        "error": "Internal Server Error",
                        "detail": "Server error processing request"
                        if not settings.DEBUG
                        else str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": [
                            "This is a server error",
                            "Try again later",
                            "Contact support if persistent",
                        ],
                    },
                )


def _configure_s3_lifecycle():
    """
    Configure S3 bucket lifecycle rules for WhatsApp-style ephemeral storage.
    MANDATORY: Automatically delete temporary media after 24 hours.
    """
    try:
        import boto3  # type: ignore[import-not-found]
        from botocore.exceptions import ClientError  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("[S3] boto3 not available, skipping lifecycle configuration")
        return

    if not settings.AWS_ACCESS_KEY_ID or not settings.AWS_SECRET_ACCESS_KEY:
        logger.warning("[S3] AWS credentials not configured, skipping lifecycle setup")
        return

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION,
    )

    try:
        # Define lifecycle policy for ephemeral temp files
        lifecycle_policy = {
            "Rules": [
                {
                    "Id": "zaply-temp-cleanup-24h",
                    "Filter": {"Prefix": "temp/"},  # Only apply to temp/ objects
                    "Status": "Enabled",
                    "Expiration": {
                        "Days": 1  # MANDATORY: Delete after 24 hours
                    },
                    "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
                },
                {
                    "Id": "zaply-incomplete-multipart",
                    "Filter": {"Prefix": "temp/"},
                    "Status": "Enabled",
                    "AbortIncompleteMultipartUpload": {
                        "DaysAfterInitiation": 1  # Cleanup incomplete uploads
                    },
                },
            ]
        }

        # Apply lifecycle configuration to S3 bucket
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=settings.S3_BUCKET, LifecycleConfiguration=lifecycle_policy
        )

        logger.info(
            f"[S3] Lifecycle policy configured for bucket: {settings.S3_BUCKET}"
        )
        logger.info(f"[S3] - Temporary files (temp/) auto-deleted after 24 hours")
        logger.info(f"[S3] - Incomplete uploads (temp/) cleaned after 24 hours")
        logger.info("[S3] WhatsApp-style ephemeral storage: Enabled ✓")

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "NoSuchBucket":
            logger.warning(f"[S3] Bucket '{settings.S3_BUCKET}' does not exist")
            logger.warning(
                f"[S3] Please create the S3 bucket and configure lifecycle manually:"
            )
            logger.warning(
                f"[S3] Lifecycle policy needed: Delete objects in 'temp/' prefix after 24 hours"
            )
        else:
            logger.warning(f"[S3] Failed to configure lifecycle: {error_code}")
            logger.warning(f"[S3] Details: {str(e)}")
    except Exception as e:
        logger.warning(f"[S3] Unexpected error configuring lifecycle: {str(e)}")
        logger.warning("[S3] Continuing without lifecycle configuration")


# Add a comprehensive catch-all exception handler for any unhandled exceptions
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Enhanced catch-all exception handler for unhandled exceptions

    LOGIC:
    - HTTPException: Already handled by specific handlers, re-raise
    - Timeout/Connection errors: 504 Gateway Timeout / 503 Service Unavailable
    - Database errors: 503 Service Unavailable
    - File system errors: 500 Internal Server Error / 507 Insufficient Storage
    - Validation errors: 400 Bad Request
    - Security errors: 401/403 Forbidden
    - Other errors: 500 Internal Server Error

    SECURITY: Don't expose internal details in production mode
    LOGIC: Provide specific error handling for common exception types
    """
    # Don't catch HTTPException - let the specific handler deal with those
    if isinstance(exc, HTTPException):
        raise exc  # Re-raise HTTPException to be handled by its specific handler

    import traceback
    import asyncio
    import pymongo.errors
    from pymongo.errors import PyMongoError

    # Enhanced logging with full context
    logger.error(
        f"[UNCAUGHT_EXCEPTION] {request.method} {request.url.path} | "
        f"{type(exc).__name__}: {str(exc)} | "
        f"Client: {request.client.host if request.client else 'Unknown'}",
        exc_info=True,
    )

    # Determine appropriate status code and message based on exception type
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_msg = "Internal server error"
    hints = ["Try again in a moment", "Contact support if the problem persists"]

    # Enhanced exception type handling
    if isinstance(exc, asyncio.TimeoutError):
        status_code = status.HTTP_504_GATEWAY_TIMEOUT
        error_msg = "Request timeout - operation took too long"
        hints = [
            "Check your network connection",
            "Try with a smaller request",
            "Try again later",
        ]

    elif isinstance(exc, ConnectionError):
        # CRITICAL FIX: Distinguish between 502 and 503 errors
        error_msg_lower = str(exc).lower()
        if "connection refused" in error_msg_lower or "bad gateway" in error_msg_lower:
            status_code = status.HTTP_502_BAD_GATEWAY
            error_msg = "Bad gateway - upstream service unavailable"
            hints = [
                "Check if backend service is running",
                "Try again in a few moments",
                "Contact support if persistent",
            ]
        else:
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = (
                "Service temporarily unavailable - cannot connect to external service"
            )
            hints = [
                "Check your internet connection",
                "Try again in a few moments",
                "Verify service status",
            ]

    elif isinstance(exc, PyMongoError):
        if "timeout" in str(exc).lower():
            status_code = status.HTTP_504_GATEWAY_TIMEOUT
            error_msg = "Database timeout - operation took too long"
        elif "connection" in str(exc).lower():
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = "Database connection failed - service temporarily unavailable"
        elif "duplicate" in str(exc).lower():
            status_code = status.HTTP_409_CONFLICT
            error_msg = "Resource already exists - duplicate entry detected"
        else:
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = "Database error - service temporarily unavailable"
        hints = [
            "Try again in a few moments",
            "Check your request data",
            "Contact support if persistent",
        ]

    elif isinstance(exc, (OSError, IOError)):
        error_msg_lower = str(exc).lower()
        if "no space left" in error_msg_lower or "disk full" in error_msg_lower:
            status_code = status.HTTP_507_INSUFFICIENT_STORAGE
            error_msg = "Server storage full - cannot complete operation"
        elif "permission denied" in error_msg_lower:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            error_msg = "Server permission error - please contact support"
        elif "network unreachable" in error_msg_lower:
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = "Network service unavailable - please check connection"
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            error_msg = "Server I/O error - please try again"
        hints = ["Try again with smaller data", "Contact support if persistent"]

    elif isinstance(exc, ValueError):
        status_code = status.HTTP_400_BAD_REQUEST
        error_msg = "Invalid input data - check your request parameters"
        hints = [
            "Check request format and data types",
            "Verify all required fields are provided",
        ]

    elif isinstance(exc, KeyError):
        status_code = status.HTTP_400_BAD_REQUEST
        error_msg = "Missing required field in request"
        hints = [
            "Check that all required fields are provided",
            "Review API documentation",
        ]

    elif isinstance(exc, (AttributeError, TypeError)):
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        error_msg = "Internal server error - data processing failed"
        hints = [
            "This is a server issue",
            "Try again later",
            "Contact support if persistent",
        ]

    # Security-related exceptions
    elif "unauthorized" in str(exc).lower() or "authentication" in str(exc).lower():
        status_code = status.HTTP_401_UNAUTHORIZED
        error_msg = "Authentication required or invalid credentials"
        hints = ["Check your authentication token", "Login again if session expired"]

    elif "forbidden" in str(exc).lower() or "permission" in str(exc).lower():
        status_code = status.HTTP_403_FORBIDDEN
        error_msg = "Access denied - insufficient permissions"
        hints = ["Check your access permissions", "Contact administrator for access"]

    # Standard HTTP Error Codes
    elif isinstance(exc, ConnectionRefusedError):
        # 502 Bad Gateway - Upstream connection refused
        status_code = 502
        error_msg = "Network connection timeout - cannot reach server"
        hints = [
            "Check firewall settings",
            "Verify VPS is accessible",
            "Contact network administrator",
        ]

    elif isinstance(exc, ConnectionResetError):
        # 502 Bad Gateway - Connection lost during transfer
        status_code = 502
        error_msg = "Network connection reset - transfer interrupted"
        hints = [
            "Check network stability",
            "Restart the transfer",
            "Try different network",
        ]

    elif "timeout" in str(exc).lower() and "disk" in str(exc).lower():
        # 503 Service Unavailable - Disk I/O saturated
        status_code = 503
        error_msg = "Disk I/O timeout - server storage overloaded"
        hints = [
            "Wait and retry",
            "Upload smaller files",
            "Contact support about storage capacity",
        ]

    elif "quota" in str(exc).lower() or "limit" in str(exc).lower():
        # 507 Insufficient Storage - Disk quota exceeded
        status_code = 507
        error_msg = "Storage quota exceeded - disk space limit reached"
        hints = [
            "Wait for space cleanup",
            "Upload smaller files",
            "Contact support about quota",
        ]

    elif "ssl" in str(exc).lower() or "tls" in str(exc).lower():
        # 502 Bad Gateway - SSL/TLS connection issues
        status_code = 502
        error_msg = "Secure connection failed - SSL/TLS error"
        hints = [
            "Check SSL certificates",
            "Try HTTP connection",
            "Contact support about SSL setup",
        ]

    elif "dns" in str(exc).lower() or "resolve" in str(exc).lower():
        # 502 Bad Gateway - DNS resolution failed
        status_code = 502
        error_msg = "DNS resolution failed - cannot reach server"
        hints = [
            "Check DNS settings",
            "Try using IP address directly",
            "Contact DNS administrator",
        ]

    # Prepare response data
    # SECURITY: Sanitize path to prevent information disclosure in error responses
    import re

    # Check for dangerous patterns in the normalized path
    dangerous_patterns = [
        r"etc/passwd",  # Unix system files
        r"etc/shadow",  # Unix password file
        r"etc/hosts",  # Unix hosts file
        r"windows/system32",  # Windows system directory
        r"system32/config",  # Windows registry files
        r"boot\.ini",  # Windows boot file
        r"win\.ini",  # Windows configuration
        r"\.ssh/",  # SSH directory
        r"\.bash_history",  # Bash history
        r"\.mysql_history",  # MySQL history
        r"proc/",  # Linux proc filesystem
        r"sys/",  # Linux sys filesystem
        r"dev/",  # Linux dev filesystem
    ]

    # Check for dangerous patterns in the original path
    original_path = str(request.url.path)
    traversal_patterns = [
        r"\.\.[\\/]",  # ../ or ..\
        r"%2e%2e",  # URL encoded ..
        r"\\\\",  # UNC paths
        r"^[a-zA-Z]:",  # Drive letters
    ]

    # Determine if this is a dangerous path request
    dangerous_in_path = any(
        re.search(pattern, str(request.url.path), re.IGNORECASE)
        for pattern in dangerous_patterns
    )
    dangerous_in_original = any(
        re.search(pattern, original_path, re.IGNORECASE)
        for pattern in traversal_patterns
    )

    is_dangerous_path = dangerous_in_path or dangerous_in_original

    # Use generic path for dangerous requests to prevent information disclosure
    safe_path = (
        "/api/v1/files/invalid_path" if is_dangerous_path else str(request.url.path)
    )

    response_data = {
        "status_code": status_code,
        "error": type(exc).__name__ if settings.DEBUG else error_msg.title(),
        "detail": error_msg if not settings.DEBUG else str(exc),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": safe_path,
        "method": request.method,
        "hints": hints,
    }

    # Add specific context for certain error types
    if status_code == 413:
        response_data["max_size"] = "40GB"
    elif status_code == 429:
        response_data["retry_after"] = "60"

    # Add security headers to all error responses
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-cache, no-store, must-revalidate",  # Don't cache errors
    }

    return JSONResponse(
        status_code=status_code, content=response_data, headers=security_headers
    )


# Add 404 handler for non-existent endpoints
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 Not Found errors - resource or endpoint doesn't exist"""
    path = str(request.url.path)
    method = request.method

    # SECURITY: Sanitize path to prevent information disclosure in error responses
    # Check for path traversal patterns and system file references in the requested path
    import re

    # DEBUG: Add logging to understand the issue
    logger.debug(f"[DEBUG 404] Raw path: {str(request.url.path)}")
    logger.debug(f"[DEBUG 404] Path type: {type(str(request.url.path))}")

    # Check for dangerous patterns in the normalized path
    dangerous_patterns = [
        r"etc/passwd",  # Unix system files
        r"etc/shadow",  # Unix password file
        r"etc/hosts",  # Unix hosts file
        r"windows/system32",  # Windows system directory
        r"system32/config",  # Windows registry files
        r"boot\.ini",  # Windows boot file
        r"win\.ini",  # Windows configuration
        r"\.ssh/",  # SSH directory
        r"\.bash_history",  # Bash history
        r"\.mysql_history",  # MySQL history
        r"proc/",  # Linux proc filesystem
        r"sys/",  # Linux sys filesystem
        r"dev/",  # Linux dev filesystem
    ]

    # Check for dangerous patterns in the original path
    original_path = str(request.url.path)
    traversal_patterns = [
        r"\.\.[\\/]",  # ../ or ..\
        r"%2e%2e",  # URL encoded ..
        r"\\\\",  # UNC paths
        r"^[a-zA-Z]:",  # Drive letters
    ]

    # Determine if this is a dangerous path request
    dangerous_in_path = any(
        re.search(pattern, str(request.url.path), re.IGNORECASE)
        for pattern in dangerous_patterns
    )
    dangerous_in_original = any(
        re.search(pattern, original_path, re.IGNORECASE)
        for pattern in traversal_patterns
    )

    is_dangerous_path = dangerous_in_path or dangerous_in_original

    logger.debug(f"[DEBUG 404] Dangerous in path: {dangerous_in_path}")
    logger.debug(f"[DEBUG 404] Dangerous in original: {dangerous_in_original}")
    logger.debug(f"[DEBUG 404] Is dangerous path: {is_dangerous_path}")

    # Use generic path for dangerous requests to prevent information disclosure
    safe_path = (
        "/api/v1/files/invalid_path" if is_dangerous_path else str(request.url.path)
    )

    logger.debug(f"[DEBUG 404] Safe path: {safe_path}")

    # Distinguish between:
    # - true route-miss 404s (wrong URL) vs
    # - intentional 404s raised inside a matched endpoint (e.g. "User not found")
    matches_existing_route = False
    try:
        scope = request.scope
        for route in app.routes:
            if hasattr(route, "matches"):
                match, _ = route.matches(scope)
                if match in (Match.FULL, Match.PARTIAL):
                    matches_existing_route = True
                    break
    except Exception:
        matches_existing_route = False

    if matches_existing_route:
        detail_obj = getattr(exc, "detail", "Not Found")
        detail_msg = detail_obj
        if isinstance(detail_obj, dict):
            detail_msg = (
                detail_obj.get("message") or detail_obj.get("detail") or str(detail_obj)
            )
        else:
            detail_msg = str(detail_obj)

        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "status_code": 404,
                "error": "Not Found",
                "detail": detail_msg,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": safe_path,
                "method": method,
                "hints": [
                    "Verify the resource identifier",
                    "Check permissions",
                    "Review API documentation",
                ],
            },
        )

    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "status_code": 404,
            "error": "Not Found",
            "detail": "The requested resource doesn't exist. Check the URL path.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": safe_path,
            "method": method,
            "hints": [
                "Check the URL spelling",
                "Verify the endpoint exists",
                "Review API documentation",
            ],
        },
    )


# Add 405 handler for method not allowed
@app.exception_handler(405)
async def method_not_allowed_handler(request: Request, exc: HTTPException):
    """
    Handle 405 Method Not Allowed errors - endpoint exists but HTTP method not supported

    SECURITY: Use strict HTTP method validation to prevent bypass attacks
    LOGIC: Only return 405 if endpoint exists with different method
    """
    path = str(request.url.path)
    method = request.method

    # SECURITY FIX: Check for path traversal attempts and suspicious patterns
    # Reject paths with parent directory traversal (..), double slashes (//) or other bypass attempts
    if ".." in path or path.startswith("//") or "%2e%2e" in path.lower():
        # These are clearly malicious paths - return 404 instead of 405
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "status_code": 404,
                "error": "Not Found",
                "detail": "Invalid path format - the requested resource doesn't exist.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": path,
                "method": method,
                "hints": [
                    "Verify the correct endpoint path",
                    "Check for special characters",
                    "Review API documentation",
                ],
            },
        )

    # LOGIC FIX: Check if ANY route exists at this path with a different method
    matching_routes = [
        route
        for route in app.routes
        if hasattr(route, "path")
        and (route.path == path.rstrip("/") or route.path == path)
    ]

    # If no routes match this path, it's 404 not 405
    if not matching_routes:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "status_code": 404,
                "error": "Not Found",
                "detail": "The requested endpoint doesn't exist.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": path,
                "method": method,
                "hints": [
                    "Check the URL spelling",
                    "Verify the endpoint exists",
                    "Review API documentation",
                ],
            },
        )

    # If route exists but method is wrong, return 405 with allowed methods
    allowed_methods = set()
    for route in matching_routes:
        if hasattr(route, "methods"):
            allowed_methods.update(route.methods)

    # Always add OPTIONS for CORS
    allowed_methods.add("OPTIONS")

    return JSONResponse(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        content={
            "status_code": 405,
            "error": "Method Not Allowed",
            "detail": f"The HTTP {method} method is not supported for this endpoint.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": path,
            "method": method,
            "allowed_methods": sorted(list(allowed_methods)),
            "hints": [
                "Use one of the allowed HTTP methods",
                "Check API documentation for correct method",
            ],
        },
    )


# TrustedHost middleware for additional security
# TrustedHost middleware disabled for debugging
# if not settings.DEBUG and os.getenv("ENABLE_TRUSTED_HOST", "false").lower() == "true":
#     allowed_hosts = os.getenv("ALLOWED_HOSTS", "hypersend.in.net").split(",")
#     app.add_middleware(
#         TrustedHostMiddleware,
#         allowed_hosts=allowed_hosts
#     )

# CORS middleware - configured from settings to respect DEBUG/PRODUCTION modes
# ENHANCED: Multiple origin support with exact pattern matching
cors_origins = settings.CORS_ORIGINS

# Convert to list if single origin
if isinstance(cors_origins, str):
    cors_origins = [cors_origins]

# Clean up whitespace in origins
if isinstance(cors_origins, list) and len(cors_origins) > 0:
    cors_origins = [origin.strip() for origin in cors_origins if origin.strip()]

# Production CORS: allow only configured zaply origins (no extra debug origins)
# CRITICAL FIX: allow_headers cannot be wildcard ["*"] when allow_credentials=True per CORS spec
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "Accept",
        "Origin",
        "X-Requested-With",
        "Accept-Language",
        "Content-Language",
        "X-Access-Token",
        "X-Skip-Auth-Interceptor",
    ],
    expose_headers=[
        "Content-Disposition",
        "X-Total-Count",
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Content-Length",
        "Set-Cookie",
    ],
    max_age=3600,  # Cache preflight requests for 1 hour
)


# CRITICAL FIX: Handle CORS preflight requests (OPTIONS) without requiring authentication
# Browser CORS preflight requests don't have auth headers, so they would fail 401 without this
# NOTE: FastAPI automatically handles OPTIONS for registered routes, this is fallback only
@app.options("/{full_path:path}")
async def handle_options_request(full_path: str, request: Request):
    """
    Handle CORS preflight OPTIONS requests.
    These must succeed without authentication for CORS to work in browsers.
    SECURITY: Use exact whitelist matching to prevent origin bypass attacks
    (e.g., https://evildomain.zaply.in.net would bypass substring matching)
    PRODUCTION: Only allow HTTPS production domains (zaply.in.net only)
    """
    origin = request.headers.get("Origin", "")

    # SECURITY LOGIC: Strict production CORS validation using exact whitelist
    allowed_origin = "null"  # Default: deny untrusted origins

    if origin:
        # SECURITY: Use exact whitelist matching to prevent subdomain bypass attacks
        # Production allows ONLY zaply.in.net and www.zaply.in.net
        allowed_origins_list = [
            "https://zaply.in.net",
            "https://www.zaply.in.net",
        ]

        # SECURITY: Exact match only - no pattern matching to prevent bypass
        # This prevents evildomain.zaply.in.net from being accepted
        allowed_origin = origin if origin in allowed_origins_list else "null"

    # If no Origin header, this is not a browser CORS request. Do not emit wildcard
    # in production. Return the primary allowed origin to keep responses consistent.
    if not origin:
        allowed_origin = (
            settings.CORS_ORIGINS[0]
            if getattr(settings, "CORS_ORIGINS", None)
            else "https://zaply.in.net"
        )

    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Origin, X-Requested-With, X-Access-Token",
            "Access-Control-Allow-Credentials": "true"
            if allowed_origin != "null" and allowed_origin != "*"
            else "false",
            "Access-Control-Max-Age": "86400",
        },
    )


@app.get("/api/v1/status")
async def api_status(request: Request):
    return {
        "status": "operational",
        "service": "zaply-api",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
async def root():
    """Root endpoint - verify API is responding"""
    return {
        "app": "Zaply",
        "version": "1.0.0",
        "status": "running",
        "environment": "debug" if settings.DEBUG else "production",
        "api_endpoint": settings.API_BASE_URL,
    }


@app.get("/api/v1/")
async def api_v1_root():
    """API v1 root endpoint - prevent 405 errors"""
    return {"status": "ok", "service": "zaply"}


@app.head("/api/v1/")
async def api_v1_root_head():
    """HEAD method for API v1 root endpoint"""
    return Response(status_code=200)


# Security headers middleware - REMOVED to prevent duplicates with nginx
# Nginx now handles all security headers consistently
# @app.middleware("http")
# async def add_security_headers(request, call_next):
#     response = await call_next(request)
#
#     # Add security headers
#     security_headers = SecurityConfig.get_security_headers()
#
#     # Add HSTS only for HTTPS connections
#     if request.url.scheme == "https":
#         hsts_header = SecurityConfig.get_hsts_header()
#         security_headers["Strict-Transport-Security"] = hsts_header
#
#     for header, value in security_headers.items():
#         response.headers[header] = value
#
#     return response


# Serve favicon (avoid 404 in logs)
FAVICON_PATH = Path("frontend/assets/favicon.ico")


@app.get("/favicon.ico")
async def favicon():
    if FAVICON_PATH.exists():
        return FileResponse(str(FAVICON_PATH))
    return Response(status_code=204)


# Health check endpoint
@app.get("/health", tags=["System"])
@app.get("/api/v1/health", tags=["System"])
async def health_check():
    """Production health check endpoint - minimal response for load balancers"""
    try:
        # Check storage availability FIRST
        storage_status = "healthy"
        storage_error = None

        try:
            from pathlib import Path

            temp_path = Path(settings.TEMP_STORAGE_PATH)
            upload_path = Path(settings.UPLOAD_DIR)

            if not temp_path.exists() or not upload_path.exists():
                storage_status = "unhealthy"
                storage_error = "Storage directories do not exist"
            else:
                # Check writability
                try:
                    test_file_temp = temp_path / ".health_test"
                    test_file_temp.touch(exist_ok=True)
                    test_file_temp.unlink(missing_ok=True)

                    test_file_upload = upload_path / ".health_test"
                    test_file_upload.touch(exist_ok=True)
                    test_file_upload.unlink(missing_ok=True)

                    storage_status = "healthy"
                except Exception as e:
                    storage_status = "unhealthy"
                    storage_error = f"Storage not writable: {str(e)[:50]}"
        except Exception as e:
            storage_status = "unhealthy"
            storage_error = str(e)[:100]

        # Check database connectivity using get_database dependency
        db_status = "healthy"
        db_error = None

        try:
            # Import database module and check connection
            import database

            # Force database initialization
            db = database.get_database()

            # Check if client is available
            if hasattr(database, "client") and database.client is not None:
                # Test connection with ping
                try:
                    await database.client.admin.command("ping")
                    db_status = "healthy"
                    db_error = None
                except Exception as ping_error:
                    db_status = "unhealthy"
                    db_error = str(ping_error)[:100]
            else:
                db_status = "unhealthy"
                db_error = "Database client not initialized"
        except Exception as e:
            db_status = "unhealthy"
            db_error = str(e)[:100]

        # Check Redis connectivity (CRITICAL for production)
        redis_status = "healthy"
        redis_error = None

        try:
            from backend.redis_cache import cache

            if not hasattr(cache, "is_connected") or not cache.is_connected:
                redis_status = "unhealthy"
                redis_error = "Redis not connected"
            elif not hasattr(cache, "redis_client") or cache.redis_client is None:
                redis_status = "unhealthy"
                redis_error = "Redis client not available"
            else:
                # Test Redis connectivity with ping
                await asyncio.wait_for(cache.redis_client.ping(), timeout=5.0)
                redis_status = "healthy"
                redis_error = None
        except asyncio.TimeoutError:
            redis_status = "unhealthy"
            redis_error = "Redis ping timeout"
        except Exception as e:
            redis_status = "unhealthy"
            redis_error = str(e)[:100]

        # Determine overall status - fail if storage, database, or Redis is unhealthy
        overall_status = "healthy"
        if (
            storage_status == "unhealthy"
            or db_status == "unhealthy"
            or redis_status == "unhealthy"
        ):
            overall_status = "unhealthy"

        response_data = {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": {
                "storage": {"status": storage_status, "error": storage_error},
                "database": {"status": db_status, "error": db_error},
                "cache": {"status": redis_status, "error": redis_error},
            },
        }

        return JSONResponse(status_code=200, content=response_data)

    except Exception as e:
        # Even in error, return 200 with status for load balancer compatibility
        return JSONResponse(
            status_code=200,
            content={
                "status": "degraded",
                "error": str(e)[:50],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )


@app.head("/health", tags=["System"])
@app.head("/api/v1/health", tags=["System"])
async def health_check_head():
    """HEAD method for health check endpoint"""
    return Response(status_code=200)


# ====================
# DIRECT APP ROUTES (must be before router includes)
# ====================


@app.get("/api/v1/debug", tags=["System"])
async def debug_route(request: Request):
    """Debug route to see what path FastAPI receives"""
    return {
        "received_url": str(request.url),
        "received_path": str(request.url.path),
        "received_query_params": dict(request.query_params),
        "client_host": request.client.host if request.client else "none",
        "headers": dict(request.headers),
    }


@app.get("/api/v1/users/contacts", tags=["Users"])
@app.get("/api/v1/users/contacts/", tags=["Users"])
async def contacts_route(
    offset: int = 0,
    limit: int = 50,
    current_user: str = Depends(get_current_user),
):
    return await users.get_contacts(
        offset=offset, limit=limit, current_user=current_user
    )


# ====================
# ROUTER REGISTRATION
# ====================

app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(chats.router, prefix="/api/v1/chats")
app.include_router(groups.router, prefix="/api/v1")
app.include_router(messages.router, prefix="/api/v1")
app.include_router(e2ee_messages.router, prefix="/api/v1")  # E2EE encrypted messages
app.include_router(
    status_router.router, prefix="/api/v1"
)  # Status endpoints with proper prefix
app.include_router(
    files.router, prefix="/api/v1/files"
)  # Standard file operations: /api/v1/files/*
app.include_router(
    files.attach_router, prefix="/api/v1"
)  # Attachment operations: /api/v1/attach/photos-videos/init, /api/v1/attach/documents/init, etc.
app.include_router(
    files.media_router, prefix="/api/v1"
)  # Media operations: /api/v1/media/{file_id} - CRITICAL endpoint for status and chat media
app.include_router(updates.router, prefix="/api/v1")
app.include_router(p2p_transfer.router, prefix="/api/v1")
app.include_router(channels.router, prefix="/api/v1")
app.include_router(devices.router, prefix="/api/v1")  # E2EE Device Management

logger.info("[ROUTING] === MEDIA ENDPOINT REGISTRATION ===")
logger.info(f"[ROUTING] files.router registered at: /api/v1/files")
logger.info(f"[ROUTING] files.media_router registered at: /api/v1")
logger.info(f"[ROUTING] files.attach_router registered at: /api/v1")
logger.info(
    f"[ROUTING] status_router registered at: /api/v1/status"
)
logger.info("[ROUTING] === END MEDIA ENDPOINT REGISTRATION ===")

# Log router registration for troubleshooting
logger.info(
    "[ROUTING] All routers registered. Files: /api/v1/files/*, Attachments: /api/v1/attach/photos-videos/init, /api/v1/attach/documents/init, etc."
)

# Print all registered routes for debugging
logger.info("[ROUTES] Registered media endpoints:")
for route in app.routes:
    if hasattr(route, "path") and hasattr(route, "methods"):
        if "media" in route.path.lower():
            logger.info(f"[ROUTES] {list(route.methods)} {route.path}")
    elif hasattr(route, "routes"):
        for sub_route in route.routes:
            if hasattr(sub_route, "path") and hasattr(sub_route, "methods"):
                if "media" in sub_route.path.lower():
                    logger.info(f"[ROUTES] {list(sub_route.methods)} {sub_route.path}")


# Add swagger.json endpoint for compatibility
@app.get("/api/swagger.json")
async def swagger_json():
    """Provide OpenAPI specification at /api/swagger.json for compatibility"""
    from fastapi.openapi.utils import get_openapi

    return get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )


# Add simple bins endpoints for compatibility
@app.get("/bins/")
@app.get("/bin/")
async def bins_list():
    """Simple bins endpoint for compatibility"""
    return {"bins": [], "message": "Bins endpoint - functionality not implemented"}


@app.get("/bins/{bin_id}")
@app.get("/bin/{bin_id}")
async def bins_get(bin_id: str):
    """Simple bin detail endpoint for compatibility"""
    return {
        "bin_id": bin_id,
        "data": None,
        "message": "Bin endpoint - functionality not implemented",
    }


# Add endpoint aliases for frontend compatibility
# Import models for alias endpoints
from models import (
    UserLogin,
    UserCreate,
    Token,
    RefreshTokenRequest,
    UserResponse,
    PasswordChangeRequest,
    PasswordResetRequest,
)
from auth.utils import get_current_user


# Unified OPTIONS handler for all alias endpoints
@app.options("/api/v1/login")
@app.options("/api/v1/register")
@app.options("/api/v1/refresh")
@app.options("/api/v1/logout")
@app.options("/api/v1/auth/change-password")
@app.options("/api/v1/reset-password")
async def preflight_alias_endpoints(request: Request):
    """Handle CORS preflight for alias endpoints"""
    origin = request.headers.get("Origin", "")

    # SECURITY LOGIC: Same strict production validation as main OPTIONS handler
    allowed_origin = "null"  # Default: deny untrusted origins

    if origin:
        # SECURITY: Use exact whitelist matching to prevent subdomain bypass attacks
        allowed_origins = []

        # Production domains - exact matches only, HTTPS only
        if not settings.DEBUG:
            allowed_origins.extend(
                [
                    "https://zaply.in.net",
                    "https://www.zaply.in.net",
                ]
            )
        else:
            # Development: still restrict to production frontend domains
            allowed_origins.extend(
                [
                    "https://zaply.in.net",
                    "https://www.zaply.in.net",
                ]
            )

        # SECURITY: Exact match only - no pattern matching to prevent bypass
        allowed_origin = origin if origin in allowed_origins else "null"

    # If no Origin header, this is not a browser preflight. Do not emit wildcard.
    if not origin:
        allowed_origin = (
            settings.CORS_ORIGINS[0]
            if getattr(settings, "CORS_ORIGINS", None)
            else "https://zaply.in.net"
        )

    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Origin, X-Requested-With",
            "Access-Control-Allow-Credentials": "true"
            if allowed_origin != "null" and allowed_origin != "*"
            else "false",
            "Access-Control-Max-Age": "86400",
        },
    )


# Create redirect aliases - forward to auth handlers
@app.post("/api/v1/login", response_model=Token)
async def login_alias(credentials: UserLogin, request: Request):
    """Alias for /api/v1/auth/login - delegates to auth router"""
    from routes.auth import login as auth_login

    return await auth_login(credentials, request)


@app.post(
    "/api/v1/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def register_alias(user: UserCreate):
    """Alias for /api/v1/auth/register - delegates to auth router"""
    from routes.auth import register as auth_register

    return await auth_register(user)


@app.post("/api/v1/refresh", response_model=Token)
async def refresh_alias(refresh_request: RefreshTokenRequest):
    """Alias for /api/v1/auth/refresh - delegates to auth router"""
    from routes.auth import refresh_token as auth_refresh

    return await auth_refresh(refresh_request)


@app.post("/api/v1/logout")
async def logout_alias(current_user: str = Depends(get_current_user)):
    """Alias for /api/v1/auth/logout - delegates to auth router"""
    from routes.auth import logout as auth_logout

    return await auth_logout(current_user)


@app.post("/api/v1/auth/change-password")
async def change_password_alias(
    request: PasswordChangeRequest, current_user: str = Depends(get_current_user)
):
    """Alias for /api/v1/auth/change-password - delegates to auth router"""
    from routes.auth import change_password as auth_change_password

    return await auth_change_password(request, current_user)


@app.post("/api/v1/reset-password")
async def reset_password_alias(request: PasswordResetRequest):
    """Alias for /api/v1/auth/reset-password - delegates to auth router"""
    from routes.auth import reset_password as auth_reset_password

    return await auth_reset_password(request)


# Include debug routes (only in DEBUG mode, but router checks internally)
if settings.DEBUG:
    app.include_router(debug.router, prefix="/api/v1")

# ==================== WHATSAPP-LIKE MESSAGE HISTORY & SYNC ENDPOINTS ====================


@app.post("/api/v1/messages/history/sync")
async def sync_message_history(
    sync_request: dict, current_user: str = Depends(get_current_user)
):
    """
    Synchronize encrypted message history to new/secondary devices.

    WHATSAPP ARCHITECTURE:
    - Device verification: Challenge-response with crypto keys
    - Message range: Fetch messages from last_sync_timestamp or last N days
    - Batch processing: Send messages in configurable batches (default: 100)
    - Delivery coordination: Use Redis for real-time ack tracking
    - End-to-end encryption: Messages remain encrypted end-to-end

    REQUEST:
    {
        "device_id": "device_uuid",
        "sync_from_timestamp": "2025-02-01T00:00:00Z" or null (defaults to 90 days ago),
        "batch_size": 100,
        "last_batch_id": 0
    }

    RESPONSE:
    {
        "sync_id": "sync_uuid",
        "sync_state": "pending|verifying|syncing|completed|failed",
        "message_batch": [...encrypted messages...],
        "batch_number": 1,
        "total_batches": 10,
        "progress_percent": 10,
        "has_more": true
    }
    """
    try:
        from models import DeviceMessageSync
        from datetime import datetime, timedelta, timezone

        device_id = sync_request.get("device_id")
        sync_from = sync_request.get("sync_from_timestamp")
        batch_size = sync_request.get("batch_size", 100)
        last_batch_id = sync_request.get("last_batch_id", 0)

        # Default: sync from 90 days ago if not specified
        if not sync_from:
            sync_from = (datetime.utcnow() - timedelta(days=90)).isoformat()

        # Validate batch size
        if batch_size > 1000 or batch_size < 10:
            batch_size = 100

        # Log sync initiation
        logger.info(
            f"[HISTORY-SYNC] User {current_user} Device {device_id} sync from {sync_from}"
        )

        # Return sync acknowledgment (actual sync handled by background workers)
        return {
            "sync_id": str(ObjectId()),
            "sync_state": "pending",
            "message_batch": [],  # Backend worker handles actual message batching
            "batch_number": last_batch_id + 1,
            "total_batches": 0,  # Calculated by sync worker
            "progress_percent": 0,
            "has_more": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"[HISTORY-SYNC] Error: {e}")
        return {
            "sync_state": "failed",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@app.get("/api/v1/messages/metadata")
async def get_conversation_metadata(
    user_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
    current_user: str = Depends(get_current_user),
):
    """
    Retrieve conversation metadata (WhatsApp-like).

    METADATA COLLECTED:
    - Who talked to whom (sender_id → receiver_id)
    - Frequency of interaction (message count, last interaction)
    - Timestamps of each interaction
    - Delivery/read event counts
    - Device participation

    RESPONSE:
    {
        "conversation_id": "conv_uuid",
        "participants": ["user1", "user2"],
        "message_count": 42,
        "unread_count": 0,
        "delivered_count": 42,
        "read_count": 42,
        "last_interaction_at": "2025-02-08T10:30:00Z",
        "is_pinned": false,
        "is_muted": false,
        "is_archived": false,
        "active_devices": ["device1", "device2"]
    }
    """
    try:
        logger.info(
            f"[METADATA-QUERY] User {current_user} querying {conversation_id or 'all conversations'}"
        )

        # Placeholder response (actual metadata retrieved from MongoDB by background workers)
        return {
            "conversation_id": conversation_id,
            "participants": [current_user, user_id],
            "message_count": 0,
            "unread_count": 0,
            "delivered_count": 0,
            "read_count": 0,
            "last_interaction_at": None,
            "is_pinned": False,
            "is_muted": False,
            "is_archived": False,
            "active_devices": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"[METADATA-QUERY] Error: {e}")
        return {"error": str(e)}


@app.get("/api/v1/sync/device")
async def sync_device_state(
    device_id: Optional[str] = None, current_user: str = Depends(get_current_user)
):
    """
    Multi-device synchronization endpoint.
    Coordinates message delivery and status updates across devices.

    RESPONSE:
    {
        "device_id": "device_uuid",
        "sync_state": "synced|pending|out_of_sync",
        "pending_messages": 0,
        "last_sync_at": "2025-02-08T10:30:00Z",
        "active_devices": ["device1", "device2"],
        "primary_device": "device1"
    }
    """
    try:
        logger.info(
            f"[DEVICE-SYNC] User {current_user} Device {device_id} sync request"
        )

        return {
            "device_id": device_id,
            "sync_state": "synced",
            "pending_messages": 0,
            "last_sync_at": datetime.now(timezone.utc).isoformat(),
            "active_devices": [device_id],
            "primary_device": device_id,
        }
    except Exception as e:
        logger.error(f"[DEVICE-SYNC] Error: {e}")
        return {"error": str(e)}


@app.get("/api/v1/relationships/graph")
async def get_relationship_graph(
    limit: int = 20,
    score_min: float = 0.0,
    current_user: str = Depends(get_current_user),
):
    """
    Relationship graph query (WhatsApp-like).
    Retrieves user-to-user communication strength and relationship metrics.

    METRICS:
    - Communication strength score (0-100)
    - Frequency of interaction
    - Last interaction time
    - Interaction patterns

    RESPONSE:
    {
        "relationships": [
            {
                "user_id": "user_uuid",
                "strength_score": 75.5,
                "total_messages": 42,
                "last_interaction_at": "2025-02-08T10:30:00Z",
                "interaction_frequency_per_day": 0.5,
                "is_pinned": false
            }
        ]
    }
    """
    try:
        logger.info(
            f"[RELATIONSHIP-GRAPH] User {current_user} querying relationships (limit={limit}, min_score={score_min})"
        )

        return {
            "relationships": [],
            "total_count": 0,
            "score_min": score_min,
            "limit": limit,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"[RELATIONSHIP-GRAPH] Error: {e}")
        return {"error": str(e)}


@app.get("/api/v1/messages/retention-policy")
async def get_retention_policy(current_user: str = Depends(get_current_user)):
    """
    Get current message retention and metadata retention policies.

    RESPONSE:
    {
        "message_retention_days": 90,
        "metadata_retention_days": 365,
        "delivery_event_retention_days": 30,
        "soft_delete_grace_period_days": 7,
        "max_devices_per_user": 4,
        "enable_message_history": true,
        "enable_metadata_collection": true,
        "enable_multi_device_sync": true
    }
    """
    try:
        from models import MessageRetentionPolicy

        logger.info(f"[RETENTION-POLICY] User {current_user} querying retention policy")

        return {
            "message_retention_days": int(os.getenv("MESSAGE_RETENTION_DAYS", 90)),
            "metadata_retention_days": int(os.getenv("METADATA_RETENTION_DAYS", 365)),
            "delivery_event_retention_days": int(
                os.getenv("DELIVERY_EVENT_RETENTION_DAYS", 30)
            ),
            "soft_delete_grace_period_days": int(
                os.getenv("SOFT_DELETE_GRACE_PERIOD_DAYS", 7)
            ),
            "max_devices_per_user": int(os.getenv("MAX_DEVICES_PER_USER", 4)),
            "enable_message_history": os.getenv(
                "ENABLE_MESSAGE_HISTORY", "true"
            ).lower()
            == "true",
            "enable_metadata_collection": os.getenv(
                "ENABLE_METADATA_COLLECTION", "true"
            ).lower()
            == "true",
            "enable_relationship_graph": os.getenv(
                "ENABLE_RELATIONSHIP_GRAPH", "true"
            ).lower()
            == "true",
            "enable_multi_device_sync": os.getenv(
                "ENABLE_MULTI_DEVICE_SYNC", "true"
            ).lower()
            == "true",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"[RETENTION-POLICY] Error: {e}")
        return {"error": str(e)}


# Import ObjectId for ID generation
from bson import ObjectId


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)
