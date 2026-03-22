import os
import logging
import asyncio
import sys
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import HTTPException, status
from dotenv import load_dotenv
from pathlib import Path
from backend.config import settings

logger = logging.getLogger(__name__)

# NOTE: Environment variables are already loaded by config.py
# Do NOT reload .env files here to prevent duplicate initialization

# Global database connection variables as specified
client = None
db = None

# Database initialization state tracker
_database_initialized = False

# Async-safe initialization guard to prevent duplicate Motor clients
_init_lock: asyncio.Lock | None = None

# Atlas-only mode: do not recreate the Motor client based on event loop.

def is_database_initialized():
    """Check if database is initialized"""
    global _database_initialized, db
    return _database_initialized and db is not None


def _is_pytest_running() -> bool:
    """Centralized pytest detection - used across all modules"""
    try:
        if os.getenv("PYTEST_CURRENT_TEST"):
            return True
        if "pytest" in sys.modules:
            return True
        return False
    except Exception:
        return False

async def init_database():
    """Initialize MongoDB Atlas database connection (ASYNC ONLY).

    This function is designed to be called exactly once during FastAPI startup.
    It is async-safe and will not create duplicate clients under concurrent calls.
    CRITICAL: Uses UTC timestamps only via datetime.utcnow()
    """
    global client, db, _database_initialized, _init_lock

    if _init_lock is None:
        _init_lock = asyncio.Lock()

    async with _init_lock:
        if _database_initialized and client is not None and db is not None:
            return
        
        # Prevent duplicate initialization
        if _database_initialized:
            logger.info("[DATABASE] Already initialized, returning existing connection")
            return

        # Import settings to get centralized config (already validated by config.py)
        try:
            from backend.config import settings
        except ImportError:
            from config import settings
        
        # CRITICAL FIX: Check environment directly for values that may change at runtime (e.g., during pytest)
        # config.py was loaded at import time, but pytest may change env vars after that
        mongodb_atlas_enabled = os.getenv("MONGODB_ATLAS_ENABLED", "true").lower() == "true"
        mongodb_uri = os.getenv("MONGODB_URI") or settings.MONGODB_URI
        database_name = os.getenv("DATABASE_NAME") or settings.DATABASE_NAME

        if not mongodb_atlas_enabled:
            raise RuntimeError('MONGODB_ATLAS_ENABLED must be "true"')

        if not mongodb_uri:
            raise RuntimeError('MONGODB_URI is required for Atlas-only operation')

        if not database_name:
            raise RuntimeError('DATABASE_NAME is required for Atlas-only operation')

        if client is None:
            logger.info(f"[DATABASE] Initializing MongoDB Atlas connection (ASYNC ONLY)...")
            temp_client = None
            try:
                temp_client = AsyncIOMotorClient(
                    mongodb_uri,
                    serverSelectionTimeoutMS=10000,
                    connectTimeoutMS=10000,
                    maxPoolSize=50,
                    minPoolSize=10,
                )
                # Verify connection is working
                await asyncio.wait_for(temp_client.admin.command("ping"), timeout=10.0)
                logger.info(f"[DATABASE] MongoDB Atlas connected successfully (db={database_name})")
                # Only assign to module variable after successful connection
                client = temp_client
            except asyncio.TimeoutError:
                logger.error("[DATABASE] Connection timeout - MongoDB Atlas unreachable")
                # Clean up temp client on failure
                if temp_client:
                    temp_client.close()
                raise RuntimeError("Failed to connect to MongoDB Atlas")
            except asyncio.CancelledError:
                logger.error("[DATABASE] Connection cancelled")
                # Clean up temp client on cancellation
                if temp_client:
                    temp_client.close()
                raise
            except Exception as e:
                logger.error(f"[DATABASE] Connection error: {e}")
                # Clean up temp client on any error
                if temp_client:
                    temp_client.close()
                raise
        
        if db is None:
            db = client[database_name]

        # Create/update indexes used by hot-path queries (idempotent) - ASYNC ONLY
        try:
            # Create all necessary indexes for hot-path queries
            await db["messages"].create_index([("chat_id", 1), ("created_at", 1)])
            await db["messages"].create_index([("status", 1), ("created_at", 1)])
            await db["users"].create_index([("email", 1)], unique=True)
            await db["chats"].create_index([("members", 1), ("updated_at", 1)])
            await db["statuses"].create_index([("expires_at", 1)])  # For status cleanup
            await db["statuses"].create_index([("user_id", 1), ("created_at", -1)])  # For status queries
            logger.info("[DATABASE] Async indexes created/verified (UTC timestamps used)")
        except Exception as e:
            # Index creation should not prevent startup; Atlas may restrict permissions.
            logger.warning(f"[DATABASE] Index creation skipped: {type(e).__name__}")

        _database_initialized = True

def _mask_uri(uri: str) -> str:
    """Mask MongoDB URI password for logging"""
    try:
        if "@" not in uri:
            return uri
        prefix = uri.split("@")[0]
        suffix = uri.split("@")[1]
        if "://" in prefix:
            scheme = prefix.split("://")[0]
            return f"{scheme}://***:***@{suffix}"
        return uri
    except Exception:
        return "***MASKED***"

def get_database():
    """Get database instance"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db

# Collection shortcuts
def users_collection():
    """Get users collection"""
    if is_database_initialized() and db is not None:
        return db["users"]
    raise RuntimeError("Database not initialized")

def chats_collection():
    """Get chats collection"""
    if is_database_initialized() and db is not None:
        return db["chats"]
    raise RuntimeError("Database not initialized")

def messages_collection():
    """Get messages collection"""
    if is_database_initialized() and db is not None:
        return db["messages"]
    raise RuntimeError("Database not initialized")

def files_collection():
    """Get files collection"""
    if is_database_initialized() and db is not None:
        return db["files"]
    raise RuntimeError("Database not initialized")

def uploads_collection():
    """Get uploads collection"""
    if is_database_initialized() and db is not None:
        return db["uploads"]
    raise RuntimeError("Database not initialized")

def refresh_tokens_collection():
    """Get refresh tokens collection"""
    if is_database_initialized() and db is not None:
        return db["refresh_tokens"]
    raise RuntimeError("Database not initialized")

def reset_tokens_collection():
    """Get reset tokens collection"""
    if is_database_initialized() and db is not None:
        return db["reset_tokens"]
    raise RuntimeError("Database not initialized")

def group_activity_collection():
    """Get group activity collection"""
    if is_database_initialized() and db is not None:
        return db["group_activity"]
    raise RuntimeError("Database not initialized")

def media_collection():
    """Get media collection"""
    if is_database_initialized() and db is not None:
        return db["media"]
    raise RuntimeError("Database not initialized")

# Backward compatibility aliases for tests
async def connect_db():
    # Legacy wrapper used by some test suites that patch `database.settings` and
    # `database.AsyncIOMotorClient`. Keep behavior predictable for those tests
    # without changing the Atlas-only guarantees enforced by `init_database()`.
    global client, db, _database_initialized

    # If the attribute exists on `settings` (even if None), honor it.
    if hasattr(settings, "MONGODB_URI"):
        mongodb_uri = getattr(settings, "MONGODB_URI")
    else:
        mongodb_uri = os.getenv("MONGODB_URI")

    if hasattr(settings, "_MONGO_DB"):
        database_name = getattr(settings, "_MONGO_DB")
    else:
        database_name = os.getenv("DATABASE_NAME")
    use_mock_db = bool(getattr(settings, "USE_MOCK_DB", False))

    if use_mock_db:
        raise RuntimeError('USE_MOCK_DB must be "false" for Atlas-only operation')

    if not mongodb_uri or not database_name:
        raise ValueError("Database configuration is invalid")

    # Always (re)create a client here so patched AsyncIOMotorClient in tests is used.
    client = AsyncIOMotorClient(
        mongodb_uri,
        retryWrites=False,
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
    )
    db = client[database_name]

    try:
        await client.admin.command("ping")
    except asyncio.TimeoutError as e:
        raise ConnectionError("Database connection test failed") from e
    except Exception as e:
        raise ConnectionError("Database connection test failed") from e

    _database_initialized = True

get_db = get_database

# Add database module export for imports
database = sys.modules[__name__]

# Ensure this module is a singleton regardless of import path.
# Tests and app code sometimes import it as `database` (via PYTHONPATH) and
# sometimes as `backend.database` (package import). Without aliasing, Python
# can load the same file twice under different names, resulting in separate
# global `client`/`db` state and "Database not initialized" errors.
sys.modules.setdefault("database", database)
sys.modules.setdefault("backend.database", database)
