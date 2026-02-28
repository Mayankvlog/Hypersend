import os
import logging
import asyncio
import sys
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import HTTPException, status
from dotenv import load_dotenv
from pathlib import Path

try:
    from .config import settings
except Exception:
    from config import settings

IS_PRODUCTION = os.getenv("ENVIRONMENT", "").lower() == "production" and os.getenv("DEBUG", "").lower() not in (
    "true",
    "1",
    "yes",
)

# Load environment variables from .env file
# Docker requirement: only load from /app/backend/.env and /app/.env inside container.
_env_paths = [Path("/app/backend/.env"), Path("/app/.env")]
for env_path in _env_paths:
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
        break

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
    try:
        if os.getenv("PYTEST_CURRENT_TEST"):
            return True
        return "pytest" in sys.modules
    except Exception:
        return False

async def init_database():
    """Initialize MongoDB Atlas database connection.

    This function is designed to be called exactly once during FastAPI startup.
    It is async-safe and will not create duplicate clients under concurrent calls.
    """
    global client, db, _database_initialized, _init_lock

    if _init_lock is None:
        _init_lock = asyncio.Lock()

    async with _init_lock:
        if _database_initialized and client is not None and db is not None:
            return

        # Atlas-only mode (no mock/fallback): when Atlas is enabled, mock DB is forbidden
        # even under pytest.
        mongodb_atlas_enabled = (os.getenv("MONGODB_ATLAS_ENABLED") or "").lower() == "true"
        use_mock_db = (os.getenv("USE_MOCK_DB") or "").lower() == "true"
        
        # Allow mock database in pytest environment
        if _is_pytest_running() and use_mock_db:
            # In pytest, allow mock database even if Atlas is configured
            print("✅ Using mock database for pytest")
            _database_initialized = True
            return
        
        if not mongodb_atlas_enabled:
            # Atlas must be enabled for this backend.
            raise RuntimeError('MONGODB_ATLAS_ENABLED must be "true"')
            
        if mongodb_atlas_enabled and use_mock_db:
            raise RuntimeError('USE_MOCK_DB must be "false" when MongoDB Atlas is enabled')
            
        # Continue with Atlas initialization

        mongodb_uri = os.getenv("MONGODB_URI")
        if not mongodb_uri:
            raise RuntimeError('MONGODB_URI is required for Atlas-only operation')

        database_name = os.getenv("DATABASE_NAME")
        if not database_name:
            raise RuntimeError('DATABASE_NAME is required for Atlas-only operation')

        if client is None:
            client = AsyncIOMotorClient(
                mongodb_uri,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
            )
        if db is None:
            db = client[database_name]

        await client.admin.command("ping")
        print("MongoDB Atlas connected")

        # Create/update indexes used by hot-path queries (idempotent)
        try:
            await db["messages"].create_index([("chat_id", 1), ("created_at", 1)])
            await db["users"].create_index([("email", 1)], unique=True)
        except Exception:
            # Index creation should not prevent startup; Atlas may restrict permissions.
            pass

        _database_initialized = True
        print(f"Database initialized: {db is not None}, Client initialized: {client is not None}")
        print(f"Database name: {database_name}")

def get_database():
    """Get database instance"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db

# Collection shortcuts
def users_collection():
    """Get users collection"""
    if _is_pytest_running() and (os.getenv("USE_MOCK_DB") or "").lower() == "true":
        # Return mock collection for pytest
        from .mock_database import MockCollection
        return MockCollection("users")
    if is_database_initialized() and db is not None:
        return db["users"]
    raise RuntimeError("Database not initialized")

def chats_collection():
    """Get chats collection"""
    if _is_pytest_running() and (os.getenv("USE_MOCK_DB") or "").lower() == "true":
        # Return mock collection for pytest
        from .mock_database import MockCollection
        return MockCollection("chats")
    if is_database_initialized() and db is not None:
        return db["chats"]
    raise RuntimeError("Database not initialized")

def messages_collection():
    """Get messages collection"""
    if _is_pytest_running() and (os.getenv("USE_MOCK_DB") or "").lower() == "true":
        # Return mock collection for pytest
        from .mock_database import MockCollection
        return MockCollection("messages")
    if is_database_initialized() and db is not None:
        return db["messages"]
    raise RuntimeError("Database not initialized")

def files_collection():
    """Get files collection"""
    if _is_pytest_running() and (os.getenv("USE_MOCK_DB") or "").lower() == "true":
        # Return mock collection for pytest
        from .mock_database import MockCollection
        return MockCollection("files")
    if is_database_initialized() and db is not None:
        return db["files"]
    raise RuntimeError("Database not initialized")

def uploads_collection():
    """Get uploads collection"""
    if _is_pytest_running() and (os.getenv("USE_MOCK_DB") or "").lower() == "true":
        # Return mock collection for pytest
        from .mock_database import MockCollection
        return MockCollection("uploads")
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
    await init_database()

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
