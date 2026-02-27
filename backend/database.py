import os
import logging
import asyncio
import sys
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import HTTPException, status
from dotenv import load_dotenv
from pathlib import Path

IS_PRODUCTION = os.getenv("ENVIRONMENT", "").lower() == "production" and os.getenv("DEBUG", "").lower() not in (
    "true",
    "1",
    "yes",
)

# Load environment variables from .env file
env_paths = [Path(__file__).parent / ".env", Path(__file__).parent.parent / ".env"]
for env_path in env_paths:
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
        break

# Global database connection variables as specified
client = None
db = None

# Database initialization state tracker
_database_initialized = False

# Async-safe initialization guard to prevent duplicate Motor clients
_init_lock: asyncio.Lock | None = None

# Track which event loop created the Motor client/lock. Motor clients are not safe
# to reuse across different event loops (common in pytest/TestClient lifecycles).
_init_loop_id: int | None = None


def _ensure_client_db_sync() -> None:
    global client, db, _database_initialized
    if db is not None and client is not None:
        return

    mongodb_atlas_enabled = os.getenv("MONGODB_ATLAS_ENABLED", "").lower()
    if mongodb_atlas_enabled != "true":
        return

    mongodb_uri = os.getenv("MONGODB_URI")
    database_name = os.getenv("DATABASE_NAME")
    if not mongodb_uri or not database_name:
        return

    if client is None:
        client = AsyncIOMotorClient(mongodb_uri, serverSelectionTimeoutMS=10000)
    if db is None:
        db = client[database_name]
    _database_initialized = True

def is_database_initialized():
    """Check if database is initialized"""
    global _database_initialized, db
    return _database_initialized and db is not None

async def init_database():
    """Initialize MongoDB Atlas database connection.

    This function is designed to be called exactly once during FastAPI startup.
    It is async-safe and will not create duplicate clients under concurrent calls.
    """
    global client, db, _database_initialized, _init_lock, _init_loop_id

    current_loop = asyncio.get_running_loop()
    current_loop_id = id(current_loop)

    # If we're running under a different loop than the one that created the lock/client,
    # reset both. This prevents "Event loop is closed" errors in tests.
    if _init_loop_id is not None and _init_loop_id != current_loop_id:
        try:
            if client is not None:
                client.close()
        except Exception:
            pass
        client = None
        db = None
        _database_initialized = False
        _init_lock = None
        _init_loop_id = None

    if _init_lock is None:
        _init_lock = asyncio.Lock()
        _init_loop_id = current_loop_id

    async with _init_lock:
        if _database_initialized and client is not None and db is not None:
            return

        mongodb_atlas_enabled = os.getenv("MONGODB_ATLAS_ENABLED", "").lower()
        if mongodb_atlas_enabled != "true":
            raise RuntimeError("MONGODB_ATLAS_ENABLED must be true")

        mongodb_uri = os.getenv("MONGODB_URI")
        if not mongodb_uri:
            raise RuntimeError("MONGODB_URI is required")

        database_name = os.getenv("DATABASE_NAME")
        if not database_name:
            raise RuntimeError("DATABASE_NAME is required")

        # Close any half-initialized prior client before re-creating.
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

        client = AsyncIOMotorClient(mongodb_uri, serverSelectionTimeoutMS=10000)
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
        _init_loop_id = current_loop_id
        print(f"Database initialized: {db is not None}, Client initialized: {client is not None}")
        print(f"Database name: {database_name}")

def get_database():
    """Get database instance"""
    _ensure_client_db_sync()
    if db is None:
        raise RuntimeError("Database not initialized")
    return db

# Collection shortcuts
def users_collection():
    """Get users collection"""
    _ensure_client_db_sync()
    if is_database_initialized() and db is not None:
        return db["users"]
    raise RuntimeError("Database not initialized")

def chats_collection():
    """Get chats collection"""
    _ensure_client_db_sync()
    if is_database_initialized() and db is not None:
        return db["chats"]
    raise RuntimeError("Database not initialized")

def messages_collection():
    """Get messages collection"""
    _ensure_client_db_sync()
    if is_database_initialized() and db is not None:
        return db["messages"]
    raise RuntimeError("Database not initialized")

def files_collection():
    """Get files collection"""
    _ensure_client_db_sync()
    if is_database_initialized() and db is not None:
        return db["files"]
    raise RuntimeError("Database not initialized")

def uploads_collection():
    """Get uploads collection"""
    _ensure_client_db_sync()
    if is_database_initialized() and db is not None:
        return db["uploads"]
    raise RuntimeError("Database not initialized")

def refresh_tokens_collection():
    """Get refresh tokens collection"""
    _ensure_client_db_sync()
    if is_database_initialized() and db is not None:
        return db["refresh_tokens"]
    raise RuntimeError("Database not initialized")

def reset_tokens_collection():
    """Get reset tokens collection"""
    _ensure_client_db_sync()
    if is_database_initialized() and db is not None:
        return db["reset_tokens"]
    raise RuntimeError("Database not initialized")

def group_activity_collection():
    """Get group activity collection"""
    _ensure_client_db_sync()
    if is_database_initialized() and db is not None:
        return db["group_activity"]
    raise RuntimeError("Database not initialized")

def media_collection():
    """Get media collection"""
    _ensure_client_db_sync()
    if is_database_initialized() and db is not None:
        return db["media"]
    raise RuntimeError("Database not initialized")

# Backward compatibility aliases for tests
connect_db = lambda: None  # No-op since we use global client
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
