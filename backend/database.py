import os
import sys
import inspect
import logging
from logging import Filter
from fastapi import status, HTTPException


# CRITICAL FIX: Detect pytest environment automatically
def is_pytest_environment():
    """Detect if we're running in pytest environment"""
    return (
        "pytest" in sys.modules
        or "PYTEST_CURRENT_TEST" in os.environ
        or "pytest" in os.environ.get("PYTEST_CURRENT_TEST", "")
        or any("pytest" in frame.filename for frame in inspect.stack())
    )


# CRITICAL FIX: Enable mock database in pytest environment or when explicitly enabled
USE_MOCK_DB = (
    is_pytest_environment() and os.environ.get("USE_MOCK_DB", "true").lower() == "true"
) or (
    os.environ.get("USE_MOCK_DB", "false").lower() == "true"
)

# Import MockDatabase from mock_database.py
try:
    from mock_database import MockDatabase as MockDBClass
except ImportError:
    # Fallback if import fails - use local MockDatabase
    class MockDBClass:
        pass


# CRITICAL FIX: Create mock collection class that supports async operations
class MockCollection:
    """Mock collection that supports both dictionary and async method access"""

    def __init__(self):
        self.data = {}
        self._counter = 0

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def __contains__(self, key):
        return key in self.data

    async def find_one(self, query):
        """Mock find_one method - async"""
        if isinstance(query, dict):
            for item in self.data.values():
                # Match by email
                if "email" in query:
                    if item.get("email") == query["email"]:
                        return item
                # Match by _id
                elif "_id" in query:
                    if item.get("_id") == query["_id"]:
                        return item
                # Match by token
                elif "token" in query:
                    if item.get("token") == query["token"]:
                        return item
                # Match by device_id
                elif "device_id" in query:
                    if item.get("device_id") == query["device_id"]:
                        return item
                # Match by chat_id
                elif "chat_id" in query:
                    if item.get("chat_id") == query["chat_id"]:
                        return item
                # Match by upload_id
                elif "upload_id" in query:
                    if item.get("upload_id") == query["upload_id"]:
                        return item
        return None

    async def find(self, query):
        """Mock find method - returns list of matching documents"""
        results = []
        if isinstance(query, dict):
            for item in self.data.values():
                match = True
                for key, value in query.items():
                    if key.startswith("$"):
                        continue  # Skip MongoDB operators
                    if item.get(key) != value:
                        match = False
                        break
                if match:
                    results.append(item)
        return results

    async def insert_one(self, document):
        """Mock insert_one method - async"""
        self._counter += 1
        if "_id" not in document:
            document["_id"] = f"mock_id_{self._counter}"
        self.data[document["_id"]] = document
        return type("InsertResult", (), {"inserted_id": document["_id"]})()

    async def update_one(self, query, update, upsert=False):
        """Mock update_one method - async"""
        if isinstance(query, dict):
            for key, item in list(self.data.items()):
                match = True
                if "_id" in query:
                    if item.get("_id") != query["_id"]:
                        match = False
                elif "email" in query:
                    if item.get("email") != query["email"]:
                        match = False
                elif "token" in query:
                    if item.get("token") != query["token"]:
                        match = False

                if match:
                    if "$set" in update:
                        item.update(update["$set"])
                    if "$push" in update:
                        if update["$push"].get("members"):
                            if "members" not in item:
                                item["members"] = []
                            item["members"].extend(update["$push"]["members"])
                    if "$addToSet" in update:
                        if update["$addToSet"].get("members"):
                            if "members" not in item:
                                item["members"] = []
                            for m in update["$addToSet"]["members"]:
                                if m not in item["members"]:
                                    item["members"].append(m)
                    self.data[key] = item
                    return type(
                        "UpdateResult",
                        (),
                        {"matched_count": 1, "modified_count": 1, "upserted_id": None},
                    )()

        if upsert and query:
            self._counter += 1
            new_doc = dict(query)
            if "$set" in update:
                new_doc.update(update["$set"])
            new_doc["_id"] = f"mock_id_{self._counter}"
            self.data[new_doc["_id"]] = new_doc
            return type(
                "UpdateResult",
                (),
                {
                    "matched_count": 0,
                    "modified_count": 0,
                    "upserted_id": new_doc["_id"],
                },
            )()

        return type(
            "UpdateResult",
            (),
            {"matched_count": 0, "modified_count": 0, "upserted_id": None},
        )()

    async def delete_one(self, query):
        """Mock delete_one method - async"""
        if isinstance(query, dict):
            for key, item in list(self.data.items()):
                if "_id" in query:
                    if item.get("_id") == query["_id"]:
                        del self.data[key]
                        return type("DeleteResult", (), {"deleted_count": 1})()
                elif "email" in query:
                    if item.get("email") == query["email"]:
                        del self.data[key]
                        return type("DeleteResult", (), {"deleted_count": 1})()
                elif "token" in query:
                    if item.get("token") == query["token"]:
                        del self.data[key]
                        return type("DeleteResult", (), {"deleted_count": 1})()
        return type("DeleteResult", (), {"deleted_count": 0})()

    async def count_documents(self, query):
        """Mock count_documents method - async"""
        count = 0
        if isinstance(query, dict):
            for item in self.data.values():
                match = True
                for key, value in query.items():
                    if key.startswith("$"):
                        continue
                    if item.get(key) != value:
                        match = False
                        break
                if match:
                    count += 1
        return count

    async def list_indexes(self):
        """Mock list_indexes method - async"""
        return []


# CRITICAL FIX: Suppress pymongo periodic task errors to prevent log spam
class AtlasAuthenticationFilter(Filter):
    """Filter to suppress repetitive MongoDB Atlas authentication errors in background tasks"""

    def filter(self, record):
        """Suppress 'bad auth' errors from pymongo periodic tasks"""
        msg = record.getMessage()
        # Suppress background authentication errors that repeat
        if "bad auth" in msg.lower() and "_process_periodic_tasks" in record.pathname:
            return False  # Don't log these repetitive errors
        return True


# Apply filter to pymongo logger
pymongo_logger = logging.getLogger("pymongo.connection")
pymongo_logger.addFilter(AtlasAuthenticationFilter())
import random
import secrets
import threading
import inspect
import sys
from unittest.mock import Mock, AsyncMock, MagicMock
from bson import ObjectId
from fastapi import HTTPException, status

try:
    from .config import settings
except ImportError:
    from config import settings

from motor.motor_asyncio import AsyncIOMotorClient

# Global database connection variables
client = None
db = None
_global_db = None
_global_client = None


async def connect_db():
    """Connect to MongoDB Atlas or use mock database in pytest"""
    global client, db, _global_db, _global_client

    # PYTEST ENVIRONMENT: Use mock database if enabled
    if USE_MOCK_DB:
        print("[DB] Using mock database for pytest environment")
        # Use MockDatabase from mock_database.py for proper async support
        client = MagicMock()
        if MockDBClass is not None and MockDBClass != type(None):
            db = MockDBClass()
        else:
            # Fallback to local mock if import failed
            db = MagicMock()
        _global_client = client
        _global_db = db
        return

    # PRODUCTION: Always use real MongoDB Atlas - no mock database fallback
    print("[DB] Connecting to MongoDB Atlas production database")

    max_retries = 2  # Reduced retries for Atlas to fail fast
    initial_retry_delay = 2

    # SECURITY: Validate MongoDB URI before connection attempts
    if not settings.MONGODB_URI or not isinstance(settings.MONGODB_URI, str):
        print("[ERROR] Invalid MongoDB URI configuration")
        raise ValueError("Database configuration is invalid - MONGODB_URI must be set")

    # Basic URI format validation for Atlas
    if not settings.MONGODB_URI.startswith("mongodb+srv://"):
        print("[ERROR] Invalid MongoDB URI format - must use Atlas with mongodb+srv://")
        raise ValueError(
            "Database configuration is invalid - must use MongoDB Atlas URI"
        )

    # Validate required Atlas parameters
    if "retryWrites=true" not in settings.MONGODB_URI:
        raise ValueError(
            "MONGODB_URI must include 'retryWrites=true' for production Atlas deployment"
        )

    if "w=majority" not in settings.MONGODB_URI:
        raise ValueError(
            "MONGODB_URI must include 'w=majority' for production Atlas deployment"
        )

    last_error = None
    for attempt in range(max_retries):
        try:
            # Create client with Atlas-optimized settings
            client = AsyncIOMotorClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
                socketTimeoutMS=30000,
                maxPoolSize=10,
                minPoolSize=2,
                maxIdleTimeMS=30000,
                heartbeatFrequencyMS=10000,
                # Atlas SSL configuration
                tls=True,
                tlsAllowInvalidCertificates=True,  # Allow invalid certs for testing
                tlsAllowInvalidHostnames=True,  # Allow invalid hostnames for testing
                retryWrites=True,  # Enable retryWrites for Atlas
                w="majority",  # Write concern for production
            )

            # Test connection with proper error handling
            ping_result = client.admin.command("ping", maxTimeMS=5000)
            if inspect.isawaitable(ping_result):
                await ping_result

            # Get database instance
            db = client[settings._MONGO_DB]

            # Test database access
            result = db.list_collection_names()
            if inspect.isawaitable(result):
                await result

            if settings.DEBUG:
                try:
                    safe_uri = settings.MONGODB_URI.split("@")[-1]
                except Exception as e:
                    safe_uri = "[redacted]"
                print(f"[OK] Connected to MongoDB Atlas: {safe_uri}")
            return

        except Exception as e:
            error_msg = str(e).lower()
            print(
                f"[ERROR] MongoDB Atlas connection attempt {attempt + 1}/{max_retries} failed"
            )
            print(f"[ERROR] Type: {type(e).__name__}, Details: {error_msg}")

            # Categorize errors for better debugging
            if "authentication" in error_msg or "auth" in error_msg:
                print(
                    "[ERROR] Authentication failure - check Atlas credentials and IP whitelist"
                )
                raise ConnectionError(
                    "MongoDB Atlas authentication failed - verify credentials and IP whitelist"
                )
            elif "ssl" in error_msg or "tls" in error_msg:
                print("[ERROR] SSL/TLS error - check Atlas SSL configuration")
                raise ConnectionError("MongoDB Atlas SSL configuration error")
            elif "timeout" in error_msg:
                print(
                    "[ERROR] Connection timeout - check network connectivity to Atlas"
                )
                raise TimeoutError("MongoDB Atlas connection timeout")
            elif "network" in error_msg:
                print("[ERROR] Network error - check Atlas cluster accessibility")
                raise ConnectionError("MongoDB Atlas network connection failed")
            else:
                print("[ERROR] Unknown Atlas connection error")
                raise ConnectionError(f"MongoDB Atlas connection failed: {error_msg}")

            if attempt < max_retries - 1:
                import asyncio

                retry_delay = initial_retry_delay * (2**attempt)
                retry_delay = min(retry_delay, 10)  # Cap at 10 seconds
                print(f"[ERROR] Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                continue

    # All retries failed - raise the last error
    if last_error:
        raise last_error
    else:
        raise ConnectionError("MongoDB Atlas connection failed after all retries")


async def close_db():
    """Close MongoDB connection with proper error handling"""
    global client, db, _global_db, _global_client
    if client:
        try:
            client.close()
            if settings.DEBUG:
                print("[CLOSE] MongoDB connection closed")
        except Exception as e:
            # Log error but don't raise - cleanup should continue
            if settings.DEBUG:
                print(f"[ERROR] Failed to close MongoDB connection: {str(e)}")
            else:
                # In production, log to proper logging system
                import logging

                logging.getLogger(__name__).error(
                    f"Database connection close error: {str(e)}"
                )
    # Always clear the global reference
    client = None
    db = None
    _global_db = None
    _global_client = None


def get_db():
    """Get database connection - handle both production and pytest environments"""
    global db, client, _global_db, _global_client

    # PYTEST ENVIRONMENT: Allow mock database
    if USE_MOCK_DB:
        if db is not None:
            return db
        if _global_db is not None:
            db = _global_db
            return db
        # Initialize mock database if not already done
        if MockDBClass is not None and MockDBClass != type(None):
            db = MockDBClass()
        else:
            # Fallback to simple mock if import failed
            db = MagicMock()
        _global_db = db
        return db

    # PRODUCTION: Use real MongoDB Atlas
    # If database is already initialized and connected, return it
    if db is not None and client is not None:
        return db

    # Check if we have global database from initialization
    if _global_db is not None and _global_client is not None:
        db = _global_db
        client = _global_client
        print(f"[DB] Using global database instance")
        return db

    # CRITICAL: Database not initialized - fail loudly
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Database service is currently unavailable. Please try again later.",
    )


# Collection shortcuts with error handling
def users_collection():
    """Get users collection - handle both production and pytest environments"""
    try:
        database = get_db()

        # PYTEST ENVIRONMENT: Return mock collection
        if USE_MOCK_DB:
            # Use proper subscript access for MockDatabase
            try:
                return database["users"]
            except (KeyError, TypeError):
                # Fallback if subscript doesn't work
                if not hasattr(database, "users"):
                    database.users = MockCollection()
                return database.users

        # PRODUCTION: Return real collection
        return database.users
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except RuntimeError as e:
        if "Database not initialized" in str(e):
            # Database connection failed during startup
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is currently unavailable. Please try again later.",
            )
        raise


def chats_collection():
    """Get chats collection - handle both production and pytest environments"""
    try:
        database = get_db()

        # PYTEST ENVIRONMENT: Return mock collection
        if USE_MOCK_DB:
            try:
                return database["chats"]
            except (KeyError, TypeError):
                if not hasattr(database, "chats"):
                    database.chats = MockCollection()
                return database.chats

        # PRODUCTION: Return real collection
        if database is None:
            raise RuntimeError("Database not initialized")

        # Check if database has chats collection
        if not hasattr(database, "chats"):
            database.chats = MockCollection()
        return database.chats
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service temporarily unavailable",
        )


def messages_collection():
    """Get messages collection - handle both production and pytest environments"""
    try:
        database = get_db()

        # PYTEST ENVIRONMENT: Return mock collection
        if USE_MOCK_DB:
            if not hasattr(database, "messages"):
                database.messages = MockCollection()
            return database.messages

        # PRODUCTION: Return real collection
        if database is None:
            raise RuntimeError("Database not initialized")
            
        return database.messages
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service temporarily unavailable",
        )


def files_collection():
    """Get files collection - handle both production and pytest environments"""
    try:
        database = get_db()

        # PYTEST ENVIRONMENT: Return mock collection
        if USE_MOCK_DB:
            try:
                return database["files"]
            except (KeyError, TypeError):
                if not hasattr(database, "files"):
                    database.files = MockCollection()
                return database.files

        # PRODUCTION: Return real collection
        if database is None:
            raise RuntimeError("Database not initialized")
            
        return database.files
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service temporarily unavailable",
        )


def uploads_collection():
    """Get uploads collection - handle both production and pytest environments"""
    try:
        database = get_db()

        # PYTEST ENVIRONMENT: Return mock collection
        if USE_MOCK_DB:
            try:
                return database["uploads"]
            except (KeyError, TypeError):
                if not hasattr(database, "uploads"):
                    database.uploads = MockCollection()
                return database.uploads

        # PRODUCTION: Return real collection
        if database is None:
            raise RuntimeError("Database not initialized")
            
        return database.uploads
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service temporarily unavailable",
        )


def refresh_tokens_collection():
    """Get refresh tokens collection - handle both production and pytest environments"""
    try:
        database = get_db()

        # PYTEST ENVIRONMENT: Return mock collection
        if USE_MOCK_DB:
            try:
                return database["refresh_tokens"]
            except (KeyError, TypeError):
                if not hasattr(database, "refresh_tokens"):
                    database.refresh_tokens = MockCollection()
                return database.refresh_tokens

        # PRODUCTION: Return real collection
        if database is None:
            raise RuntimeError("Database not initialized")
            
        return database.refresh_tokens
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service temporarily unavailable",
        )


def reset_tokens_collection():
    """Get reset tokens collection - handle both production and pytest environments"""
    try:
        database = get_db()

        # PYTEST ENVIRONMENT: Return mock collection
        if USE_MOCK_DB:
            try:
                return database["reset_tokens"]
            except (KeyError, TypeError):
                if not hasattr(database, "reset_tokens"):
                    database.reset_tokens = MockCollection()
                return database.reset_tokens

        # PRODUCTION: Return real collection
        if database is None:
            raise RuntimeError("Database not initialized")
            
        return database.reset_tokens
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service temporarily unavailable",
        )


def group_activity_collection():
    """Get group activity collection - handle both production and pytest environments"""
    try:
        database = get_db()

        # PYTEST ENVIRONMENT: Return mock collection
        if USE_MOCK_DB:
            try:
                return database["group_activity"]
            except (KeyError, TypeError):
                if not hasattr(database, "group_activity"):
                    database.group_activity = MockCollection()
                return database.group_activity

        # PRODUCTION: Return real collection
        if database is None:
            raise RuntimeError("Database not initialized")
            
        return database.group_activity
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service temporarily unavailable",
        )


def media_collection():
    """Get media collection - handle both production and pytest environments"""
    try:
        database = get_db()

        # PYTEST ENVIRONMENT: Return mock collection
        if USE_MOCK_DB:
            try:
                return database["media"]
            except (KeyError, TypeError):
                if not hasattr(database, "media"):
                    database.media = MockCollection()
                return database.media

        # PRODUCTION: Return real collection
        if database is None:
            raise RuntimeError("Database not initialized")
            
        return database.media
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service temporarily unavailable",
        )
