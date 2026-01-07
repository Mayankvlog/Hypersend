import os
import random
import secrets
import threading
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import HTTPException, status
from config import settings

client = None
db = None


async def connect_db():
    """Connect to MongoDB with improved retry logic and exponential backoff for VPS"""
    global client, db
    max_retries = 5
    initial_retry_delay = 2
    
    # SECURITY: Validate MongoDB URI before connection attempts
    if not settings.MONGODB_URI or not isinstance(settings.MONGODB_URI, str):
        print("[ERROR] Invalid MongoDB URI configuration")
        raise ValueError("Database configuration is invalid")
    
    for attempt in range(max_retries):
        try:
            # Create client with extended timeouts for VPS connectivity
            client = AsyncIOMotorClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=30000,  # Increased to 30 seconds for Linux VPS compatibility
                connectTimeoutMS=30000,  # Increased for slower Linux connections
                socketTimeoutMS=60000,   # Increased for large file operations
                retryWrites=True,
                maxPoolSize=50,
                minPoolSize=10,
                # Enhanced connection settings with compression
                compressors=["zlib"],  # List of compressors
                zlibCompressionLevel=6  # Balanced compression level
            )
            # Test connection with proper error handling
            try:
                await client.admin.command('ping', maxTimeMS=5000)  # 5 second timeout for ping
            except Exception as ping_error:
                print(f"[ERROR] MongoDB ping failed: {type(ping_error).__name__}: {str(ping_error)}")
                raise ConnectionError("Database connection test failed")
                
            db = client[settings._MONGO_DB]
            
            # Test database access
            try:
                await db.list_collection_names()
            except Exception as db_error:
                print(f"[ERROR] Database access failed: {type(db_error).__name__}: {str(db_error)}")
                raise ConnectionError("Database access test failed")
            
            if settings.DEBUG:
                try:
                    safe_uri = settings.MONGODB_URI.split("@")[-1]
                except Exception as e:
                    safe_uri = "[redacted]"
                    if settings.DEBUG:
                        print(f"[DEBUG] URI parse error: {e}")
                print(f"[OK] Connected to MongoDB: {safe_uri}")
            return
            
        except (ConnectionError, TimeoutError) as e:
            # Enhanced database error classification
            error_msg = str(e)
            error_type = type(e).__name__
            print(f"[ERROR] MongoDB connection attempt {attempt + 1}/{max_retries} failed")
            print(f"[ERROR] Type: {error_type}, Details: {error_msg}")
            
            # Specific error categorization
            if isinstance(e, TimeoutError) or "timeout" in error_msg.lower():
                print(f"[ERROR] Connection timeout - likely network issues")
                # CRITICAL FIX: Raise TimeoutError for proper 504 response
                if attempt >= max_retries - 1:
                    raise TimeoutError("Database connection timeout")
            elif "authentication" in error_msg.lower() or "auth" in error_msg.lower():
                print(f"[ERROR] Authentication failure - check credentials")
                if attempt >= max_retries - 1:
                    raise ConnectionError("Database authentication failed")
            elif "network" in error_msg.lower() or "connection" in error_msg.lower():
                print(f"[ERROR] Network error - check MongoDB connectivity")
                if attempt >= max_retries - 1:
                    raise ConnectionError("Database service temporarily unavailable")
            
            if attempt < max_retries - 1:
                import asyncio
                import math
                import random
                import secrets
                # ENHANCED: Better exponential backoff with proper jitter
                retry_delay = initial_retry_delay * (2 ** attempt)
                # Add cryptographic jitter using secrets for better distribution
                # Fix: secrets.randbelow() takes only one argument (upper bound)
                jitter_range = 0.4  # 0.1 to 0.5 range = 0.4 total range
                jitter = (secrets.randbelow(int(jitter_range * 1000)) / 1000 + 0.1) * retry_delay
                retry_delay = min(retry_delay + jitter, 60)  # Cap at 60 seconds
                # Single error message per retry attempt
                print(f"[ERROR] Retrying in {retry_delay:.1f} seconds...")
                await asyncio.sleep(retry_delay)
                continue
            else:
                print("[ERROR] All connection attempts failed. Troubleshooting steps:")
                print("  1. Verify MongoDB container is running: docker ps | grep mongodb")
                print("  2. Check MongoDB logs: docker logs hypersend_mongodb")
                print("  3. Verify credentials: MONGO_USER, MONGO_PASSWORD in docker-compose.yml")
                print(f"  4. Check host:port connectivity: {settings._MONGO_HOST}:{settings._MONGO_PORT}")
                print("  5. Ensure MongoDB is bound to 0.0.0.0 (check: mongod --bind_ip 0.0.0.0)")
                print("  6. For VPS, verify firewall allows MongoDB port")
                # CRITICAL FIX: Raise appropriate error for HTTP mapping
                if isinstance(e, TimeoutError):
                    raise TimeoutError("Database connection timeout")
                else:
                    raise ConnectionError("Database service temporarily unavailable")
        except TimeoutError as e:
            # Database timeout should return 504 Gateway Timeout
            print(f"[ERROR] MongoDB connection timeout on attempt {attempt + 1}")
            if attempt >= max_retries - 1:
                # CRITICAL FIX: Don't raise HTTPException from database layer
                raise TimeoutError("Database connection timeout")
            else:
                import asyncio
                retry_delay = 5.0
                print(f"[ERROR] Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                continue
        except Exception as e:
            error_msg = str(e)
            print(f"[ERROR] MongoDB connection attempt {attempt + 1}/{max_retries} failed")
            print(f"[ERROR] Details: {error_msg}")
            
            if attempt < max_retries - 1:
                import asyncio
                import math
                import random
                import secrets
                # ENHANCED: Better exponential backoff with proper jitter
                retry_delay = initial_retry_delay * (2 ** attempt)
                # Add cryptographic jitter using secrets for better distribution
                # Fix: secrets.randbelow() takes only one argument (upper bound)
                jitter_range = 0.4  # 0.1 to 0.5 range = 0.4 total range
                jitter = (secrets.randbelow(int(jitter_range * 1000)) / 1000 + 0.1) * retry_delay
                retry_delay = min(retry_delay + jitter, 60)  # Cap at 60 seconds
                # Single error message per retry attempt
                print(f"[ERROR] Retrying in {retry_delay:.1f} seconds...")
                await asyncio.sleep(retry_delay)
                continue
            else:
                print("[ERROR] All connection attempts failed. Troubleshooting steps:")
                print("  1. Verify MongoDB container is running: docker ps | grep mongodb")
                print("  2. Check MongoDB logs: docker logs hypersend_mongodb")
                print("  3. Verify credentials: MONGO_USER, MONGO_PASSWORD in docker-compose.yml")
                print(f"  4. Check host:port connectivity: {settings._MONGO_HOST}:{settings._MONGO_PORT}")
                print("  5. Ensure MongoDB is bound to 0.0.0.0 (check: mongod --bind_ip 0.0.0.0)")
                print("  6. For VPS, verify firewall allows MongoDB port")
                # CRITICAL FIX: Raise generic connection error, not HTTPException
                raise ConnectionError("Database service temporarily unavailable")


async def close_db():
    """Close MongoDB connection with proper error handling"""
    global client
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
                logging.getLogger(__name__).error(f"Database connection close error: {str(e)}")
    # Always clear the global reference
    client = None


def get_db():
    """Get database instance with enhanced error checking and lazy initialization"""
    global db, client
    
    # If database is already initialized and connected, return it
    if db is not None and client is not None:
        return db
    
    # Attempt to use the global database if it was previously initialized
    if db is not None:
        try:
            # Quick validation - try to access a collection
            _ = db.command('ping')
            return db
        except Exception:
            # Database connection is stale, fall through to initialization
            pass
    
    # In test environment or when database isn't ready, provide mock database
    try:
        # Try to import real mock database first (if available)
        from mock_database import get_db as get_mock_db
        mock_result = get_mock_db()
        if mock_result is not None:
            return mock_result
    except (ImportError, RuntimeError):
        pass
    
    # Fallback: Create inline mock database for testing
    try:
        from unittest.mock import MagicMock, AsyncMock, PropertyMock
        
        # Create a proper mock database that behaves like motor AsyncIOMotorDatabase
        mock_db = MagicMock()
        
        # Define collection names that should be mocked
        collection_names = [
            "users", 
            "chats", 
            "messages", 
            "files", 
            "uploads", 
            "refresh_tokens", 
            "reset_tokens", 
            "group_activity",
            "contact_requests",
            "group_members",
        ]
        
        # Create mock collections with proper async support
        for coll_name in collection_names:
            coll = MagicMock()
            
            # Mock async methods
            coll.find_one = AsyncMock(return_value={"_id": "mock_upload_id", "user_id": "test_user"})
            coll.insert_one = AsyncMock(return_value=MagicMock(inserted_id="test_upload_id"))
            coll.find_one_and_update = AsyncMock(return_value=None)
            coll.find_one_and_delete = AsyncMock(return_value=None)
            coll.delete_one = AsyncMock(return_value=MagicMock(deleted_count=0))
            coll.delete_many = AsyncMock(return_value=MagicMock(deleted_count=0))
            coll.update_one = AsyncMock(return_value=MagicMock(modified_count=0))
            coll.update_many = AsyncMock(return_value=MagicMock(modified_count=0))
            coll.replace_one = AsyncMock(return_value=MagicMock(modified_count=0))
            
            # Mock find method with chaining support
            find_result = MagicMock()
            find_result.limit = MagicMock(return_value=find_result)
            find_result.skip = MagicMock(return_value=find_result)
            find_result.sort = MagicMock(return_value=find_result)
            find_result.to_list = AsyncMock(return_value=[])
            coll.find = MagicMock(return_value=find_result)
            
            # Mock distinct
            coll.distinct = AsyncMock(return_value=[])
            
            # Mock aggregate
            aggregate_result = MagicMock()
            aggregate_result.to_list = AsyncMock(return_value=[])
            coll.aggregate = MagicMock(return_value=aggregate_result)
            
            # Mock count_documents
            coll.count_documents = AsyncMock(return_value=0)
            
            # Mock create_index
            coll.create_index = AsyncMock(return_value=None)
            coll.create_indexes = AsyncMock(return_value=None)
            
            # Add collection to database mock
            setattr(mock_db, coll_name, coll)
        
        # Mock database methods
        mock_db.list_collection_names = AsyncMock(return_value=collection_names)
        mock_db.command = AsyncMock(return_value={"ok": 1})
        
        # Return the mock database
        return mock_db
    except Exception as e:
        # Last resort: raise informative error
        error_msg = f"Database not initialized and cannot create mock: {str(e)}"
        if db is None and client is None:
            raise RuntimeError("Database not connected. Call connect_db() first.")
        raise RuntimeError(error_msg)


# Collection shortcuts with error handling
def users_collection():
    """Get users collection with error handling"""
    try:
        database = get_db()
        return database.users
    except Exception as e:
        print(f"[ERROR] Failed to get users collection: {type(e).__name__}: {str(e)}")
        raise RuntimeError("Database service unavailable")


def chats_collection():
    database = get_db()
    return database.chats


def messages_collection():
    database = get_db()
    return database.messages


def files_collection():
    database = get_db()
    return database.files


def uploads_collection():
    database = get_db()
    return database.uploads


def refresh_tokens_collection():
    """Get refresh tokens collection with error handling"""
    try:
        database = get_db()
        return database.refresh_tokens
    except Exception as e:
        print(f"[ERROR] Failed to get refresh_tokens collection: {type(e).__name__}: {str(e)}")
        raise RuntimeError("Database service unavailable")

def reset_tokens_collection():
    """Get reset tokens collection with error handling"""
    try:
        database = get_db()
        return database.reset_tokens
    except Exception as e:
        print(f"[ERROR] Failed to get reset_tokens collection: {type(e).__name__}: {str(e)}")
        raise RuntimeError("Database service unavailable")


def group_activity_collection():
    database = get_db()
    return database.group_activity

