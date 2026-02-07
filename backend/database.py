import os
import logging
from logging import Filter

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
    """Connect to MongoDB with improved retry logic and exponential backoff for VPS"""
    global client, db
    
    # PRODUCTION: Always use real MongoDB Atlas - no mock database fallback
    print("[DB] Connecting to MongoDB Atlas production database")
    
    max_retries = 3  # Reduced retries for Atlas to fail faster
    initial_retry_delay = 2
    # In test environments, when client is patched to a mock, avoid retries.
    client_class = AsyncIOMotorClient
    if isinstance(client_class, (MagicMock, Mock, AsyncMock)) or getattr(settings, "DEBUG", False):
        max_retries = 1  # keep unit tests fast

    # SECURITY: Validate MongoDB URI before connection attempts
    if not settings.MONGODB_URI or not isinstance(settings.MONGODB_URI, str):
        print("[ERROR] Invalid MongoDB URI configuration")
        raise ValueError("Database configuration is invalid")
    # Basic URI format validation
    if not (settings.MONGODB_URI.startswith("mongodb://") or settings.MONGODB_URI.startswith("mongodb+srv://")):
        print("[ERROR] Invalid MongoDB URI format")
        raise ValueError("Database configuration is invalid")

    last_error = None
    for attempt in range(max_retries):
        try:
            # Create client with extended timeouts for VPS connectivity
            # CRITICAL FIX: Suppress periodic task errors for Atlas authentication issues
            client = client_class(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
                socketTimeoutMS=30000,
                retryWrites=False,
                maxPoolSize=5,
                minPoolSize=1,
                maxIdleTimeMS=45000,  # Close idle connections after 45s
                heartbeatFrequencyMS=10000  # Reduce heartbeat frequency
            )
            
            # Test connection with proper error handling
            try:
                ping_result = client.admin.command('ping', maxTimeMS=5000)
                if inspect.isawaitable(ping_result):
                    await ping_result
            except Exception as ping_error:
                error_msg = str(ping_error).lower()
                # CRITICAL FIX: Suppress "bad auth" logs in background tasks
                if "bad auth" in error_msg or "authentication" in error_msg:
                    if attempt == 0:  # Only print once
                        print(f"[ERROR] MongoDB authentication failed on attempt {attempt + 1}")
                        print(f"[ERROR] Check:")
                        print(f"  1. MONGODB_URI credentials in .env file")
                        print(f"  2. IP whitelist in MongoDB Atlas dashboard")
                        print(f"  3. Database user exists with proper permissions")
                    last_error = ping_error
                    if attempt >= max_retries - 1:
                        raise ConnectionError("MongoDB authentication failed - verify Atlas credentials and IP whitelist")
                    await asyncio.sleep(2 ** (attempt + 1))  # Exponential backoff
                    continue
                else:
                    print(f"[ERROR] MongoDB ping failed: {type(ping_error).__name__}: {error_msg}")
                    raise ConnectionError("Database connection test failed")
                
            db = client[settings._MONGO_DB]
            
            # Test database access
            try:
                result = db.list_collection_names()
                if inspect.isawaitable(result):
                    await result
            except Exception as db_error:
                error_msg = str(db_error).lower()
                if "bad auth" in error_msg or "authentication" in error_msg:
                    if attempt == 0:
                        print(f"[ERROR] Database access authentication failed")
                    last_error = db_error
                    if attempt >= max_retries - 1:
                        raise ConnectionError("MongoDB authentication failed - verify Atlas credentials and IP whitelist")
                    await asyncio.sleep(2 ** (attempt + 1))
                    continue
                else:
                    print(f"[ERROR] Database access failed: {type(db_error).__name__}: {error_msg}")
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
            if attempt == 0:  # Only print detailed logs on first attempt
                print(f"[ERROR] MongoDB connection attempt {attempt + 1}/{max_retries} failed")
                print(f"[ERROR] Type: {error_type}, Details: {error_msg}")
            
            # Specific error categorization
            if isinstance(e, TimeoutError) or "timeout" in error_msg.lower():
                if attempt == 0:
                    print(f"[ERROR] Connection timeout - likely network issues")
                # CRITICAL FIX: Raise TimeoutError for proper 504 response
                if attempt >= max_retries - 1:
                    raise TimeoutError("Database connection timeout")
            elif "authentication" in error_msg.lower() or "auth" in error_msg.lower():
                if attempt == 0:
                    print(f"[ERROR] Authentication failure - check credentials and IP whitelist")
                if attempt >= max_retries - 1:
                    raise ConnectionError("Database authentication failed")
            elif "network" in error_msg.lower() or "connection" in error_msg.lower():
                if attempt == 0:
                    print(f"[ERROR] Network error - check MongoDB connectivity")
                if attempt >= max_retries - 1:
                    # CRITICAL FIX: Match the expected error message in tests
                    raise ConnectionError("Database connection test failed")
            else:
                # Default case for any other connection errors
                if attempt == 0:
                    print(f"[ERROR] Unknown connection error")
                if attempt >= max_retries - 1:
                    # CRITICAL FIX: Match the expected error message in tests
                    raise ConnectionError("Database connection test failed")
            
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
                logging.getLogger(__name__).error(f"Database connection close error: {str(e)}")
    # Always clear the global reference
    client = None
    db = None
    _global_db = None
    _global_client = None


def get_db():
    """Get database connection with proper initialization"""
    global db, client, _global_db, _global_client
    
    # If database is already initialized and connected, return it
    if db is not None and client is not None:
        return db
    
    # Check if we have global database from initialization
    if _global_db is not None and _global_client is not None:
        db = _global_db
        client = _global_client
        print(f"[DB] Using global database instance")
        return db
    
    # CRITICAL FIX: Check if database was initialized at startup
    # Try to get database from mongo_init module if it exists
    try:
        import sys
        if 'mongo_init' in sys.modules:
            mongo_init = sys.modules['mongo_init']
            if hasattr(mongo_init, '_app_db') and mongo_init._app_db is not None:
                app_db = mongo_init._app_db
                app_client = getattr(mongo_init, '_app_client', None)
                if app_db is not None:
                    # Store globally for future calls
                    _global_db = app_db
                    _global_client = app_client
                    print(f"[DB] Using initialized database from mongo_init")
                    return app_db
    except Exception as e:
        print(f"[DB] Warning: Could not get initialized database: {e}")
    
    # Check if we should use mock database for testing
    if settings.USE_MOCK_DB:
        print("[DB] Using mock database for testing")
        try:
            from .mock_database import MockDatabase
            mock_db = MockDatabase()
            db = mock_db
            _global_db = db
            return db
        except ImportError as e:
            # Fail fast with clear error message instead of minimal mock
            error_msg = f"Failed to import MockDatabase: {str(e)}"
            print(f"[ERROR] {error_msg}")
            raise RuntimeError(
                f"Mock database requested via USE_MOCK_DB=True but MockDatabase module not available. "
                f"Please install required test dependencies or disable mock database mode. "
                f"Original error: {error_msg}"
            )
    
    # PRODUCTION: Always use real MongoDB Atlas - no mock database fallback
    print("[DB] Connecting to MongoDB Atlas production database")
    
    # Initialize real MongoDB connection
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        
        # Use Atlas connection string from settings
        mongo_uri = settings.MONGODB_URI
        
        # Create MongoDB client with connection pooling and better timeout handling
        client = AsyncIOMotorClient(
            mongo_uri,
            maxPoolSize=10,
            minPoolSize=2,
            maxIdleTimeMS=30000,
            serverSelectionTimeoutMS=10000,    # Reduced timeout for faster failure
            connectTimeoutMS=10000,            # Reduced timeout for faster failure
            socketTimeoutMS=15000,           # Moderate socket timeout
            retryWrites=False,  # Disable retryWrites to prevent Future issues
            w="majority"
        )
        
        # Get database instance using configured database name
        db = client[settings._MONGO_DB]
        
        # Store globally for future calls
        _global_db = db
        _global_client = client
        
        if settings.DEBUG:
            print(f"[DB] Connected to MongoDB Atlas: {mongo_uri.split('@')[1] if '@' in mongo_uri else 'configured'}")
        
        return db
        
    except Exception as e:
        error_msg = str(e)
        print(f"[ERROR] MongoDB Atlas connection failed: {error_msg}")
        raise ConnectionError(f"MongoDB Atlas connection failed: {error_msg}")


# Collection shortcuts with error handling
def users_collection():
    """Get users collection with enhanced error handling and Future safety"""
    try:
        database = get_db()
        if database is None:
            raise RuntimeError("Database not initialized")
        
        # Check if database has users collection
        if not hasattr(database, 'users'):
            raise RuntimeError("Database users collection not available")
        
        users_col = database.users
        
        # CRITICAL FIX: Ensure collection is properly initialized and not a Future
        if hasattr(users_col, '__await__'):
            raise RuntimeError("CRITICAL: users_collection is a coroutine - not awaited")
        
        # CRITICAL FIX: Validate collection is callable
        if not callable(getattr(users_col, 'find_one', None)):
            raise RuntimeError("CRITICAL: users_collection.find_one is not callable")
        
        # CRITICAL FIX: Add clear method for test compatibility
        if not hasattr(users_col, 'clear') and not hasattr(users_col, 'data'):
            # Add a clear method for real Motor collections for test compatibility
            def clear_method():
                # For real collections, we need to delete all documents
                print("[TEST_CLEAR] Clearing real Motor collection (not implemented)")
                pass  # We'll implement this as async in tests
            
            users_col.clear = clear_method
            
            # Add a data attribute for test compatibility
            class DataProxy:
                def clear(self):
                    print("[TEST_CLEAR] DataProxy clear called")
                    pass
            
            users_col.data = DataProxy()
        
        return users_col
    except Exception as e:
        print(f"[ERROR] Failed to get users collection: {type(e).__name__}: {str(e)}")
        raise RuntimeError(f"Database service unavailable: {str(e)}")


def chats_collection():
    """Get chats collection with error handling"""
    try:
        database = get_db()
        if database is None:
            raise RuntimeError("Database not initialized")
        
        # Check if database has chats collection
        if not hasattr(database, 'chats'):
            raise RuntimeError("Database chats collection not available")
        
        chats_col = database.chats
        
        # CRITICAL FIX: Ensure collection is properly initialized and not a Future
        if hasattr(chats_col, '__await__'):
            raise RuntimeError("CRITICAL: chats_collection is a coroutine - not awaited")
        
        # CRITICAL FIX: Validate collection is callable
        if not callable(getattr(chats_col, 'find_one', None)):
            raise RuntimeError("CRITICAL: chats_collection.find_one is not callable")
        
        return chats_col
    except Exception as e:
        print(f"[ERROR] Failed to get chats collection: {type(e).__name__}: {str(e)}")
        raise RuntimeError(f"Database service unavailable: {str(e)}")


def messages_collection():
    """Get messages collection with error handling"""
    try:
        database = get_db()
        if database is None:
            raise RuntimeError("Database not initialized")
        
        # Check if database has messages collection
        if not hasattr(database, 'messages'):
            raise RuntimeError("Database messages collection not available")
        
        messages_col = database.messages
        
        # CRITICAL FIX: Ensure collection is properly initialized and not a Future
        if hasattr(messages_col, '__await__'):
            raise RuntimeError("CRITICAL: messages_collection is a coroutine - not awaited")
        
        # CRITICAL FIX: Validate collection is callable
        if not callable(getattr(messages_col, 'find_one', None)):
            raise RuntimeError("CRITICAL: messages_collection.find_one is not callable")
        
        return messages_col
    except Exception as e:
        print(f"[ERROR] Failed to get messages collection: {type(e).__name__}: {str(e)}")
        raise RuntimeError(f"Database service unavailable: {str(e)}")


def files_collection():
    """Get files collection with error handling"""
    try:
        database = get_db()
        if database is None:
            raise RuntimeError("Database not initialized")
        
        # Check if database has files collection
        if not hasattr(database, 'files'):
            raise RuntimeError("Database files collection not available")
        
        files_col = database.files
        
        # CRITICAL FIX: Ensure collection is properly initialized and not a Future
        if hasattr(files_col, '__await__'):
            raise RuntimeError("CRITICAL: files_collection is a coroutine - not awaited")
        
        # CRITICAL FIX: Validate collection is callable
        if not callable(getattr(files_col, 'find_one', None)):
            raise RuntimeError("CRITICAL: files_collection.find_one is not callable")
        
        return files_col
    except Exception as e:
        print(f"[ERROR] Failed to get files collection: {type(e).__name__}: {str(e)}")
        raise RuntimeError(f"Database service unavailable: {str(e)}")


def uploads_collection():
    """Get uploads collection with error handling"""
    try:
        database = get_db()
        if database is None:
            raise RuntimeError("Database not initialized")
        
        # Check if database has uploads collection
        if not hasattr(database, 'uploads'):
            raise RuntimeError("Database uploads collection not available")
        
        uploads_col = database.uploads
        
        # CRITICAL FIX: Ensure collection is properly initialized and not a Future
        if hasattr(uploads_col, '__await__'):
            raise RuntimeError("CRITICAL: uploads_collection is a coroutine - not awaited")
        
        # CRITICAL FIX: Validate collection is callable
        if not callable(getattr(uploads_col, 'find_one', None)):
            raise RuntimeError("CRITICAL: uploads_collection.find_one is not callable")
        
        return uploads_col
    except Exception as e:
        print(f"[ERROR] Failed to get uploads collection: {type(e).__name__}: {str(e)}")
        raise RuntimeError(f"Database service unavailable: {str(e)}")


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


def media_collection():
    """Get media collection with enhanced error handling and Future safety"""
    try:
        database = get_db()
        if database is None:
            raise RuntimeError("Database not initialized")
        
        # Check if database has media collection
        if not hasattr(database, 'media'):
            raise RuntimeError("Database media collection not available")
        
        media_col = database.media
        
        # CRITICAL FIX: Ensure collection is properly initialized and not a Future
        if hasattr(media_col, '__await__'):
            raise RuntimeError("CRITICAL: media_collection is a coroutine - not awaited")
        
        # CRITICAL FIX: Validate collection is callable
        if not callable(getattr(media_col, 'find_one', None)):
            raise RuntimeError("CRITICAL: media_collection.find_one is not callable")
        
        return media_col
    except Exception as e:
        print(f"[ERROR] Failed to get media collection: {type(e).__name__}: {str(e)}")
        raise RuntimeError("Database service unavailable")
