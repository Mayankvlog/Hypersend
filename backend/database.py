import os
import logging
import asyncio
import sys
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import HTTPException, status
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
env_paths = [Path(__file__).parent / ".env", Path(__file__).parent.parent / ".env"]
for env_path in env_paths:
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
        break

# Environment detection
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
IS_PRODUCTION = ENVIRONMENT == "production"
IS_TEST = ENVIRONMENT == "test" or "pytest" in sys.modules

# Load MongoDB Atlas configuration from environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")
MONGODB_ATLAS_ENABLED = os.getenv("MONGODB_ATLAS_ENABLED", "false").lower() == "true"

# Mock database configuration with production override
# CRITICAL: Production MUST use MongoDB Atlas, never mock database
if IS_PRODUCTION:
    USE_MOCK_DB = False  # Force disable mock in production
    print("[DB] PRODUCTION MODE: Mock database disabled, MongoDB Atlas required")
else:
    USE_MOCK_DB = os.getenv("USE_MOCK_DB", "false").lower() == "true"
    if IS_TEST:
        USE_MOCK_DB = True  # Force enable mock in test
        print("[DB] TEST MODE: Mock database enabled")

# CRITICAL: In production, ensure MongoDB Atlas is enabled and mock is disabled
if IS_PRODUCTION:
    if not MONGODB_ATLAS_ENABLED:
        raise RuntimeError("PRODUCTION ERROR: MONGODB_ATLAS_ENABLED must be true in production")
    if USE_MOCK_DB:
        raise RuntimeError("PRODUCTION ERROR: USE_MOCK_DB cannot be true in production")
    if not MONGODB_URI:
        raise RuntimeError("PRODUCTION ERROR: MONGODB_URI is required in production")
    if not DATABASE_NAME:
        raise RuntimeError("PRODUCTION ERROR: DATABASE_NAME is required in production")
    print("[DB] PRODUCTION: MongoDB Atlas configuration validated")

# Connection timeout
CONNECTION_TIMEOUT = int(os.getenv("CONNECTION_TIMEOUT", "10000"))  # 10 seconds default

# Validate configuration and log status
if IS_PRODUCTION:
    # Production: Must use MongoDB Atlas
    print("[DB] PRODUCTION: Using MongoDB Atlas (mock database disabled)")
    print(f"[DB] MONGODB_URI: {MONGODB_URI[:50]}...")
    print(f"[DB] DATABASE_NAME: {DATABASE_NAME}")
    print(f"[DB] Connection timeout: {CONNECTION_TIMEOUT}ms")
elif MONGODB_ATLAS_ENABLED and not USE_MOCK_DB:
    # Atlas enabled for non-production
    print("[DB] Using MongoDB Atlas")
    print(f"[DB] MONGODB_URI: {MONGODB_URI}")
    print(f"[DB] DATABASE_NAME: {DATABASE_NAME}")
    print(f"[DB] Connection timeout: {CONNECTION_TIMEOUT}ms")
elif USE_MOCK_DB and not MONGODB_ATLAS_ENABLED:
    # Mock database for testing
    print("[DB] Using mock database")
else:
    # No database available
    print("[DB] WARNING: No database available - Atlas disabled and mock disabled")

# Global database connection variables as specified
client = None
db = None

async def init_database():
    """Initialize MongoDB database connection with proper logging and error handling"""
    global client, db
    
    # Read environment variables
    mongodb_uri = os.getenv("MONGODB_URI")
    database_name = os.getenv("DATABASE_NAME")
    environment = os.getenv("ENVIRONMENT", "development").lower()
    
    # Log initialization start
    print(f"[DB] Initializing database connection...")
    print(f"[DB] Environment: {environment}")
    print(f"[DB] Database Name: {database_name}")
    
    if environment == "production":
        print("[DB] PRODUCTION MODE: MongoDB Atlas required")
        
        # Validate production requirements
        if not mongodb_uri:
            raise RuntimeError("PRODUCTION ERROR: MONGODB_URI is required in production")
        if not database_name:
            raise RuntimeError("PRODUCTION ERROR: DATABASE_NAME is required in production")
        
        try:
            # Create AsyncIOMotorClient
            print(f"[DB] Connecting to MongoDB Atlas...")
            client = AsyncIOMotorClient(
                mongodb_uri,
                uuidRepresentation="standard",
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
                socketTimeoutMS=10000
            )
            
            # Test connection
            await client.admin.command("ping")
            print("[DB] MongoDB Atlas connection test successful")
            
            # Assign database globally
            db = client[database_name]
            
            # Log success
            print(f"[DB] MongoDB Atlas initialized successfully")
            print(f"[DB] Database: {database_name}")
            print("[DB] PRODUCTION: MongoDB Atlas is active and ready")
            
        except Exception as e:
            print(f"[DB] ERROR: Failed to connect to MongoDB Atlas: {str(e)}")
            # In production, this is a critical failure
            raise RuntimeError(f"PRODUCTION CRITICAL: MongoDB Atlas connection failed: {str(e)}")
    
    else:
        # Non-production environment
        if USE_MOCK_DB:
            print("[DB] Non-production mode: Using mock database")
            # Mock database is already initialized above
            if database is None:
                database = mock_db
                print("[DB] Mock database assigned to global database variable")
        else:
            print("[DB] Non-production mode: No database initialization")
            print("[DB] Database will remain None - routes should handle this gracefully")

def get_database():
    """Get database instance - sync function as specified"""
    global db
    return db

# Mock database for testing - ONLY used when Atlas is disabled and USE_MOCK_DB=true
class MockDatabase:
    """Mock database for testing"""
    def __init__(self):
        self.users = MockCollection()
        self.chats = MockCollection()
        self.messages = MockCollection()
        self.files = MockCollection()
        self.uploads = MockCollection()
        self.refresh_tokens = MockCollection()
        self.reset_tokens = MockCollection()
        self.group_activity = MockCollection()
        self.media = MockCollection()

class MockCollection:
    """Mock collection for testing"""
    def __init__(self):
        self.data = {}
        self._id_counter = 1
    
    async def find_one(self, query, **kwargs):
        # Simple mock implementation
        if isinstance(query, dict):
            if "_id" in query:
                # Find by ID
                return self.data.get(query["_id"])
            elif "email" in query:
                # Find by email
                for value in self.data.values():
                    if isinstance(value, dict) and value.get("email") == query["email"]:
                        return value
        return None
    
    async def insert_one(self, document):
        # Generate mock ID
        document = dict(document)
        document["_id"] = f"mock_id_{self._id_counter}"
        self._id_counter += 1
        
        # Store by ID and also by email if available
        self.data[document["_id"]] = document
        if "email" in document:
            self.data[document["email"]] = document
        
        result = type('InsertResult', (), {'inserted_id': document["_id"]})()
        return result
    
    async def update_one(self, query, update, **kwargs):
        # Mock implementation
        result = type('UpdateResult', (), {'matched_count': 1, 'modified_count': 1})()
        return result
    
    async def delete_one(self, query, **kwargs):
        # Mock implementation
        result = type('DeleteResult', (), {'deleted_count': 1})()
        return result
    
    async def delete_many(self, query, **kwargs):
        # Mock implementation
        result = type('DeleteResult', (), {'deleted_count': 1})()
        return result
    
    async def find(self, query, **kwargs):
        # Mock cursor
        return MockCursor(list(self.data.values()))
    
    async def find_one_and_update(self, query, update, **kwargs):
        # Mock implementation
        return None
    
    async def find_one_and_delete(self, query, **kwargs):
        # Mock implementation
        return None

class MockCursor:
    """Mock cursor for testing"""
    def __init__(self, data):
        self.data = data
        self._index = 0
    
    async def to_list(self, length=None):
        return self.data[:length] if length else self.data
    
    def limit(self, count):
        return MockCursor(self.data[:count])
    
    def skip(self, count):
        return MockCursor(self.data[count:])
    
    def sort(self, key, direction=1):
        return self
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        if self._index >= len(self.data):
            raise StopAsyncIteration
        item = self.data[self._index]
        self._index += 1
        return item

# Initialize database based on configuration
# CRITICAL: Check USE_MOCK_DB first before creating any mock client
if USE_MOCK_DB and not IS_PRODUCTION:
    print("[DB] Initializing mock database for testing")
    mock_db = MockDatabase()
    # Create global client and database for compatibility
    client = None
    database = mock_db
    print("[DB] Mock database initialized")
else:
    # Production or Atlas mode: no mock database initialization
    mock_db = None
    client = None
    database = None
    if IS_PRODUCTION:
        print("[DB] PRODUCTION: No mock database initialized - will use MongoDB Atlas")
    elif MONGODB_ATLAS_ENABLED:
        print("[DB] MongoDB Atlas will be initialized in startup event")
    else:
        print("[DB] No database initialization - waiting for configuration")

def get_database():
    """Get database instance - sync function as specified"""
    global db
    return db


# Collection shortcuts
def users_collection():
    """Get users collection"""
    global db
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["users"]


def chats_collection():
    """Get chats collection"""
    global db
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["chats"]


def messages_collection():
    """Get messages collection"""
    global db
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["messages"]


def files_collection():
    """Get files collection"""
    global db
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["files"]


def uploads_collection():
    """Get uploads collection"""
    global db
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["uploads"]


def refresh_tokens_collection():
    """Get refresh tokens collection"""
    global db
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["refresh_tokens"]


def reset_tokens_collection():
    """Get reset tokens collection"""
    global db
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["reset_tokens"]


def group_activity_collection():
    """Get group activity collection"""
    global db
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["group_activity"]


def media_collection():
    """Get media collection"""
    global db
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["media"]


# Backward compatibility aliases for tests
connect_db = lambda: None  # No-op since we use global client
get_db = get_database
