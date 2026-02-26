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
if IS_PRODUCTION:
    USE_MOCK_DB = False  # Force disable mock in production
    print("[DB] PRODUCTION MODE: Mock database disabled, MongoDB Atlas required")
else:
    USE_MOCK_DB = os.getenv("USE_MOCK_DB", "false").lower() == "true"
    if IS_TEST:
        USE_MOCK_DB = True  # Force enable mock in test
        print("[DB] TEST MODE: Mock database enabled")

# Connection timeout
CONNECTION_TIMEOUT = int(os.getenv("CONNECTION_TIMEOUT", "10000"))  # 10 seconds default

# Validate configuration and log status
if MONGODB_ATLAS_ENABLED and not USE_MOCK_DB:
    # Atlas enabled - validate required variables
    if not MONGODB_URI:
        raise ValueError("MONGODB_URI environment variable is required when MONGODB_ATLAS_ENABLED=true")
    if not DATABASE_NAME:
        raise ValueError("DATABASE_NAME environment variable is required when MONGODB_ATLAS_ENABLED=true")
    # Validate MongoDB URI format
    if not MONGODB_URI.startswith("mongodb+srv://"):
        raise ValueError("MONGODB_URI must be a MongoDB Atlas URI starting with 'mongodb+srv://'")
    print(f"[DB] Using MongoDB Atlas")
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
database = None

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
if MONGODB_ATLAS_ENABLED:
    # Atlas enabled - database will be initialized in main.py startup event
    database = None  # Will be set by startup event
if USE_MOCK_DB and not MONGODB_ATLAS_ENABLED:
    print("[DB] Initializing mock database for testing")
    mock_db = MockDatabase()
    # Create global client and database for compatibility
    client = None
    database = mock_db
else:
    # Production mode: no mock database initialization
    mock_db = None
    client = None
    database = None
    if IS_PRODUCTION:
        print("[DB] PRODUCTION: No mock database initialized")

def get_database():
    """Get database instance - sync function as specified"""
    global database
    return database


# Collection shortcuts
def users_collection():
    """Get users collection"""
    global database
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.users


def chats_collection():
    """Get chats collection"""
    global database
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.chats


def messages_collection():
    """Get messages collection"""
    global database
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.messages


def files_collection():
    """Get files collection"""
    global database
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.files


def uploads_collection():
    """Get uploads collection"""
    global database
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.uploads


def refresh_tokens_collection():
    """Get refresh tokens collection"""
    global database
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.refresh_tokens


def reset_tokens_collection():
    """Get reset tokens collection"""
    global database
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.reset_tokens


def group_activity_collection():
    """Get group activity collection"""
    global database
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.group_activity


def media_collection():
    """Get media collection"""
    global database
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.media


# Backward compatibility aliases for tests
connect_db = lambda: None  # No-op since we use global client
get_db = get_database
