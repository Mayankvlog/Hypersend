import os
import logging
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import HTTPException, status
from unittest.mock import MagicMock

try:
    from .config import settings
except ImportError:
    from config import settings

# MockCollection for test compatibility
class MockCollection:
    """Mock collection for testing purposes"""
    def __init__(self):
        self.data = {}
    
    def __getitem__(self, key):
        return self.data[key]
    
    def __setitem__(self, key, value):
        self.data[key] = value
    
    def __contains__(self, key):
        return key in self.data
    
    def clear(self):
        """Clear all data from mock collection"""
        self.data.clear()
    
    async def find_one(self, query):
        return None
    
    async def insert_one(self, document):
        return type("InsertResult", (), {"inserted_id": "mock_id"})()
    
    async def update_one(self, query, update, upsert=False):
        return type("UpdateResult", (), {"matched_count": 1, "modified_count": 1})()
    
    async def delete_one(self, query):
        return type("DeleteResult", (), {"deleted_count": 1})()
    
    async def count_documents(self, query):
        return 0

# MockDatabase for test compatibility
class MockDatabase:
    """Mock database with all collection attributes for testing purposes"""
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

# Global database connection variables
client = None
db = None

async def connect_db():
    """Connect to MongoDB Atlas using MONGODB_URI environment variable only"""
    global client, db
    
    # Check if mock database is enabled for testing
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    
    # Also check if settings are mocked and USE_MOCK_DB is False in settings
    settings_mocked = hasattr(settings, 'USE_MOCK_DB') and not settings.USE_MOCK_DB
    
    if use_mock_db and not settings_mocked:
        print("[DB] Using mock database for testing")
        client = MagicMock()
        db = MockDatabase()
        return
    
    if client is not None:
        return  # Already connected
    
    # Validate MongoDB URI
    if not settings.MONGODB_URI:
        raise ValueError("MONGODB_URI environment variable is required")
    
    if not settings.MONGODB_URI.startswith("mongodb+srv://"):
        raise ValueError("MONGODB_URI must be a MongoDB Atlas URI starting with 'mongodb+srv://'")
    
    try:
        # Create AsyncIOMotorClient with Atlas-optimized settings
        client = AsyncIOMotorClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=30000,
            retryWrites=True,
            w="majority"
        )
        
        # Verify connection with ping
        await client.admin.command("ping", maxTimeMS=5000)
        
        # Get database instance
        db = client[settings.DATABASE_NAME]
        
        print(f"[DB] Connected to MongoDB Atlas: {settings.DATABASE_NAME}")
        
    except Exception as e:
        print(f"[DB] Connection failed: {str(e)}")
        raise ConnectionError(f"Failed to connect to MongoDB Atlas: {str(e)}")

async def close_db():
    """Close MongoDB connection"""
    global client, db
    if client:
        client.close()
        print("[DB] MongoDB connection closed")
    client = None
    db = None

def get_db():
    """Get database instance"""
    global db
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    
    if use_mock_db:
        if db is None:
            # Auto-initialize mock database
            db = MockDatabase()
            print("[DB] Mock database auto-initialized")
        return db
    
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service is currently unavailable. Please try again later."
        )
    return db


# Collection shortcuts
def users_collection():
    """Get users collection"""
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    database = get_db()
    if use_mock_db:
        return database.users  # Return MockDatabase.users
    return database.users

def chats_collection():
    """Get chats collection"""
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    database = get_db()
    if use_mock_db:
        return database.chats  # Return MockDatabase.chats
    return database.chats

def messages_collection():
    """Get messages collection"""
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    database = get_db()
    if use_mock_db:
        return database.messages  # Return MockDatabase.messages
    return database.messages

def files_collection():
    """Get files collection"""
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    database = get_db()
    if use_mock_db:
        return database.files  # Return MockDatabase.files
    return database.files

def uploads_collection():
    """Get uploads collection"""
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    database = get_db()
    if use_mock_db:
        return database.uploads  # Return MockDatabase.uploads
    return database.uploads

def refresh_tokens_collection():
    """Get refresh tokens collection"""
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    database = get_db()
    if use_mock_db:
        return database.refresh_tokens  # Return MockDatabase.refresh_tokens
    return database.refresh_tokens

def reset_tokens_collection():
    """Get reset tokens collection"""
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    database = get_db()
    if use_mock_db:
        return database.reset_tokens  # Return MockDatabase.reset_tokens
    return database.reset_tokens

def group_activity_collection():
    """Get group activity collection"""
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    database = get_db()
    if use_mock_db:
        return database.group_activity  # Return MockDatabase.group_activity
    return database.group_activity

def media_collection():
    """Get media collection"""
    use_mock_db = os.getenv('USE_MOCK_DB', 'false').lower() == 'true'
    database = get_db()
    if use_mock_db:
        return database.media  # Return MockDatabase.media
    return database.media
