import os
import logging
import asyncio
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

# Load MongoDB Atlas configuration from environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")

# Validate required environment variables
if not MONGODB_URI:
    raise ValueError("MONGODB_URI environment variable is required")

if not DATABASE_NAME:
    raise ValueError("DATABASE_NAME environment variable is required")

# Validate MongoDB URI format
if not MONGODB_URI.startswith("mongodb+srv://"):
    raise ValueError("MONGODB_URI must be a MongoDB Atlas URI starting with 'mongodb+srv://'")

# Print startup log confirming MongoDB configuration
print(f"[DB] MongoDB Atlas URI configured for database: {DATABASE_NAME}")
print(f"[DB] MONGODB_URI: {MONGODB_URI}")
print(f"[DB] DATABASE_NAME: {DATABASE_NAME}")
print(f"[DB] Connection timeout: 10000ms")

# Global database connection variables as specified
client = None
database = None

# Mock database for testing
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

# Initialize mock database if needed
if os.getenv("USE_MOCK_DB", "false").lower() == "true":
    database = MockDatabase()
    print("[DB] Using mock database for testing")

def get_database():
    """Get database instance - sync function as specified"""
    global database
    return database


# Collection shortcuts
def users_collection():
    """Get users collection"""
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.users


def chats_collection():
    """Get chats collection"""
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.chats


def messages_collection():
    """Get messages collection"""
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.messages


def files_collection():
    """Get files collection"""
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.files


def uploads_collection():
    """Get uploads collection"""
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.uploads


def refresh_tokens_collection():
    """Get refresh tokens collection"""
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.refresh_tokens


def reset_tokens_collection():
    """Get reset tokens collection"""
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.reset_tokens


def group_activity_collection():
    """Get group activity collection"""
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.group_activity


def media_collection():
    """Get media collection"""
    if database is None:
        raise RuntimeError("Database not initialized - ensure startup event has run")
    return database.media


# Backward compatibility aliases for tests
connect_db = lambda: None  # No-op since we use global client
get_db = get_database
