#!/usr/bin/env python3
"""
Mock Database for Testing
Provides in-memory database functionality for tests
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock

class MockCollection:
    """Mock MongoDB collection"""
    
    def __init__(self, name: str):
        self.name = name
        self._data: Dict[str, Dict] = {}
        self._counter = 1
    
    async def find_one(self, query: Dict) -> Optional[Dict]:
        """Find one document"""
        for doc_id, doc in self._data.items():
            if self._matches_query(doc, query):
                return doc.copy()
        return None
    
    async def insert_one(self, document: Dict) -> MagicMock:
        """Insert one document"""
        doc_id = str(self._counter)
        self._counter += 1
        document["_id"] = doc_id
        document["created_at"] = datetime.now(timezone.utc)
        self._data[doc_id] = document.copy()
        
        result = MagicMock()
        result.inserted_id = doc_id
        return result
    
    async def update_one(self, query: Dict, update: Dict) -> MagicMock:
        """Update one document"""
        for doc_id, doc in self._data.items():
            if self._matches_query(doc, query):
                if "$set" in update:
                    doc.update(update["$set"])
                if "$unset" in update:
                    for key in update["$unset"]:
                        doc.pop(key, None)
                doc["updated_at"] = datetime.now(timezone.utc)
                
                result = MagicMock()
                result.modified_count = 1
                return result
        
        result = MagicMock()
        result.modified_count = 0
        return result
    
    async def find(self, query: Dict = None) -> MagicMock:
        """Find documents"""
        if query is None:
            query = {}
        
        results = []
        for doc in self._data.values():
            if self._matches_query(doc, query):
                results.append(doc.copy())
        
        cursor = MagicMock()
        cursor.to_list = AsyncMock(return_value=results)
        return cursor
    
    async def count_documents(self, query: Dict = None) -> int:
        """Count documents"""
        if query is None:
            query = {}
        
        count = 0
        for doc in self._data.values():
            if self._matches_query(doc, query):
                count += 1
        return count
    
    async def delete_many(self, query: Dict) -> MagicMock:
        """Delete multiple documents"""
        deleted_count = 0
        docs_to_delete = []
        for doc_id, doc in self._data.items():
            if self._matches_query(doc, query):
                docs_to_delete.append(doc_id)
                deleted_count += 1
        
        for doc_id in docs_to_delete:
            del self._data[doc_id]
        
        result = MagicMock()
        result.deleted_count = deleted_count
        return result
    
    async def create_index(self, index_spec: Dict, **kwargs) -> None:
        """Create index (mock)"""
        pass
    
    async def create_indexes(self, indexes: List) -> None:
        """Create indexes (mock)"""
        pass
    
    def _matches_query(self, doc: Dict, query: Dict) -> bool:
        """Simple query matching"""
        if not query:
            return True
        
        for key, value in query.items():
            if key not in doc or doc[key] != value:
                return False
        return True

class MockDatabase:
    """Mock MongoDB database"""
    
    def __init__(self):
        self.users = MockCollection("users")
        self.chats = MockCollection("chats")
        self.messages = MockCollection("messages")
        self.files = MockCollection("files")
        self.uploads = MockCollection("uploads")
        self.refresh_tokens = MockCollection("refresh_tokens")
        self.reset_tokens = MockCollection("reset_tokens")
        self.group_activity = MockCollection("group_activity")
        self.contact_requests = MockCollection("contact_requests")
        self.group_members = MockCollection("group_members")
    
    async def command(self, command: str) -> Dict:
        """Mock database command"""
        return {"ok": 1}
    
    async def list_collection_names(self) -> List[str]:
        """List collection names"""
        return [
            "users", "chats", "messages", "files", "uploads",
            "refresh_tokens", "reset_tokens", "group_activity",
            "contact_requests", "group_members"
        ]

# Global mock database instance
_mock_db = None

async def connect_db():
    """Connect to mock database"""
    global _mock_db
    _mock_db = MockDatabase()
    return _mock_db

async def close_db():
    """Close mock database connection"""
    global _mock_db
    _mock_db = None

def get_db():
    """Get mock database instance"""
    global _mock_db
    if _mock_db is None:
        _mock_db = MockDatabase()
    return _mock_db

# Collection shortcuts
def users_collection():
    """Get users collection"""
    return get_db().users

def chats_collection():
    """Get chats collection"""
    return get_db().chats

def messages_collection():
    """Get messages collection"""
    return get_db().messages

def files_collection():
    """Get files collection"""
    return get_db().files

def uploads_collection():
    """Get uploads collection"""
    return get_db().uploads

def refresh_tokens_collection():
    """Get refresh tokens collection"""
    return get_db().refresh_tokens

def reset_tokens_collection():
    """Get reset tokens collection"""
    return get_db().reset_tokens

def group_activity_collection():
    """Get group activity collection"""
    return get_db().group_activity

def contact_requests_collection():
    """Get contact requests collection"""
    return get_db().contact_requests

def group_members_collection():
    """Get group members collection"""
    return get_db().group_members

async def ensure_mongodb_ready():
    """Mock MongoDB readiness check"""
    return True
