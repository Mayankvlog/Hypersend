"""
Mock Database for Testing
Provides mock implementations of database collections for testing without real MongoDB
"""

import asyncio
from typing import Dict, List, Optional, Any
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
import uuid

class MockCollection:
    """Mock collection for testing"""
    def __init__(self, name: str):
        self.name = name
        self.data: Dict[str, Dict] = {}
        self._id_counter = 1
    
    def _generate_id(self):
        return str(self._id_counter)
    
    async def insert_one(self, document: Dict) -> MagicMock:
        doc_id = self._generate_id()
        document['_id'] = doc_id
        self.data[doc_id] = document.copy()
        self._id_counter += 1
        
        result = MagicMock()
        result.inserted_id = doc_id
        return result
    
    async def find_one(self, query: Dict) -> Optional[Dict]:
        for doc in self.data.values():
            if self._match_query(doc, query):
                return doc.copy()
        return None
    
    async def find_one_and_update(self, query: Dict, update: Dict, **kwargs) -> Optional[Dict]:
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                # Apply update
                if '$set' in update:
                    doc.update(update['$set'])
                self.data[doc_id] = doc.copy()
                return doc.copy()
        return None
    
    async def find(self, query: Dict = None) -> List[Dict]:
        if not query:
            return [doc.copy() for doc in self.data.values()]
        
        return [doc.copy() for doc in self.data.values() if self._match_query(doc, query)]
    
    async def update_one(self, query: Dict, update: Dict) -> MagicMock:
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                if '$set' in update:
                    doc.update(update['$set'])
                self.data[doc_id] = doc.copy()
                
                result = MagicMock()
                result.modified_count = 1
                return result
        
        result = MagicMock()
        result.modified_count = 0
        return result
    
    async def delete_many(self, query: Dict) -> MagicMock:
        to_delete = []
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                to_delete.append(doc_id)
        
        for doc_id in to_delete:
            del self.data[doc_id]
        
        result = MagicMock()
        result.deleted_count = len(to_delete)
        return result
    
    async def count_documents(self, query: Dict = None) -> int:
        if not query:
            return len(self.data)
        
        count = 0
        for doc in self.data.values():
            if self._match_query(doc, query):
                count += 1
        return count
    
    def _match_query(self, doc: Dict, query: Dict) -> bool:
        """Simple query matching for basic cases"""
        if not query:
            return True
        
        for key, value in query.items():
            if key not in doc or doc[key] != value:
                return False
        return True

# Mock collection instances
_users_collection = None
_chats_collection = None
_messages_collection = None
_files_collection = None
_uploads_collection = None
_refresh_tokens_collection = None
_reset_tokens_collection = None

def users_collection():
    global _users_collection
    if _users_collection is None:
        _users_collection = MockCollection("users")
    return _users_collection

def chats_collection():
    global _chats_collection
    if _chats_collection is None:
        _chats_collection = MockCollection("chats")
    return _chats_collection

def messages_collection():
    global _messages_collection
    if _messages_collection is None:
        _messages_collection = MockCollection("messages")
    return _messages_collection

def files_collection():
    global _files_collection
    if _files_collection is None:
        _files_collection = MockCollection("files")
    return _files_collection

def uploads_collection():
    global _uploads_collection
    if _uploads_collection is None:
        _uploads_collection = MockCollection("uploads")
    return _uploads_collection

def refresh_tokens_collection():
    global _refresh_tokens_collection
    if _refresh_tokens_collection is None:
        _refresh_tokens_collection = MockCollection("refresh_tokens")
    return _refresh_tokens_collection

def reset_tokens_collection():
    global _reset_tokens_collection
    if _reset_tokens_collection is None:
        _reset_tokens_collection = MockCollection("reset_tokens")
    return _reset_tokens_collection

async def connect_db():
    """Mock database connection"""
    pass

async def close_db():
    """Mock database close"""
    pass

def get_db():
    """Mock database getter"""
    return None
