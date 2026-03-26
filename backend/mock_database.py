"""
Mock Database for Testing
Provides mock implementations of database collections for testing without real MongoDB
"""

import asyncio
from typing import Dict, List, Optional, Any
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
import uuid

class MockDatabase:
    """Mock database for testing"""
    def __init__(self):
        self.collections = {}
    
    def __getattr__(self, name):
        """Create collections on demand"""
        if name not in self.collections:
            self.collections[name] = MockCollection(name)
        return self.collections[name]

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
    
    async def find_one(self, query: Dict, projection: Dict = None, sort: List = None) -> Optional[Dict]:
        """Enhanced find_one with debugging"""
        print(f"[MOCK_DB] find_one called with query: {query}")
        print(f"[MOCK_DB] Current data: {list(self.data.keys())}")
        
        matching_docs = []
        for doc_id, doc in self.data.items():
            print(f"[MOCK_DB] Checking doc {doc_id}: {doc}")
            if self._match_query(doc, query):
                print(f"[MOCK_DB] Found matching document: {doc_id}")
                matching_docs.append(doc.copy())
        
        if not matching_docs:
            print(f"[MOCK_DB] No matching document found")
            return None
        
        # Apply projection if provided
        if projection:
            for doc in matching_docs:
                projected_doc = {}
                for field, include in projection.items():
                    if include == 1:
                        projected_doc[field] = doc.get(field)
                matching_docs = [projected_doc]
        
        # Apply sorting if provided
        if sort:
            for field, direction in sort:
                matching_docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))
        
        return matching_docs[0] if matching_docs else None
    
    async def find_one_and_update(self, query: Dict, update: Dict, **kwargs) -> Optional[Dict]:
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                # Apply update
                if '$set' in update:
                    doc.update(update['$set'])
                self.data[doc_id] = doc.copy()
                return doc.copy()
        return None
    
    async def find(self, query: Dict = None, sort: List = None) -> 'MockCursor':
        """Mock find that returns a cursor-like object"""
        docs = []
        if not query:
            docs = [doc.copy() for doc in self.data.values()]
        else:
            docs = [doc.copy() for doc in self.data.values() if self._match_query(doc, query)]
        
        # Apply sorting if provided
        if sort:
            for field, direction in sort:
                docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))
        
        return MockCursor(docs)

class MockCursor:
    """Mock cursor for async iteration"""
    def __init__(self, docs):
        self.docs = docs
        self._sort_applied = False
        self._sort_field = None
        self._sort_direction = None
    
    def sort(self, field, direction=1):
        """Mock sort method that actually sorts the documents"""
        print(f"[MOCK_CURSOR] sort called with field={field}, direction={direction}")
        self._sort_applied = True
        self._sort_field = field
        self._sort_direction = direction
        
        # Apply the sorting
        if field and direction is not None:
            self.docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))
        
        return self
    
    def __aiter__(self):
        """Make cursor async iterable"""
        async def async_iter():
            for doc in self.docs:
                yield doc
        return async_iter()

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
    
    async def find_one(self, query: Dict, projection: Dict = None, sort: List = None) -> Optional[Dict]:
        """Enhanced find_one with debugging"""
        print(f"[MOCK_DB] find_one called with query: {query}")
        print(f"[MOCK_DB] Current data: {list(self.data.keys())}")
        
        matching_docs = []
        for doc_id, doc in self.data.items():
            print(f"[MOCK_DB] Checking doc {doc_id}: {doc}")
            if self._match_query(doc, query):
                print(f"[MOCK_DB] Found matching document: {doc_id}")
                matching_docs.append(doc.copy())
        
        if not matching_docs:
            print(f"[MOCK_DB] No matching document found")
            return None
        
        # Apply projection if provided
        if projection:
            for doc in matching_docs:
                projected_doc = {}
                for field, include in projection.items():
                    if include == 1:
                        projected_doc[field] = doc.get(field)
                matching_docs = [projected_doc]
        
        # Apply sorting if provided
        if sort:
            for field, direction in sort:
                matching_docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))
        
        return matching_docs[0] if matching_docs else None
    
    async def find_one_and_update(self, query: Dict, update: Dict, **kwargs) -> Optional[Dict]:
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                # Apply update
                if '$set' in update:
                    doc.update(update['$set'])
                self.data[doc_id] = doc.copy()
                return doc.copy()
        return None
    
    async def find(self, query: Dict = None, sort: List = None) -> 'MockCursor':
        """Mock find that returns a cursor-like object"""
        docs = []
        if not query:
            docs = [doc.copy() for doc in self.data.values()]
        else:
            docs = [doc.copy() for doc in self.data.values() if self._match_query(doc, query)]
        
        # Apply sorting if provided
        if sort:
            for field, direction in sort:
                docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))
        
        return MockCursor(docs)
    
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
        """Enhanced query matching for ObjectId and string queries"""
        if not query:
            return True
        
        for key, value in query.items():
            if key not in doc:
                return False
            
            # Handle ObjectId queries - if key is "_id", compare as string
            if key == "_id":
                if str(doc.get("_id", "")) != str(value):
                    return False
            # For all other keys, do exact comparison
            elif doc[key] != value:
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
    """Get or create users collection instance"""
    global _users_collection
    if _users_collection is None:
        _users_collection = MockCollection("users")
    return _users_collection

def chats_collection():
    """Get or create chats collection instance"""
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
    return MockDatabase()
