"""
Mock Database for Testing
Provides mock implementations of database collections for testing without real MongoDB
"""

import asyncio
from typing import Dict, List, Optional, Any
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
import uuid

class MockMongoClient:
    """Mock MongoDB client for testing"""
    def __init__(self):
        self.databases = {}
    
    def __getitem__(self, name):
        """Get database by name"""
        if name not in self.databases:
            self.databases[name] = MockDatabase()
        return self.databases[name]
    
    def close(self):
        """Mock close method"""
        pass
    
    async def admin_command(self, command):
        """Mock admin command"""
        return {"ok": 1}

class MockDatabase:
    """Mock database for testing"""
    def __init__(self, client=None, name="test"):
        self.client = client
        self.name = name
        self.collections = {}
    
    def clear_all(self):
        """Clear all collections"""
        for collection in self.collections.values():
            collection.clear()
        print(f"[MOCK_DB] Cleared all collections")
    
    def __getitem__(self, name):
        """Support subscriptable access for collections"""
        if name == '__await__':
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '__await__'")
        if name not in self.collections:
            self.collections[name] = MockCollection(name)
        return self.collections[name]
    
    def __getattr__(self, name):
        """Create collections on demand (fallback)"""
        if name == '__await__':
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '__await__'")
        if name not in self.collections:
            self.collections[name] = MockCollection(name)
        return self.collections[name]

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
    
    def limit(self, count):
        """Mock limit method that limits the number of documents"""
        print(f"[MOCK_CURSOR] limit called with count={count}")
        self.docs = self.docs[:count]
        return self
    
    async def to_list(self, length=None):
        """Mock to_list method for MongoDB cursor compatibility"""
        print(f"[MOCK_CURSOR] to_list called with length={length}")
        if length is not None:
            return self.docs[:length]
        return self.docs
    
    def __aiter__(self):
        """Make cursor async iterable"""
        async def async_iter():
            for doc in self.docs:
                yield doc
        return async_iter()
    
    def __iter__(self):
        """Make cursor sync iterable too"""
        return iter(self.docs)

class MockCollection:
    """Mock collection for testing"""
    def __init__(self, name: str):
        self.name = name
        self.data: Dict[str, Dict] = {}
        self._id_counter = 1
    
    def _generate_id(self):
        return str(self._id_counter)
    
    def clear(self):
        """Clear all data from the collection"""
        self.data.clear()
        self._id_counter = 1
        print(f"[MOCK_DB] Cleared collection: {self.name}")
    
    async def insert_one(self, document: Dict) -> MagicMock:
        # Use provided _id or generate one
        if '_id' not in document:
            doc_id = self._generate_id()
            document['_id'] = doc_id
        else:
            doc_id = document['_id']
        
        self.data[doc_id] = document.copy()
        self._id_counter += 1
        print(f"[MOCK_DB] Inserted document with ID: {doc_id}")
        print(f"[MOCK_DB] Current data keys: {list(self.data.keys())}")
        
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
    
    async def delete_one(self, query: Dict) -> MagicMock:
        """Delete one document matching the query"""
        print(f"[MOCK_DB] delete_one called with query: {query}")
        
        doc_id_to_delete = None
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                doc_id_to_delete = doc_id
                break
        
        if doc_id_to_delete:
            del self.data[doc_id_to_delete]
            print(f"[MOCK_DB] Deleted document with ID: {doc_id_to_delete}")
            
            result = MagicMock()
            result.deleted_count = 1
            return result
        else:
            print(f"[MOCK_DB] No document found to delete")
            
            result = MagicMock()
            result.deleted_count = 0
            return result
    
    async def find(self, query: Dict = None, sort: List = None) -> MockCursor:
        """Mock find that returns a cursor-like object"""
        print(f"[MOCK_DB] find called with query={query}, sort={sort}")
        docs = []
        if not query:
            docs = [doc.copy() for doc in self.data.values()]
        else:
            docs = [doc.copy() for doc in self.data.values() if self._match_query(doc, query)]
        
        # Apply sorting if provided - handle the sort parameter correctly
        if sort:
            for sort_item in sort:
                if isinstance(sort_item, tuple) and len(sort_item) == 2:
                    field, direction = sort_item
                    docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))
                elif isinstance(sort_item, dict):
                    # Handle MongoDB sort format like {"field": 1}
                    for field, direction in sort_item.items():
                        docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))
        
        cursor = MockCursor(docs)
        print(f"[MOCK_DB] find returning MockCursor with {len(docs)} docs")
        return cursor
    
    async def update_one(self, query: Dict, update: Dict) -> MagicMock:
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                if '$set' in update:
                    doc.update(update['$set'])
                elif '$addToSet' in update:
                    for field, value in update['$addToSet'].items():
                        if isinstance(value, dict) and '$each' in value:
                            # Handle $addToSet with $each for adding multiple values
                            if field not in doc:
                                doc[field] = []
                            for item in value['$each']:
                                if item not in doc[field]:
                                    doc[field].append(item)
                        else:
                            # Handle simple $addToSet
                            if field not in doc:
                                doc[field] = []
                            if value not in doc[field]:
                                doc[field].append(value)
                self.data[doc_id] = doc.copy()
                result = MagicMock()
                result.matched_count = 1
                result.modified_count = 1
                return result
        result = MagicMock()
        result.matched_count = 0
        result.modified_count = 0
        return result
    
    async def update_many(self, query: Dict, update: Dict) -> MagicMock:
        """Mock update_many method"""
        matched_count = 0
        modified_count = 0
        
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                matched_count += 1
                if '$set' in update:
                    doc.update(update['$set'])
                    modified_count += 1
                elif '$addToSet' in update:
                    for field, value in update['$addToSet'].items():
                        if isinstance(value, dict) and '$each' in value:
                            # Handle $addToSet with $each for adding multiple values
                            if field not in doc:
                                doc[field] = []
                            for item in value['$each']:
                                if item not in doc[field]:
                                    doc[field].append(item)
                        else:
                            # Handle simple $addToSet
                            if field not in doc:
                                doc[field] = []
                            if value not in doc[field]:
                                doc[field].append(value)
                    modified_count += 1
                self.data[doc_id] = doc.copy()
        
        result = MagicMock()
        result.matched_count = matched_count
        result.modified_count = modified_count
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
    
    def _match_query(self, doc: Dict, query: Dict) -> bool:
        """Match document against query with basic operators"""
        if not query:
            return True
        
        for key, value in query.items():
            if key == '$and':
                if not all(self._match_query(doc, sub_query) for sub_query in value):
                    return False
            elif key == '$or':
                if not any(self._match_query(doc, sub_query) for sub_query in value):
                    return False
            elif key == '$in':
                doc_field = doc.get(key)
                # Check if any value in $in array matches the document field
                if isinstance(doc_field, list):
                    # If doc_field is an array, check if any element matches
                    if not any(item in value for item in doc_field):
                        return False
                else:
                    # If doc_field is a single value, check if it's in $in array
                    if doc_field not in value:
                        return False
            elif key == '$nin':
                if doc.get(key) in value:
                    return False
            elif key == '$ne':
                if doc.get(key) == value:
                    return False
            elif key == '$gt':
                if not (doc.get(key) and doc.get(key) > value):
                    return False
            elif key == '$gte':
                if not (doc.get(key) and doc.get(key) >= value):
                    return False
            elif key == '$lt':
                if not (doc.get(key) and doc.get(key) < value):
                    return False
            elif key == '$lte':
                if not (doc.get(key) and doc.get(key) <= value):
                    return False
            elif key == '$regex':
                import re
                pattern = value if isinstance(value, re.Pattern) else re.compile(value)
                if not (doc.get(key) and pattern.search(str(doc.get(key)))):
                    return False
            elif isinstance(value, dict):
                # Handle nested operators like $all
                for op, op_val in value.items():
                    if op == '$all':
                        if not all(item in doc.get(key, []) for item in op_val):
                            return False
                    elif op == '$exists':
                        if (key in doc) != op_val:
                            return False
            else:
                # Direct comparison with ObjectId support
                doc_val = doc.get(key)
                if doc_val != value:
                    # Handle string vs ObjectId comparison
                    if str(doc_val) != str(value):
                        return False
        return True

# Singleton instances for collections
_users_collection = None
_chats_collection = None
_messages_collection = None
_files_collection = None
_uploads_collection = None
_refresh_tokens_collection = None
_reset_tokens_collection = None
_media_collection = None
_group_activity_collection = None

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
    return MockDatabase()

def media_collection():
    """Get media collection following singleton pattern"""
    global _media_collection
    if _media_collection is None:
        _media_collection = MockCollection("media")
    return _media_collection

def group_activity_collection():
    """Get group activity collection following singleton pattern"""
    global _group_activity_collection
    if _group_activity_collection is None:
        _group_activity_collection = MockCollection("group_activity")
    return _group_activity_collection

# Helper function for tests to clear collections
def clear_test_collections():
    """Clear all mock collections for test isolation"""
    global _users_collection, _chats_collection, _messages_collection
    global _files_collection, _uploads_collection, _refresh_tokens_collection, _reset_tokens_collection
    global _media_collection, _group_activity_collection
    
    _users_collection = None
    _chats_collection = None
    _messages_collection = None
    _files_collection = None
    _uploads_collection = None
    _refresh_tokens_collection = None
    _reset_tokens_collection = None
    _media_collection = None
    _group_activity_collection = None
    print("[MOCK_DB] Cleared all collection references for test isolation")
