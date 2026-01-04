# Simple mock for testing without MongoDB
class MockCollection:
    def __init__(self, name):
        self.name = name
        self.data = {}
    
    async def find_one(self, query):
        """MongoDB compatible find_one"""
        if not hasattr(self, '_stored_data'):
            # Fallback to original test data
            if query.get("_id") == "test_user":
                return {"_id": "test_user", "name": "Test User", "email": "test@zaply.in.net"}
            return None
        
        for doc in self._stored_data:
            if self._query_matches(doc, query):
                return doc.copy()
        return None
    
    async def insert_one(self, data):
        """MongoDB compatible insert_one"""
        if not hasattr(self, '_counter'):
            self._counter = 1
        if '_id' not in data:
            data['_id'] = str(self._counter)
            self._counter += 1
        # Store in internal data structure for find operations
        if not hasattr(self, '_stored_data'):
            self._stored_data = []
        # Create a deep copy to avoid mutating input data
        import copy
        self._stored_data.append(copy.deepcopy(data))
        
        # Return MongoDB-style result
        class InsertOneResult:
            def __init__(self, inserted_id):
                self.inserted_id = inserted_id
        
        return InsertOneResult(data['_id'])
    
    async def update_one(self, query, update):
        """MongoDB compatible update_one"""
        if not hasattr(self, '_stored_data') or not self._stored_data:
            class UpdateResult:
                def __init__(self):
                    self.matched_count = 0
                    self.modified_count = 0
                    self.upserted_id = None
            return UpdateResult()
        
        # Simple mock implementation - in reality this would handle $set, $push, etc.
        matched = 0
        modified = 0
        
        # For simplicity, just mark as modified if query matches
        for doc in self._stored_data:
            if self._query_matches(doc, query):
                matched += 1
                modified += 1
                # Apply simple updates (in real implementation would parse MongoDB operators)
                if isinstance(update, dict) and '$set' in update:
                    doc.update(update['$set'])
                elif isinstance(update, dict):
                    # Apply all top-level keys except operators
                    for key, value in update.items():
                        if not key.startswith('$'):
                            doc[key] = value
        
        class UpdateResult:
            def __init__(self, matched_count, modified_count):
                self.matched_count = matched_count
                self.modified_count = modified_count
                self.upserted_id = None
        
        return UpdateResult(matched, modified)
    
    async def delete_one(self, query):
        """MongoDB compatible delete_one - deletes first matching document"""
        if not hasattr(self, '_stored_data') or not self._stored_data:
            class DeleteResult:
                def __init__(self):
                    self.deleted_count = 0
            return DeleteResult()
        
        deleted_count = 0
        for i, doc in enumerate(self._stored_data):
            if self._query_matches(doc, query):
                self._stored_data.pop(i)
                deleted_count = 1
                break  # Only delete first matching document
        
        class DeleteResult:
            def __init__(self, deleted_count):
                self.deleted_count = deleted_count
        
        return DeleteResult(deleted_count)
    
    def _query_matches(self, doc, query):
        """Simple query matching for mock"""
        if not query or not isinstance(query, dict):
            return True
        
        for key, value in query.items():
            if key.startswith('$'):
                continue  # Skip operators for simplicity
            if doc.get(key) != value:
                return False
        return True
    
    def find(self, query=None, projection=None):
        """MongoDB compatible find - returns cursor immediately like Motor"""
        data = []
        if hasattr(self, '_stored_data'):
            for doc in self._stored_data:
                if self._query_matches(doc, query):
                    # Apply projection (MongoDB-compatible)
                    if projection:
                        projected_doc = {}
                        for field in projection:
                            if field.startswith('-'):
                                # Exclusion: remove field
                                exclude_field = field[1:]
                                temp_doc = doc.copy()
                                temp_doc.pop(exclude_field, None)
                                projected_doc = temp_doc
                            else:
                                # Inclusion: include specific fields
                                if field != '_id' and field in doc:
                                    projected_doc[field] = doc[field]
                                elif field == '_id':
                                    projected_doc[field] = doc.get('_id')
                        data.append(projected_doc)
                    else:
                        data.append(doc.copy())
        
        return MockCursor(data)
    
    async def count_documents(self, query):
        """MongoDB compatible count_documents"""
        if not hasattr(self, '_stored_data') or not self._stored_data:
            return 0
        
        count = 0
        for doc in self._stored_data:
            if self._query_matches(doc, query):
                count += 1
        return count

class MockCursor:
    def __init__(self, data=None):
        self.data = data or []
        self._limit = None
        self._sort_field = None
        self._sort_direction = 1
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        if not self.data:
            raise StopAsyncIteration
        if not hasattr(self, '_index'):
            self._index = 0
        if self._index >= len(self.data):
            raise StopAsyncIteration
        item = self.data[self._index]
        self._index += 1
        return item
    
    def limit(self, limit):
        self._limit = limit
        return self
    
    def sort(self, field, direction):
        self._sort_field = field
        self._sort_direction = direction
        if self.data:
            reverse = direction < 0
            # Handle missing fields safely
            def sort_key(x):
                value = x.get(field)
                return value if value is not None else ""
            self.data.sort(key=sort_key, reverse=reverse)
        return self
    
    async def to_list(self, length=None):
        """MongoDB compatible to_list method"""
        if self._limit and (length is None or self._limit < length):
            return self.data[:self._limit]
        elif length:
            return self.data[:length]
        return self.data

# Mock database functions
def get_db():
    return None

async def connect_db():
    print("[MOCK_DB] Using mock database - no real MongoDB connection")

async def close_db():
    print("[MOCK_DB] Closing mock database connection")

# Mock collections
def users_collection():
    return MockCollection("users")

def chats_collection():
    return MockCollection("chats")

def messages_collection():
    return MockCollection("messages")

def files_collection():
    return MockCollection("files")

def refresh_tokens_collection():
    return MockCollection("refresh_tokens")

def reset_tokens_collection():
    return MockCollection("reset_tokens")

def uploads_collection():
    return MockCollection("uploads")

def get_db():
    return None