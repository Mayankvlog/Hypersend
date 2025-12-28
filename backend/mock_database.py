# Simple mock for testing without MongoDB
class MockCollection:
    def __init__(self, name):
        self.name = name
        self.data = {}
    
    async def find_one(self, query):
        if query.get("_id") == "test_user":
            return {"_id": "test_user", "name": "Test User", "email": "test@example.com"}
        return None
    
    async def insert_one(self, data):
        return None
    
    async def update_one(self, query, update):
        return None
    
    async def find(self, query=None, projection=None):
        return MockCursor()
    
    async def count_documents(self, query):
        return 0

class MockCursor:
    def __init__(self):
        pass
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        raise StopAsyncIteration
    
    def limit(self, limit):
        return self
    
    def sort(self, field, direction):
        return self

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