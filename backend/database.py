from motor.motor_asyncio import AsyncIOMotorClient
from backend.config import settings

client = None
db = None


async def connect_db():
    """Connect to MongoDB"""
    global client, db
    try:
        # Create client with server selection timeout
        client = AsyncIOMotorClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=5000,  # 5 second timeout
            connectTimeoutMS=5000,
            socketTimeoutMS=5000
        )
        # Test the connection
        await client.admin.command('ping')
        db = client.hypersend
        # Avoid leaking full connection string in logs; only log when DEBUG is enabled
        if settings.DEBUG:
            try:
                safe_uri = settings.MONGODB_URI.split("@")[-1]
            except Exception:
                safe_uri = "[redacted]"
            print(f"[OK] Connected to MongoDB: {safe_uri}")
    except Exception as e:
        print(f"[ERROR] Failed to connect to MongoDB: {str(e)}")
        raise


async def close_db():
    """Close MongoDB connection"""
    global client
    if client:
        client.close()
        if settings.DEBUG:
            print("[CLOSE] MongoDB connection closed")


def get_db():
    """Get database instance"""
    return db


# Collection shortcuts
def users_collection():
    if db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return db.users


def chats_collection():
    if db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return db.chats


def messages_collection():
    if db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return db.messages


def files_collection():
    if db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return db.files


def uploads_collection():
    if db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return db.uploads


def refresh_tokens_collection():
    if db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return db.refresh_tokens


def reset_tokens_collection():
    if db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return db.reset_tokens

