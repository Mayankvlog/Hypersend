from motor.motor_asyncio import AsyncIOMotorClient
from backend.config import settings

client = None
db = None


async def connect_db():
    """Connect to MongoDB"""
    global client, db
    client = AsyncIOMotorClient(settings.MONGODB_URI)
    db = client.hypersend
    # Avoid leaking full connection string in logs; only log when DEBUG is enabled
    if settings.DEBUG:
        try:
            safe_uri = settings.MONGODB_URI.split("@")[-1]
        except Exception:
            safe_uri = "[redacted]"
        print(f"✅ Connected to MongoDB: {safe_uri}")


async def close_db():
    """Close MongoDB connection"""
    global client
    if client:
        client.close()
        if settings.DEBUG:
            print("🔌 MongoDB connection closed")


def get_db():
    """Get database instance"""
    return db


# Collection shortcuts
def users_collection():
    return db.users


def chats_collection():
    return db.chats


def messages_collection():
    return db.messages


def files_collection():
    return db.files


def uploads_collection():
    return db.uploads


def refresh_tokens_collection():
    return db.refresh_tokens
