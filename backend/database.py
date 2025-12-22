import sys
import os

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
        error_msg = str(e)
        print(f"[ERROR] Failed to connect to MongoDB")
        print(f"[ERROR] Details: {error_msg}")
        print("[ERROR] Troubleshooting steps:")
        print("  1. Check if MongoDB is running")
        print("  2. Verify connection string format")
        print("  3. Check network connectivity")
        print("  4. Validate authentication credentials")
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
    if db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return db


# Collection shortcuts
def users_collection():
    database = get_db()
    return database.users


def chats_collection():
    database = get_db()
    return database.chats


def messages_collection():
    database = get_db()
    return database.messages


def files_collection():
    database = get_db()
    return database.files


def uploads_collection():
    database = get_db()
    return database.uploads


def refresh_tokens_collection():
    database = get_db()
    return database.refresh_tokens


def reset_tokens_collection():
    database = get_db()
    return database.reset_tokens

