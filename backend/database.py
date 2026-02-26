import os
import logging
import asyncio
import sys
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

# Global database connection variables as specified
client = None
db = None

# Database initialization state tracker
_database_initialized = False

def is_database_initialized():
    """Check if database is initialized"""
    global _database_initialized, db
    return _database_initialized and db is not None

async def init_database():
    """Initialize MongoDB Atlas database connection"""
    global client, db, _database_initialized
    
    # Read MONGODB_ATLAS_ENABLED from environment
    mongodb_atlas_enabled = os.getenv("MONGODB_ATLAS_ENABLED")
    if mongodb_atlas_enabled != "true":
        raise RuntimeError("MONGODB_ATLAS_ENABLED must be true")
    
    # Read MONGODB_URI from environment
    mongodb_uri = os.getenv("MONGODB_URI")
    if not mongodb_uri:
        raise RuntimeError("MONGODB_URI is required")
    
    # Read DATABASE_NAME from environment
    database_name = os.getenv("DATABASE_NAME")
    if not database_name:
        raise RuntimeError("DATABASE_NAME is required")
    
    # Create AsyncIOMotorClient
    client = AsyncIOMotorClient(mongodb_uri, serverSelectionTimeoutMS=10000)
    
    # Assign db = client[DATABASE_NAME]
    db = client[database_name]
    
    # Run await client.admin.command("ping")
    await client.admin.command("ping")
    
    # Log "MongoDB Atlas connected"
    print("MongoDB Atlas connected")
    
    # Set initialization flag
    _database_initialized = True
    
    # Ensure globals are properly set
    print(f"Database initialized: {db is not None}, Client initialized: {client is not None}")
    print(f"Database name: {database_name}")

def get_database():
    """Get database instance"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db

# Collection shortcuts
def users_collection():
    """Get users collection"""
    print(f"[DEBUG] users_collection called, db is None: {db is None}, initialized: {_database_initialized}")
    
    # Try global variables first
    if is_database_initialized():
        return db["users"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            print(f"[DEBUG] Using app.state.db as fallback")
            return app.state.db["users"]
    except ImportError:
        print(f"[DEBUG] Could not import app for fallback")
    except Exception as e:
        print(f"[DEBUG] App state fallback failed: {e}")
    
    print(f"[DEBUG] Database not initialized - both global and app state failed")
    raise RuntimeError("Database not initialized")

def chats_collection():
    """Get chats collection"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["chats"]

def messages_collection():
    """Get messages collection"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["messages"]

def files_collection():
    """Get files collection"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["files"]

def uploads_collection():
    """Get uploads collection"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["uploads"]

def refresh_tokens_collection():
    """Get refresh tokens collection"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["refresh_tokens"]

def reset_tokens_collection():
    """Get reset tokens collection"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["reset_tokens"]

def group_activity_collection():
    """Get group activity collection"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["group_activity"]

def media_collection():
    """Get media collection"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db["media"]

# Backward compatibility aliases for tests
connect_db = lambda: None  # No-op since we use global client
get_db = get_database
