#!/usr/bin/env python3

import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

import asyncio
from database import users_collection
from routes.auth import _await_maybe

async def test_database_operations():
    print("Testing database operations...")
    
    try:
        # Test database connection
        users_col = users_collection()
        print(f"✅ Users collection obtained: {type(users_col)}")
        
        # Test a simple query
        print("Testing database query...")
        result = await _await_maybe(users_col.find_one({"email": "nonexistent@test.com"}), timeout=5.0)
        print(f"✅ Database query works, result: {result}")
        
        # Test user document insertion
        print("Testing user insertion...")
        from datetime import datetime, timezone
        from bson import ObjectId
        
        test_doc = {
            "_id": str(ObjectId()),
            "name": "Test User",
            "email": "testdb@example.com",
            "username": "testdb@example.com",
            "password_hash": "test_hash",
            "password_salt": "test_salt",
            "avatar": None,
            "avatar_url": None,
            "bio": None,
            "quota_used": 0,
            "quota_limit": 42949672960,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_seen": None,
            "is_online": False,
            "status": None,
            "permissions": {
                "location": False,
                "camera": False,
                "microphone": False,
                "storage": False
            },
            "pinned_chats": [],
            "blocked_users": []
        }
        
        result = await _await_maybe(users_col.insert_one(test_doc), timeout=5.0)
        print(f"✅ Database insertion works: {result}")
        
        # Clean up
        await _await_maybe(users_col.delete_one({"_id": test_doc["_id"]}), timeout=5.0)
        print("✅ Test document cleaned up")
        
        print("✅ All database operations work!")
        
    except Exception as e:
        print(f"❌ Database operations failed: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    asyncio.run(test_database_operations())
