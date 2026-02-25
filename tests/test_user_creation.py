#!/usr/bin/env python3

import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from datetime import datetime, timezone
from bson import ObjectId
from models import UserCreate
from auth.utils import hash_password

def test_user_creation():
    print("Testing user document creation...")
    
    try:
        # Test UserCreate model
        user_data = {
            "email": "test@example.com",
            "password": "TestPassword123",
            "name": "Test User"
        }
        user = UserCreate(**user_data)
        print(f"✅ UserCreate model works: {user}")
        
        # Test password hashing
        password_hash, salt = hash_password(user.password)
        print(f"✅ Password hashing works")
        
        # Test user document creation
        user_doc = {
            "_id": str(ObjectId()),
            "name": user.name,
            "email": user.email,
            "username": user.email.lower().strip(),
            "password_hash": password_hash,
            "password_salt": salt,
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
        print(f"✅ User document created: _id={user_doc['_id']}")
        
        # Test UserResponse model
        from models import UserResponse
        response = UserResponse(
            id=user_doc["_id"],
            name=user_doc["name"],
            email=user_doc["email"],
            username=user_doc["username"],
            bio=None,
            avatar=None,
            avatar_url=None,
            quota_used=0,
            quota_limit=42949672960,
            created_at=user_doc["created_at"],
            updated_at=None,
            last_seen=None,
            is_online=False,
            status=None,
            pinned_chats=[],
            is_contact=False
        )
        print(f"✅ UserResponse model works: {response}")
        
        print("✅ All user creation steps work!")
        
    except Exception as e:
        print(f"❌ User creation failed: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    test_user_creation()
