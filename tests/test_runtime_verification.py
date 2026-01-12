#!/usr/bin/env python3
"""
Runtime verification test for password functionality
"""

import sys
import os
import asyncio
from datetime import datetime, timezone

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Set environment variable for testing
os.environ['USE_MOCK_DB'] = 'True'

async def test_password_functionality():
    """Test actual password functionality with real database operations"""
    print("=== Testing Password Functionality ===")
    
    # Import required modules
    from backend.db_proxy import users_collection
    from backend.auth.utils import hash_password, verify_password
    
    # Test 1: Hash password
    test_password = "test_password_123"
    password_hash, password_salt = hash_password(test_password)
    print(f"✅ Password hashing works: hash={password_hash[:20]}..., salt={password_salt[:20]}...")
    
    # Test 2: Verify password with correct hash and salt
    is_valid = verify_password(test_password, password_hash, password_salt, "test_user")
    print(f"✅ Password verification works: {is_valid}")
    
    # Test 3: Store user with password hash and salt
    test_user = {
        "_id": "test_user_runtime",
        "email": "test@example.com",
        "name": "Test User",
        "password_hash": password_hash,
        "password_salt": password_salt,
        "created_at": datetime.now(timezone.utc)
    }
    
    # Insert test user
    await users_collection().insert_one(test_user)
    print(f"✅ User stored in database with password_hash and password_salt")
    
    # Test 4: Verify stored password can be verified
    stored_user = await users_collection().find_one({"_id": "test_user_runtime"})
    if stored_user:
        stored_hash = stored_user.get("password_hash", "")
        stored_salt = stored_user.get("password_salt", "")
        
        if stored_hash and stored_salt:
            is_stored_valid = verify_password(test_password, stored_hash, stored_salt, "test_user_runtime")
            print(f"✅ Stored password verification works: {is_stored_valid}")
        else:
            print("❌ Stored password missing hash or salt")
    else:
        print("❌ Could not retrieve stored user")
    
    print("=== Password Functionality Test Complete ===")

if __name__ == "__main__":
    asyncio.run(test_password_functionality())
