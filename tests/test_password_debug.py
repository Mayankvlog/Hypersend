#!/usr/bin/env python3
"""Debug script to identify password authentication issue"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from backend.routes.users import users_collection
from backend.auth.utils import verify_password

@pytest.mark.asyncio
async def test_user_data():
    """Check what format existing users have"""
    # This will help us understand if users have password_salt field
    try:
        users_coll = users_collection()
        if hasattr(users_coll, 'find_one'):
            user = await users_coll.find_one({"email": "test@example.com"})
        else:
            # Mock collection case
            user = None
    except:
        user = None
    
    if user:
        print("User found:")
        print(f"  _id: {user.get('_id')}")
        print(f"  email: {user.get('email')}")
        print(f"  password_hash: {user.get('password_hash')}")
        print(f"  password_salt: {user.get('password_salt')}")
        print(f"  Keys: {list(user.keys())}")
    else:
        print("User not found")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_user_data())
