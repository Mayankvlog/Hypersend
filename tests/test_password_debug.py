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
    user = None
    try:
        users_coll = users_collection()
        if hasattr(users_coll, 'find_one'):
            # Handle both sync and async find_one
            import inspect
            if inspect.iscoroutinefunction(users_coll.find_one):
                user = await users_coll.find_one({"email": "test@example.com"})
            else:
                user = users_coll.find_one({"email": "test@example.com"})
        else:
            # Mock collection case
            user = None
    except Exception as e:
        print(f"Error getting user: {e}")
        user = None
    
    # Handle case where user might be a coroutine or future
    if user is not None:
        try:
            # Check if user is a coroutine/future that needs to be resolved
            import asyncio
            import inspect
            if inspect.iscoroutine(user) or inspect.isawaitable(user):
                user = await user
            elif hasattr(user, '_result') or hasattr(user, 'result'):
                # It's a Future, get the result
                if hasattr(user, 'result'):
                    user = user.result()
                else:
                    user = user._result
        except Exception as e:
            print(f"Error resolving user: {e}")
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
