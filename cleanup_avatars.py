#!/usr/bin/env python3
"""
Database cleanup script to clear all avatar text-based values
This will permanently remove any existing text-based avatars from the database
"""

import asyncio
import sys
import os

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from db_proxy import users_collection
from datetime import datetime

async def cleanup_avatar_fields():
    """Clear all avatar fields in the database to prevent text-based avatars"""
    print("🧹 CLEANING UP AVATAR FIELDS IN DATABASE")
    print("=" * 60)
    
    try:
        # Get all users in database
        cursor = users_collection().find({})
        
        # Handle both mock and real database
        import inspect
        if inspect.isawaitable(cursor):
            cursor = await cursor
        
        users_with_avatars = []
        for user in cursor:
            users_with_avatars.append(user)
        
        print(f"📊 Found {len(users_with_avatars)} total users")
        
        if not users_with_avatars:
            print("✅ No users found - database is empty")
            return
        
        # Clear avatar field for all users
        result = await users_collection().update_many(
            {},  # Update all users
            {"$set": {"avatar": "", "updated_at": datetime.now()}}
        )
        
        print(f"✅ Updated {result.modified_count} users")
        print("✅ All avatar fields cleared to empty strings")
        
        # Verify the cleanup
        remaining = await users_collection().count_documents({"avatar": {"$ne": ""}})
        if remaining == 0:
            print("✅ Verification passed: No avatar fields remaining")
        else:
            print(f"⚠️  Warning: {remaining} users still have avatar fields")
            
    except Exception as e:
        print(f"❌ Error during cleanup: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(cleanup_avatar_fields())
    print("\n" + "=" * 60)
    print("🎉 AVATAR CLEANUP COMPLETED")
    print("✅ All text-based avatars permanently removed")
    print("✅ Users will now see proper initials or uploaded images")
