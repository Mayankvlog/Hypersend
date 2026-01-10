#!/usr/bin/env python3
"""
Check the current user password in MongoDB
"""
import asyncio
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

async def check_user():
    from config import settings
    from motor.motor_asyncio import AsyncIOMotorClient
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(
        settings.MONGODB_URI,
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=30000,
        retryWrites=False,
        maxPoolSize=10,
        minPoolSize=2
    )
    
    try:
        # Ping to check connection
        result = await client.admin.command('ping')
        print(f"[OK] Connected to MongoDB: {result}")
        
        # Get database
        db = client[settings._MONGO_DB]
        
        # Find the user
        users_col = db['users']
        user = await users_col.find_one({"email": "mayank.kr0311@gmail.com"})
        
        if user:
            print(f"\n[FOUND] User: {user['email']}")
            print(f"  ID: {user.get('_id')}")
            print(f"  Password Hash: {user.get('password_hash')}")
            print(f"    Length: {len(user.get('password_hash', ''))}")
            print(f"  Password Salt: {user.get('password_salt')}")
            if user.get('password_salt'):
                print(f"    Length: {len(user.get('password_salt', ''))}")
            print(f"  Has legacy 'password' field: {'password' in user}")
            if 'password' in user:
                print(f"    Value: {user.get('password')}")
        else:
            print("[NOT FOUND] User not found in MongoDB")
            
            # List all users to see what's there
            all_users = await users_col.find({}).to_list(length=None)
            print(f"\nTotal users in database: {len(all_users)}")
            for u in all_users:
                print(f"  - {u.get('email')}: hash_len={len(u.get('password_hash', ''))}, salt={bool(u.get('password_salt'))}")
                
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(check_user())
