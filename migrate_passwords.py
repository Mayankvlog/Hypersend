#!/usr/bin/env python3
"""
Password Migration Script
Migrates existing users from old password format to new PBKDF2 format
Run this script to update all users in the database
"""
import asyncio
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

async def migrate_user_passwords():
    """Migrate all users to new password format"""
    from backend.config import settings
    from motor.motor_asyncio import AsyncIOMotorClient
    from backend.auth.utils import verify_password
    import hashlib
    
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
        # Test connection
        result = await client.admin.command('ping')
        print(f"[OK] Connected to MongoDB")
        
        # Get database and collection
        db = client[settings._MONGO_DB]
        users_col = db['users']
        
        # Find all users that need migration
        # Users needing migration either:
        # 1. Have password_hash but no password_salt (old separate format)
        # 2. Have password_hash as combined format (salt$hash)
        # 3. Have invalid salt length
        
        all_users = await users_col.find({}).to_list(length=None)
        
        print(f"\n[INFO] Total users in database: {len(all_users)}")
        
        migrated = 0
        failed = 0
        
        for user in all_users:
            email = user.get('email', 'UNKNOWN')
            user_id = user.get('_id')
            password_hash = user.get('password_hash')
            password_salt = user.get('password_salt')
            
            needs_migration = False
            
            # Check if migration is needed
            if password_hash:
                # Check for combined format (97 chars with $)
                if isinstance(password_hash, str) and len(password_hash) == 97 and '$' in password_hash:
                    needs_migration = True
                    print(f"  [MIGRATE] {email}: Combined format (salt$hash)")
                # Check for missing or invalid salt
                elif not password_salt:
                    needs_migration = True
                    print(f"  [MIGRATE] {email}: Missing salt")
                elif not isinstance(password_salt, str) or len(password_salt) != 32:
                    needs_migration = True
                    print(f"  [MIGRATE] {email}: Invalid salt (len={len(password_salt) if password_salt else 0})")
            
            if not needs_migration:
                print(f"  [SKIP] {email}: Already in new format")
                continue
            
            # For migration, we would normally need the original password to rehash it
            # But since we don't have it, we'll just mark the user as needing manual password reset
            try:
                await users_col.update_one(
                    {"_id": user_id},
                    {
                        "$set": {
                            "password_needs_reset": True,
                            "password_migrated_at": asyncio.get_event_loop().time()
                        }
                    }
                )
                print(f"    ✓ Marked for password reset")
                migrated += 1
            except Exception as e:
                print(f"    ✗ Update failed: {e}")
                failed += 1
        
        print(f"\n[SUMMARY]")
        print(f"  Migrated: {migrated}")
        print(f"  Failed: {failed}")
        print(f"  No migration needed: {len(all_users) - migrated - failed}")
        
        print(f"\n[NOTE] Users marked for migration should reset their password on next login")
                
    except Exception as e:
        print(f"[ERROR] Migration failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(migrate_user_passwords())
