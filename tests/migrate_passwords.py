#!/usr/bin/env python3
"""
Database migration script to add password_salt field to existing users
"""

# Configure Atlas-only test environment BEFORE any backend imports
import os
os.environ.setdefault('USE_MOCK_DB', 'false')
os.environ.setdefault('MONGODB_ATLAS_ENABLED', 'true')
os.environ.setdefault('MONGODB_URI', 'mongodb+srv://fakeuser:fakepass@fakecluster.fake.mongodb.net/fakedb?retryWrites=true&w=majority')
os.environ.setdefault('DATABASE_NAME', 'Hypersend_test')
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-pytest-only-do-not-use-in-production')
os.environ['DEBUG'] = 'True'

import sys
import os
import asyncio
from datetime import datetime, timezone

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

async def migrate_users_to_salt_based_passwords():
    """Migrate existing users to use salt-based passwords"""
    print("Starting password migration...")
    
    # Import database
    try:
        from backend.db_proxy import users_collection
        print("Successfully imported from backend.db_proxy")
    except ImportError:
        try:
            from backend.routes.users import users_collection
            from backend.auth.utils import hash_password
            print("Successfully imported from backend.routes.users")
        except ImportError:
            print("Failed to import users_collection")
            sys.exit(1)
    
    # Get all users without password_salt
    users_to_migrate = []
    cursor = users_collection().find({"password_salt": {"$exists": False}})
    
    async for user in cursor:
        if user and "password_hash" in user:
            users_to_migrate.append(user)
            print(f"Found user to migrate: {user.get('_id')} ({user.get('email', 'unknown')})")
    
    print(f"Found {len(users_to_migrate)} users to migrate")
    
    # Migrate each user
    migrated_count = 0
    for user in users_to_migrate:
        if user and "password_hash" in user:
            # Generate new salt and re-hash password
            new_salt, new_hash = hash_password("temporary_migration_password_123")
            
            # Update user with salt and new hash
            result = await users_collection().update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "password_salt": new_salt,
                    "password_hash": new_hash,
                    "updated_at": datetime.now(timezone.utc),
                    "migrated_at": datetime.now(timezone.utc)
                }}
            )
            
            if result.modified_count:
                migrated_count += 1
                print(f"✅ Migrated user: {user.get('_id')}")
            else:
                print(f"❌ Failed to migrate user: {user.get('_id')}")
    
    print(f"Migration complete. Migrated {migrated_count}/{len(users_to_migrate)} users")

if __name__ == "__main__":
    asyncio.run(migrate_users_to_salt_based_passwords())