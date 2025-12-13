"""
MongoDB initialization - Creates admin and application users on first startup
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from config import settings


async def init_mongodb():
    """
    Initialize MongoDB with required users and collections
    This runs once when the backend starts
    """
    try:
        # Parse the MongoDB URI to extract connection details
        from urllib.parse import urlparse
        
        parsed = urlparse(settings.MONGODB_URI)
        # For initialization, connect to admin database
        admin_uri = f"{parsed.scheme}://{parsed.netloc}/admin"
        
        # Create client for admin database
        client = AsyncIOMotorClient(
            admin_uri,
            serverSelectionTimeoutMS=5000,
        )
        
        admin_db = client.admin
        app_db = client.hypersend
        
        # Test connection
        await admin_db.command('ping')
        print("[MONGO_INIT] Connected to MongoDB")
        
        # Skip user creation in production - users should be created manually
        print("[MONGO_INIT] Skipping automatic user creation - users should be created manually")
        print("[MONGO_INIT] To create users manually, connect to MongoDB and run:")
        print("[MONGO_INIT]   use admin")
        print("[MONGO_INIT]   db.createUser({user: 'admin', pwd: 'your-secure-password', roles: ['root']})")
        print("[MONGO_INIT]   db.createUser({user: 'hypersend', pwd: 'your-secure-password', roles: [{role: 'readWrite', db: 'hypersend'}]})")
        
        # Create collections if they don't exist
        collections = ['users', 'chats', 'messages', 'files', 'uploads', 'refresh_tokens', 'reset_tokens']
        
        for collection_name in collections:
            try:
                # Try to create collection
                await app_db.create_collection(collection_name)
                print(f"[MONGO_INIT] Created collection: {collection_name}")
            except Exception as e:
                # Collection might already exist - this is expected behavior
                if "already exists" in str(e).lower():
                    print(f"[MONGO_INIT] Collection already exists: {collection_name}")
                else:
                    # Silently ignore - collection will be created on first use if needed
                    pass
        
        # Create indexes - these may already exist on subsequent runs
        indexes_to_create = [
            ('users', [('email', 1)], {'unique': True}, "users.email"),
            ('chats', [('members', 1)], {}, "chats.members"),
            ('messages', [('chat_id', 1), ('created_at', -1)], {}, "messages.chat_id, created_at"),
            ('files', [('chat_id', 1), ('owner_id', 1)], {}, "files.chat_id, owner_id"),
            ('refresh_tokens', [('expires_at', 1)], {'expireAfterSeconds': 0}, "refresh_tokens.expires_at (TTL)"),
            ('reset_tokens', [('expires_at', 1)], {'expireAfterSeconds': 0}, "reset_tokens.expires_at (TTL)"),
        ]
        
        for collection_name, keys, options, description in indexes_to_create:
            try:
                await app_db[collection_name].create_index(keys, **options)
                print(f"[MONGO_INIT] Created index: {description}")
            except Exception as e:
                # Index might already exist - this is normal on subsequent runs
                if "already exists" not in str(e).lower():
                    print(f"[MONGO_INIT] Note: Could not create index {description}: {str(e)[:60]}")
        
        print("[MONGO_INIT] [OK] MongoDB initialization complete")
        client.close()
        
    except Exception as e:
        print(f"[MONGO_INIT] Warning: Could not fully initialize MongoDB: {str(e)}")
        print("[MONGO_INIT] Continuing - collections will be created on first use")
        if 'client' in locals():
            try:
                client.close()
            except Exception:
                pass


async def ensure_mongodb_ready():
    """
    Wait for MongoDB to be ready and initialize it
    """
    max_retries = 30
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            await init_mongodb()
            return True
        except Exception as e:
            retry_count += 1
            if retry_count < max_retries:
                print(f"[MONGO_INIT] Retry {retry_count}/{max_retries}: {str(e)}")
                await asyncio.sleep(1)
            else:
                print(f"[MONGO_INIT] Failed to initialize after {max_retries} retries")
                raise
    
    return False
