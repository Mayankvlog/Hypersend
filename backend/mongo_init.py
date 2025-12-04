"""
MongoDB initialization - Creates admin and application users on first startup
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from backend.config import settings


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
        
        # Try to create root admin user (will fail silently if exists)
        try:
            await admin_db.command('createUser', 'admin', pwd='changeme', roles=['root'])
            print("[MONGO_INIT] Created root admin user")
        except Exception as e:
            if "already exists" in str(e):
                print("[MONGO_INIT] Root admin user already exists")
            else:
                print(f"[MONGO_INIT] Note: {str(e)}")
        
        # Try to create application user (will fail silently if exists)
        try:
            await admin_db.command(
                'createUser',
                'hypersend',
                pwd='Mayank@#03',
                roles=[
                    {'role': 'readWrite', 'db': 'hypersend'},
                    {'role': 'dbOwner', 'db': 'hypersend'}
                ]
            )
            print("[MONGO_INIT] Created application user: hypersend")
        except Exception as e:
            if "already exists" in str(e):
                print("[MONGO_INIT] Application user already exists")
            else:
                print(f"[MONGO_INIT] Note: {str(e)}")
        
        # Create collections if they don't exist
        collections = ['users', 'chats', 'messages', 'files', 'uploads', 'refresh_tokens', 'reset_tokens']
        
        for collection_name in collections:
            try:
                # Try to create collection
                await app_db.create_collection(collection_name)
                print(f"[MONGO_INIT] Created collection: {collection_name}")
            except Exception as e:
                if "already exists" in str(e):
                    print(f"[MONGO_INIT] Collection already exists: {collection_name}")
                else:
                    # Silently ignore - collection might already exist
                    pass
        
        # Create indexes
        try:
            await app_db.users.create_index([('email', 1)], unique=True)
            print("[MONGO_INIT] Created index: users.email")
        except Exception:
            pass  # Index might already exist
        
        try:
            await app_db.chats.create_index([('members', 1)])
            print("[MONGO_INIT] Created index: chats.members")
        except Exception:
            pass
        
        try:
            await app_db.messages.create_index([('chat_id', 1), ('created_at', -1)])
            print("[MONGO_INIT] Created index: messages.chat_id, created_at")
        except Exception:
            pass
        
        try:
            await app_db.files.create_index([('chat_id', 1), ('owner_id', 1)])
            print("[MONGO_INIT] Created index: files.chat_id, owner_id")
        except Exception:
            pass
        
        # Create TTL indexes for token cleanup
        try:
            await app_db.refresh_tokens.create_index([('expires_at', 1)], expireAfterSeconds=0)
            print("[MONGO_INIT] Created TTL index: refresh_tokens.expires_at")
        except Exception:
            pass
        
        try:
            await app_db.reset_tokens.create_index([('expires_at', 1)], expireAfterSeconds=0)
            print("[MONGO_INIT] Created TTL index: reset_tokens.expires_at")
        except Exception:
            pass
        
        print("[MONGO_INIT] ✅ MongoDB initialization complete")
        
    except Exception as e:
        print(f"[MONGO_INIT] Warning: Could not fully initialize MongoDB: {str(e)}")
        print("[MONGO_INIT] Continuing - collections will be created on first use")
    finally:
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
