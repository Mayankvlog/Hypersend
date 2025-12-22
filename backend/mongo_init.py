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
        from urllib.parse import urlparse, quote_plus
        
        parsed = urlparse(settings.MONGODB_URI)
        
        # Extract username and password from URI
        username = parsed.username or 'hypersend'
        password = parsed.password or 'hypersend_secure_password'
        
        # Try to connect with authentication first
        try:
            client = AsyncIOMotorClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=5000,
            )
            await client.admin.command('ping')
            print("[MONGO_INIT] Connected with existing credentials")
        except Exception as auth_error:
            print(f"[MONGO_INIT] Authentication failed, attempting to create user: {str(auth_error)}")
            
            # Connect without authentication to create user
            # Get root credentials from environment
            import os
            root_user = os.getenv('MONGO_USER', 'hypersend')
            root_password = os.getenv('MONGO_PASSWORD', 'hypersend_secure_password')
            
            # Connect as root user
            root_uri = f"mongodb://{quote_plus(root_user)}:{quote_plus(root_password)}@{parsed.hostname}:{parsed.port or 27017}/admin?authSource=admin"
            
            try:
                root_client = AsyncIOMotorClient(root_uri, serverSelectionTimeoutMS=5000)
                await root_client.admin.command('ping')
                print("[MONGO_INIT] Connected as root user")
                
                # Create application user
                admin_db = root_client.admin
                try:
                    await admin_db.command(
                        "createUser",
                        username,
                        pwd=password,
                        roles=[
                            {"role": "readWrite", "db": "hypersend"},
                            {"role": "dbOwner", "db": "hypersend"}
                        ]
                    )
                    print(f"[MONGO_INIT] Created user '{username}' successfully")
                except Exception as create_error:
                    if "already exists" in str(create_error).lower():
                        print(f"[MONGO_INIT] User '{username}' already exists")
                    else:
                        print(f"[MONGO_INIT] Could not create user: {create_error}")
                
                root_client.close()
                
                # Now connect with the application user
                client = AsyncIOMotorClient(
                    settings.MONGODB_URI,
                    serverSelectionTimeoutMS=5000,
                )
                await client.admin.command('ping')
                print("[MONGO_INIT] Connected with application user")
                
            except Exception as root_error:
                print(f"[MONGO_INIT] Could not connect as root: {root_error}")
                print("[MONGO_INIT] Trying to continue without authentication...")
                # Last resort: connect without auth
                no_auth_uri = f"mongodb://{parsed.hostname}:{parsed.port or 27017}/hypersend"
                client = AsyncIOMotorClient(no_auth_uri, serverSelectionTimeoutMS=5000)
                await client.admin.command('ping')
        
        app_db = client.hypersend
        
        # Create collections if they don't exist
        collections = ['users', 'chats', 'messages', 'files', 'uploads', 'refresh_tokens', 'reset_tokens', 'group_activity']
        
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
            ('chats', [('type', 1), ('created_at', -1)], {}, "chats.type, created_at"),
            ('messages', [('chat_id', 1), ('created_at', -1)], {}, "messages.chat_id, created_at"),
            ('messages', [('chat_id', 1), ('is_pinned', 1), ('pinned_at', -1)], {}, "messages.chat_id, is_pinned, pinned_at"),
            ('messages', [('chat_id', 1), ('is_deleted', 1)], {}, "messages.chat_id, is_deleted"),
            ('files', [('chat_id', 1), ('owner_id', 1)], {}, "files.chat_id, owner_id"),
            ('refresh_tokens', [('expires_at', 1)], {'expireAfterSeconds': 0}, "refresh_tokens.expires_at (TTL)"),
            ('reset_tokens', [('expires_at', 1)], {'expireAfterSeconds': 0}, "reset_tokens.expires_at (TTL)"),
            ('group_activity', [('group_id', 1), ('created_at', -1)], {}, "group_activity.group_id, created_at"),
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
