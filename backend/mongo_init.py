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
        password = parsed.password or os.getenv('MONGO_PASSWORD', 'change_me_in_production')
        
        client = None
        
        # Try to connect with authentication first
        try:
            client = AsyncIOMotorClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=15000,  # Increased for VPS
                connectTimeoutMS=15000,
            )
            await asyncio.wait_for(client.admin.command('ping'), timeout=10.0)
            print("[MONGO_INIT] Connected with existing credentials")
        except asyncio.TimeoutError:
            print("[MONGO_INIT] Connection timeout - MongoDB might not be ready yet")
            if client:
                client.close()
            return
        except Exception as auth_error:
            print(f"[MONGO_INIT] Authentication failed: {str(auth_error)[:80]}")
            if client:
                client.close()
            
            # Connect without authentication to create user
            # Get root credentials from environment - no fallbacks in production
            import os
            root_user = os.getenv('MONGO_USER')
            root_password = os.getenv('MONGO_PASSWORD')
            
            if not root_user or not root_password:
                raise ValueError("MONGO_USER and MONGO_PASSWORD must be set in production")
            
            # Connect as root user
            root_uri = f"mongodb://{quote_plus(root_user)}:{quote_plus(root_password)}@{parsed.hostname}:{parsed.port or 27017}/admin?authSource=admin"
            
            try:
                root_client = AsyncIOMotorClient(root_uri, serverSelectionTimeoutMS=15000, connectTimeoutMS=15000)
                await asyncio.wait_for(root_client.admin.command('ping'), timeout=10.0)
                print("[MONGO_INIT] Connected as root user")
                
                # Create application user
                admin_db = root_client.admin
                try:
                    await asyncio.wait_for(
                        admin_db.command(
                            "createUser",
                            username,
                            pwd=password,
                            roles=[
                                {"role": "readWrite", "db": "hypersend"},
                                {"role": "dbOwner", "db": "hypersend"}
                            ]
                        ),
                        timeout=5.0
                    )
                    print(f"[MONGO_INIT] Created user '{username}' successfully")
                except asyncio.TimeoutError:
                    print("[MONGO_INIT] User creation timeout")
                except Exception as create_error:
                    if "already exists" in str(create_error).lower():
                        print(f"[MONGO_INIT] User '{username}' already exists")
                    else:
                        print(f"[MONGO_INIT] Could not create user: {str(create_error)[:80]}")
                
                root_client.close()
                
                # Now connect with the application user
                client = AsyncIOMotorClient(
                    settings.MONGODB_URI,
                    serverSelectionTimeoutMS=15000,
                    connectTimeoutMS=15000,
                )
                await asyncio.wait_for(client.admin.command('ping'), timeout=10.0)
                print("[MONGO_INIT] Connected with application user")
                
            except asyncio.TimeoutError:
                print("[MONGO_INIT] Root connection timeout")
                if root_client:
                    root_client.close()
                return
            except Exception as root_error:
                print(f"[MONGO_INIT] Could not connect as root: {str(root_error)[:80]}")
                if 'root_client' in locals():
                    root_client.close()
                # Last resort: try without auth
                try:
                    no_auth_uri = f"mongodb://{parsed.hostname}:{parsed.port or 27017}/hypersend"
                    client = AsyncIOMotorClient(no_auth_uri, serverSelectionTimeoutMS=5000)
                    await asyncio.wait_for(client.admin.command('ping'), timeout=5.0)
                except:
                    print("[MONGO_INIT] All connection methods failed")
                    return
        
        if not client:
            print("[MONGO_INIT] No client connection established")
            return
            
        app_db = client.hypersend
        
        # CRITICAL FIX: Store database and client globally for get_db()
        import mongo_init
        mongo_init._app_db = app_db
        mongo_init._app_client = client
        
        # Create collections if they don't exist
        collections = ['users', 'chats', 'messages', 'files', 'uploads', 'refresh_tokens', 'reset_tokens', 'group_activity']
        
        for collection_name in collections:
            try:
                # Try to create collection with timeout
                await asyncio.wait_for(
                    app_db.create_collection(collection_name),
                    timeout=3.0
                )
                print(f"[MONGO_INIT] Created collection: {collection_name}")
            except asyncio.TimeoutError:
                print(f"[MONGO_INIT] Timeout creating collection: {collection_name}")
            except Exception as e:
                # Collection might already exist - this is expected behavior
                if "already exists" in str(e).lower():
                    pass  # Silent - collection already exists
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
                await asyncio.wait_for(
                    app_db[collection_name].create_index(keys, **options),
                    timeout=3.0
                )
                print(f"[MONGO_INIT] Created index: {description}")
            except asyncio.TimeoutError:
                print(f"[MONGO_INIT] Timeout creating index: {description}")
            except Exception as e:
                # Index might already exist - this is normal on subsequent runs
                if "already exists" not in str(e).lower():
                    pass  # Silent
        
        print("[MONGO_INIT] [OK] MongoDB initialization complete")
        client.close()
        
    except Exception as e:
        print(f"[MONGO_INIT] Warning: {str(e)[:100]}")
        if 'client' in locals() and client:
            try:
                client.close()
            except Exception:
                pass


async def ensure_mongodb_ready():
    """
    Wait for MongoDB to be ready and initialize it
    """
    max_retries = 120  # Increased for VPS
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            await init_mongodb()
            return True
        except Exception as e:
            retry_count += 1
            error_str = str(e)
            if retry_count < max_retries:
                print(f"[MONGO_INIT] Retry {retry_count}/{max_retries}: {error_str[:100]}")
                await asyncio.sleep(1)  # Wait 1 second between retries
            else:
                print(f"[MONGO_INIT] Failed to initialize after {max_retries} retries")
                print(f"[MONGO_INIT] Last error: {error_str}")
                # Don't raise - allow app to start with collections created on first use
                return False
    
    return False
