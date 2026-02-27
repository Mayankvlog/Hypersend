import os
import logging
import asyncio
import sys
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import HTTPException, status
from dotenv import load_dotenv
from pathlib import Path

IS_PRODUCTION = os.getenv("ENVIRONMENT", "").lower() == "production" and os.getenv("DEBUG", "").lower() not in (
    "true",
    "1",
    "yes",
)

# Load environment variables from .env file
env_paths = [Path(__file__).parent / ".env", Path(__file__).parent.parent / ".env"]
for env_path in env_paths:
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
        break

# Global database connection variables as specified
client = None
db = None

# Database initialization state tracker
_database_initialized = False

def is_database_initialized():
    """Check if database is initialized"""
    global _database_initialized, db
    return _database_initialized and db is not None

async def init_database():
    """Initialize MongoDB Atlas database connection"""
    global client, db, _database_initialized
    
    # Read MONGODB_ATLAS_ENABLED from environment (case insensitive)
    mongodb_atlas_enabled = os.getenv("MONGODB_ATLAS_ENABLED", "").lower()
    if mongodb_atlas_enabled != "true":
        raise RuntimeError("MONGODB_ATLAS_ENABLED must be true")
    
    # Read MONGODB_URI from environment
    mongodb_uri = os.getenv("MONGODB_URI")
    if not mongodb_uri:
        raise RuntimeError("MONGODB_URI is required")
    
    # Read DATABASE_NAME from environment
    database_name = os.getenv("DATABASE_NAME")
    if not database_name:
        raise RuntimeError("DATABASE_NAME is required")
    
    # Create AsyncIOMotorClient
    client = AsyncIOMotorClient(mongodb_uri, serverSelectionTimeoutMS=10000)
    
    # Assign db = client[DATABASE_NAME]
    db = client[database_name]
    
    # Run await client.admin.command("ping")
    await client.admin.command("ping")
    
    # Log "MongoDB Atlas connected"
    print("MongoDB Atlas connected")
    
    # Set initialization flag
    _database_initialized = True
    
    # Ensure globals are properly set
    print(f"Database initialized: {db is not None}, Client initialized: {client is not None}")
    print(f"Database name: {database_name}")

def get_database():
    """Get database instance"""
    if db is None:
        raise RuntimeError("Database not initialized")
    return db

# Collection shortcuts
def users_collection():
    """Get users collection"""
    print(f"[DEBUG] users_collection called, db is None: {db is None}, initialized: {_database_initialized}")
    
    # Try global variables first
    if is_database_initialized() and db is not None:
        return db["users"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            print(f"[DEBUG] Using app.state.db as fallback")
            return app.state.db["users"]
    except ImportError:
        print(f"[DEBUG] Could not import app for fallback")
    except Exception as e:
        print(f"[DEBUG] App state fallback failed: {e}")
    
    # Final attempt - try to initialize if not initialized
    if not _database_initialized:
        print("[AUTH_DEBUG] Attempting emergency database initialization")
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If loop is running, create a task
                asyncio.create_task(init_database())
            else:
                # If loop is not running, run directly
                asyncio.run(init_database())
            # Wait a moment for initialization
            import time
            time.sleep(1)
        except Exception as e:
            print(f"[AUTH_DEBUG] Emergency initialization failed: {e}")
    
    # Try again after potential initialization
    if is_database_initialized() and db is not None:
        return db["users"]
    
    print(f"[DEBUG] Database not initialized - both global and app state failed")
    raise RuntimeError("Database not initialized")

def chats_collection():
    """Get chats collection"""
    # Try global variables first
    if is_database_initialized() and db is not None:
        return db["chats"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            return app.state.db["chats"]
    except ImportError:
        pass
    except Exception:
        pass
    
    # Final attempt - try to initialize if not initialized
    if not _database_initialized:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(init_database())
            else:
                asyncio.run(init_database())
            import time
            time.sleep(1)
        except Exception:
            pass
    
    # Try again after potential initialization
    if is_database_initialized() and db is not None:
        return db["chats"]
    
    raise RuntimeError("Database not initialized")

def messages_collection():
    """Get messages collection"""
    # Try global variables first
    if is_database_initialized() and db is not None:
        return db["messages"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            return app.state.db["messages"]
    except ImportError:
        pass
    except Exception:
        pass
    
    # Final attempt - try to initialize if not initialized
    if not _database_initialized:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(init_database())
            else:
                asyncio.run(init_database())
            import time
            time.sleep(1)
        except Exception:
            pass
    
    # Try again after potential initialization
    if is_database_initialized() and db is not None:
        return db["messages"]
    
    raise RuntimeError("Database not initialized")

def files_collection():
    """Get files collection"""
    # Try global variables first
    if is_database_initialized() and db is not None:
        return db["files"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            return app.state.db["files"]
    except ImportError:
        pass
    except Exception:
        pass
    
    # Final attempt - try to initialize if not initialized
    if not _database_initialized:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(init_database())
            else:
                asyncio.run(init_database())
            import time
            time.sleep(1)
        except Exception:
            pass
    
    # Try again after potential initialization
    if is_database_initialized() and db is not None:
        return db["files"]
    
    raise RuntimeError("Database not initialized")

def uploads_collection():
    """Get uploads collection"""
    # Try global variables first
    if is_database_initialized() and db is not None:
        return db["uploads"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            return app.state.db["uploads"]
    except ImportError:
        pass
    except Exception:
        pass
    
    # Final attempt - try to initialize if not initialized
    if not _database_initialized:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(init_database())
            else:
                asyncio.run(init_database())
            import time
            time.sleep(1)
        except Exception:
            pass
    
    # Try again after potential initialization
    if is_database_initialized() and db is not None:
        return db["uploads"]
    
    raise RuntimeError("Database not initialized")

def refresh_tokens_collection():
    """Get refresh tokens collection"""
    # Try global variables first
    if is_database_initialized() and db is not None:
        return db["refresh_tokens"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            return app.state.db["refresh_tokens"]
    except ImportError:
        pass
    except Exception:
        pass
    
    # Final attempt - try to initialize if not initialized
    if not _database_initialized:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(init_database())
            else:
                asyncio.run(init_database())
            import time
            time.sleep(1)
        except Exception:
            pass
    
    # Try again after potential initialization
    if is_database_initialized() and db is not None:
        return db["refresh_tokens"]
    
    raise RuntimeError("Database not initialized")

def reset_tokens_collection():
    """Get reset tokens collection"""
    # Try global variables first
    if is_database_initialized() and db is not None:
        return db["reset_tokens"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            return app.state.db["reset_tokens"]
    except ImportError:
        pass
    except Exception:
        pass
    
    # Final attempt - try to initialize if not initialized
    if not _database_initialized:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(init_database())
            else:
                asyncio.run(init_database())
            import time
            time.sleep(1)
        except Exception:
            pass
    
    # Try again after potential initialization
    if is_database_initialized() and db is not None:
        return db["reset_tokens"]
    
    raise RuntimeError("Database not initialized")

def group_activity_collection():
    """Get group activity collection"""
    # Try global variables first
    if is_database_initialized() and db is not None:
        return db["group_activity"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            return app.state.db["group_activity"]
    except ImportError:
        pass
    except Exception:
        pass
    
    # Final attempt - try to initialize if not initialized
    if not _database_initialized:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(init_database())
            else:
                asyncio.run(init_database())
            import time
            time.sleep(1)
        except Exception:
            pass
    
    # Try again after potential initialization
    if is_database_initialized() and db is not None:
        return db["group_activity"]
    
    raise RuntimeError("Database not initialized")

def media_collection():
    """Get media collection"""
    # Try global variables first
    if is_database_initialized() and db is not None:
        return db["media"]
    
    # Fallback to app state if globals are not available
    try:
        from main import app
        if hasattr(app.state, 'db') and app.state.db is not None:
            return app.state.db["media"]
    except ImportError:
        pass
    except Exception:
        pass
    
    # Final attempt - try to initialize if not initialized
    if not _database_initialized:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(init_database())
            else:
                asyncio.run(init_database())
            import time
            time.sleep(1)
        except Exception:
            pass
    
    # Try again after potential initialization
    if is_database_initialized() and db is not None:
        return db["media"]
    
    raise RuntimeError("Database not initialized")
    return db["media"]

# Backward compatibility aliases for tests
connect_db = lambda: None  # No-op since we use global client
get_db = get_database

# Add database module export for imports
database = sys.modules[__name__]
