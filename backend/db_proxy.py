# Database proxy - uses database with real MongoDB Atlas
# Import database functions
try:
    from .database import (
        users_collection, chats_collection, messages_collection, 
        files_collection, uploads_collection, refresh_tokens_collection,
        reset_tokens_collection, group_activity_collection, media_collection,
        get_db, connect_db, close_db
    )
except ImportError:
    from database import (
        users_collection, chats_collection, messages_collection, 
        files_collection, uploads_collection, refresh_tokens_collection,
        reset_tokens_collection, group_activity_collection, media_collection,
        get_db, connect_db, close_db
    )

print("[DB_PROXY] Using real MongoDB Atlas database")