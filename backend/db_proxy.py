# Database proxy - uses database with mock support for pytest
# Import database functions with mock support
try:
    from .database import (
        users_collection, chats_collection, messages_collection, 
        files_collection, uploads_collection, refresh_tokens_collection,
        reset_tokens_collection, group_activity_collection, media_collection,
        get_db, connect_db, close_db, USE_MOCK_DB
    )
except ImportError:
    from database import (
        users_collection, chats_collection, messages_collection, 
        files_collection, uploads_collection, refresh_tokens_collection,
        reset_tokens_collection, group_activity_collection, media_collection,
        get_db, connect_db, close_db, USE_MOCK_DB
    )

if USE_MOCK_DB:
    print("[DB_PROXY] Using mock database for testing")
else:
    print("[DB_PROXY] Using real MongoDB Atlas database")