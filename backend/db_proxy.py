# Database proxy - MongoDB Atlas-only
# Note: some test harnesses load backend modules without package context.
# Support both relative and absolute imports without introducing any DB fallbacks.
try:
    from .database import (
        users_collection,
        chats_collection,
        messages_collection,
        files_collection,
        uploads_collection,
        refresh_tokens_collection,
        reset_tokens_collection,
        group_activity_collection,
        media_collection,
        get_database,
        get_db,
    )
except Exception:
    from database import (
        users_collection,
        chats_collection,
        messages_collection,
        files_collection,
        uploads_collection,
        refresh_tokens_collection,
        reset_tokens_collection,
        group_activity_collection,
        media_collection,
        get_database,
        get_db,
    )

print("[DB_PROXY] Using MongoDB Atlas database")
