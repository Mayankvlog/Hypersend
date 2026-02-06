# Database proxy that automatically chooses between real and mock based on settings
from .config import settings

if settings.USE_MOCK_DB:
    from .mock_database import *
    print("[DB_PROXY] Using mock database")
else:
    from .database import *
    print("[DB_PROXY] Using real database")