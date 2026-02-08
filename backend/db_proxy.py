# Database proxy - always uses real MongoDB Atlas
# Always use real MongoDB Atlas database
try:
    from .database import *
except ImportError:
    from database import *
print("[DB_PROXY] Using real MongoDB Atlas database")