"""
Authentication utilities package
"""

# Import functions from utils to avoid circular imports
try:
    from .utils import (
        hash_password, verify_password, create_access_token, 
        create_refresh_token, decode_token, get_current_user,
        get_current_user_for_upload, get_current_user_optional, get_current_user_or_query
    )
except ImportError:
    # Fallback for circular import issues
    from .auth_utils import (
        hash_password, verify_password, create_access_token, 
        create_refresh_token, decode_token, get_current_user,
        get_current_user_for_upload, get_current_user_optional, get_current_user_or_query
    )

# Also expose functions directly to support both import patterns
__all__ = [
    'hash_password', 'verify_password', 'create_access_token', 
    'create_refresh_token', 'decode_token', 'get_current_user',
    'get_current_user_for_upload', 'get_current_user_optional', 'get_current_user_or_query'
]
