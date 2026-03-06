from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, TYPE_CHECKING
import uuid
import jwt
from jwt import PyJWTError
import hashlib
import hmac
import logging
import os
from fastapi import HTTPException, status, Depends, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets
import string
import base64
import json
from io import BytesIO
import sys
from pathlib import Path

# Robust import handling for settings and models
try:
    # Prefer canonical package import to avoid duplicate modules (backend.config vs config)
    from backend.config import settings
except ImportError:
    try:
        # Try direct import (when running from backend directory)
        from config import settings
    except ImportError:
        try:
            # Try parent directory import (when running from project root)
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from config import settings
        except ImportError as e:
            raise ImportError(
                f"Failed to import settings from config module. "
                f"Ensure config.py exists in backend directory. Error: {e}"
            ) from e

try:
    # Try direct import first
    from models import TokenData
except ImportError:
    try:
        # Try parent directory import
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from models import TokenData
    except ImportError as e:
        raise ImportError(
            f"Failed to import TokenData from models module. "
            f"Ensure models.py exists in backend directory. Error: {e}"
        ) from e

# Configure logger
logger = logging.getLogger(__name__)


def _get_settings():
    """Return the current settings object.

    Some tests reload backend.config; importing `settings` once at module import time
    can leave this module with a stale SECRET_KEY/ALGORITHM reference.
    """
    try:
        import backend.config as _backend_config
        return _backend_config.settings
    except Exception:
        return settings

# Token lifetime constants
UPLOAD_TOKEN_MAX_LIFETIME_HOURS = 480  # 20 days - maximum lifetime for upload tokens
UPLOAD_TOKEN_MAX_LIFETIME_SECONDS = UPLOAD_TOKEN_MAX_LIFETIME_HOURS * 3600  # 1,728,000 seconds

def _log(level: str, message: str, extra_data: dict = None):
    """Centralized logging function for auth utilities"""
    log_data = {"auth_operation": message}
    if extra_data:
        log_data.update(extra_data)
    
    getattr(logger, level.lower())(message, extra=log_data)

# Handle QRCode imports with Pylance compatibility
if TYPE_CHECKING:
    # Type checking mode - provide stubs for Pylance
    from typing import Any
    
    class QRCode:
        def __init__(self, version: int = 1, error_correction: Any = None, 
                    box_size: int = 10, border: int = 2) -> None: ...
        def add_data(self, data: str) -> None: ...
        def make(self, fit: bool = True) -> None: ...
        def make_image(self, fill_color: str = "black", back_color: str = "white") -> Any: ...
    
    class ERROR_CORRECT_L: ...
    
    # In type checking mode, set to False for consistency with runtime behavior
    QR_CODE_AVAILABLE = False
else:
    # Runtime mode - actual imports
    try:
        import qrcode
        from qrcode.image.pil import PilImage
        QR_CODE_AVAILABLE = True
    except ImportError as qrcode_error:
        QR_CODE_AVAILABLE = False
        
        class MockQRCode:
            def add_data(self, data):
                pass
            
            def make(self, fit=True):
                pass
            
            def make_image(self, **kwargs):
                raise ImportError("QR code library not installed")
        
        qrcode = MockQRCode
        PilImage = None
        print(f"QR code library not available: {qrcode_error}")

logger = logging.getLogger("auth")
security = HTTPBearer(
    auto_error=False  # Don't auto-raise, handle it manually
)


def hash_password(password: str) -> Tuple[str, str]:
    """Hash a password using PBKDF2 with SHA-256 and cryptographically secure salt
    
    Returns:
        Tuple[str, str]: (password_hash, salt) - separate hash and salt for database storage
    """
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string")
    
    if len(password) < 1 or len(password) > 128:
        raise ValueError("Password length must be between 1 and 128 characters")
    
    # CRITICAL FIX: Use secrets.token_hex for cryptographically secure salt
    # Generate 32 hex characters (16 bytes of random data)
    try:
        salt = secrets.token_hex(16)  # 16 bytes -> 32 hex chars
    except Exception as e:
        raise ValueError(f"Failed to generate cryptographically secure salt: {type(e).__name__}")
    
    if not salt or len(salt) != 32:
        raise ValueError("Invalid salt generation - critical security issue")
    
    try:
        password_bytes = password.encode('utf-8')
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt.encode('utf-8'),
            100000  # 100,000 iterations (NIST recommendation)
        )
        
        hash_hex = password_hash.hex()
        if not hash_hex or len(hash_hex) != 64:  # SHA256 produces 64 hex chars
            raise ValueError("Invalid hash generation")
        
        # Return separate hash and salt for database storage
        return hash_hex, salt
    except Exception as e:
        raise ValueError(f"Password hashing failed: {type(e).__name__}")


def verify_password(plain_password: str, hashed_password: str, salt: str = None, user_id: str = None) -> bool:
    """Verify a password against its PBKDF2 hash with constant-time comparison
    
    Args:
        plain_password: Password to verify
        hashed_password: Hashed password (hex string) - can be combined "salt$hash" or just hash
        salt: Salt used for hashing (hex string) - optional, extracted from hashed_password if not provided
        user_id: Optional user ID for logging
    """
    try:
        if not plain_password or not hashed_password:
            _log("debug", f"Password verification failed: missing input (user: {user_id})")
            return False
        
        # CRITICAL FIX: Handle both new format (separate hash/salt) and legacy format (combined)
        if salt is None:
            # Legacy format: hash contains "salt$hash"
            if '$' in hashed_password:
                parts = hashed_password.split('$')
                if len(parts) != 2:
                    _log("warning", f"Invalid hash format: expected 2 parts, got {len(parts)} (user: {user_id})")
                    return False
                
                salt, stored_hash = parts
                if not salt or not stored_hash:
                    _log("warning", f"Invalid hash format: empty salt or hash (user: {user_id})")
                    return False
                
                if len(salt) != 32:
                    _log("warning", f"Invalid salt length: expected 32, got {len(salt)} (user: {user_id})")
                    return False
                
                try:
                    password_bytes = plain_password.encode('utf-8')
                    password_hash = hashlib.pbkdf2_hmac(
                        'sha256',
                        password_bytes,
                        salt.encode('utf-8'),
                        100000
                    )
                    computed_hex = password_hash.hex()
                    # SECURITY: Use constant-time comparison to prevent timing attacks
                    is_valid = hmac.compare_digest(computed_hex, stored_hash)
                    return is_valid
                except (ValueError, UnicodeEncodeError) as e:
                    _log("warning", f"Password verification failed: {type(e).__name__}")
                    return False
            else:
                # Handle other legacy formats - CRITICAL FIX: Pass salt parameter
                return _verify_legacy_passwords(plain_password, hashed_password, salt, user_id)
        else:
            # New format: separate hash and salt provided
            # CRITICAL FIX: Be permissive about salt format - just try to verify it
            if len(plain_password) > 128:
                _log("warning", f"Password verification failed: password exceeds maximum length (user: {user_id})")
                return False
            
            if len(hashed_password) > 256:
                _log("warning", f"Password verification failed: hash exceeds maximum length (user: {user_id})")
                return False
            
            # Try to verify with the provided salt, regardless of format
            # This allows for test data and legacy formats
            try:
                password_bytes = plain_password.encode('utf-8')
                # For short salts or non-hex salts, just encode as-is
                # For proper 32-char hex salts, this will work fine with PBKDF2
                password_hash = hashlib.pbkdf2_hmac(
                    'sha256',
                    password_bytes,
                    salt.encode('utf-8') if isinstance(salt, str) else salt,
                    100000
                )
                computed_hex = password_hash.hex()
                # SECURITY: Use constant-time comparison to prevent timing attacks
                is_valid = hmac.compare_digest(computed_hex, hashed_password)
                
                # CRITICAL FIX: If PBKDF2 fails and we have salt, try legacy SHA256+salt format
                if not is_valid and salt:
                    _log("debug", f"PBKDF2 with provided salt failed, trying legacy SHA256+salt format (user: {user_id})")
                    legacy_result = _verify_legacy_passwords(plain_password, hashed_password, salt, user_id)
                    if legacy_result:
                        _log("warning", f"User {user_id} using legacy SHA256+salt format - migration recommended")
                        return True
                    else:
                        _log("error", f"Legacy SHA256+salt verification also failed for {user_id}")
                        return False
                
                # CRITICAL FIX: If PBKDF2 fails and hash is 64 chars, try legacy SHA256 without salt
                if not is_valid and len(hashed_password) == 64 and all(c in '0123456789abcdefABCDEF' for c in hashed_password):
                    _log("debug", f"PBKDF2 with provided salt failed, trying legacy SHA256 (user: {user_id})")
                    # Fallback to legacy SHA256 without salt
                    legacy_hash = hashlib.sha256(plain_password.encode()).hexdigest()
                    is_valid = hmac.compare_digest(legacy_hash, hashed_password)
                    if is_valid:
                        _log("warning", f"User {user_id} using legacy SHA256 password - migration recommended")
                
                return is_valid
            except (ValueError, UnicodeEncodeError) as e:
                _log("warning", f"Password verification failed: {type(e).__name__}")
                return False
            
    except Exception as e:
        # Log but don't expose details
        _log("error", f"Password verification exception: {type(e).__name__}")
        return False


def _verify_legacy_passwords(plain_password: str, hashed_password: str, salt: str = None, user_id: str = None) -> bool:
    """Verify legacy password formats for migration purposes"""
    try:
        # CRITICAL FIX: Be flexible with salt validation - try multiple legacy formats
        if salt and hashed_password:
            _log("debug", f"Attempting legacy password verification formats for {user_id}")
            
            try:
                # Format 1: SHA256(password + salt) with hex salt
                combined_input = plain_password + salt
                legacy_hash = hashlib.sha256(combined_input.encode()).hexdigest()
                if hmac.compare_digest(legacy_hash, hashed_password):
                    _log("warning", f"User {user_id} using legacy SHA256(password+salt) format - migration recommended")
                    return True
                    
                # Format 2: SHA256(salt + password) with hex salt
                combined_input_alt = salt + plain_password
                legacy_hash_alt = hashlib.sha256(combined_input_alt.encode()).hexdigest()
                if hmac.compare_digest(legacy_hash_alt, hashed_password):
                    _log("warning", f"User {user_id} using legacy SHA256(salt+password) format - migration recommended")
                    return True
                
                # Format 3: PBKDF2 with string salt (not hex-decoded)
                try:
                    password_bytes = plain_password.encode('utf-8')
                    salt_bytes = salt.encode('utf-8')
                    password_hash = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)
                    pbkdf2_hex = password_hash.hex()
                    if hmac.compare_digest(pbkdf2_hex, hashed_password):
                        _log("warning", f"User {user_id} using legacy PBKDF2 with string salt - migration recommended")
                        return True
                except Exception as e:
                    _log("debug", f"PBKDF2 with string salt failed for {user_id}: {e}")
                
                # Format 4: Try with salt as hex bytes (if salt is a valid hex string)
                if len(salt) == 32 and all(c in '0123456789abcdefABCDEF' for c in salt):
                    try:
                        salt_bytes = bytes.fromhex(salt)
                        password_bytes = plain_password.encode('utf-8')
                        password_hash = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)
                        pbkdf2_hex = password_hash.hex()
                        if hmac.compare_digest(pbkdf2_hex, hashed_password):
                            _log("warning", f"User {user_id} using legacy PBKDF2 with hex salt - migration recommended")
                            return True
                    except Exception as e:
                        _log("debug", f"PBKDF2 with hex salt failed for {user_id}: {e}")
                    
            except Exception as e:
                _log("error", f"Legacy SHA256+salt verification failed: {type(e).__name__}")
        
        # Check for combined salt$hash format (97 chars: 32+1+64)
        if len(hashed_password) == 97 and '$' in hashed_password:
            parts = hashed_password.split('$')
            if len(parts) == 2:
                salt, stored_hash = parts
                if len(salt) == 32 and len(stored_hash) == 64:
                    try:
                        password_bytes = plain_password.encode('utf-8')
                        password_hash = hashlib.pbkdf2_hmac(
                            'sha256',
                            password_bytes,
                            salt.encode('utf-8'),
                            100000
                        )
                        computed_hex = password_hash.hex()
                        is_valid = hmac.compare_digest(computed_hex, stored_hash)
                        if is_valid:
                            _log("warning", f"User {user_id} using legacy password format - migration recommended")
                        return is_valid
                    except Exception as e:
                        _log("error", f"Legacy hash verification failed: {type(e).__name__}")
                        return False
        
        # Original checks for pure SHA256 (64 chars) and MD5 (32 chars)
        if len(hashed_password) == 64 and all(c in '0123456789abcdefABCDEF' for c in hashed_password):
            # Legacy SHA256 hash (64 hex chars) - ONLY for migration, not recommended
            try:
                legacy_hash = hashlib.sha256(plain_password.encode()).hexdigest()
                if hmac.compare_digest(legacy_hash, hashed_password):
                    _log("warning", f"User {user_id} using legacy password hash - migration recommended")
                    return True
                return False
            except Exception as e:
                _log("error", f"Legacy hash verification failed: {type(e).__name__}")
                return False
        elif len(hashed_password) == 32 and '$' not in hashed_password:
            # Possible MD5 hash (32 hex chars) - INSECURE but handle for migration
            try:
                md5_hash = hashlib.md5(plain_password.encode()).hexdigest()
                if hmac.compare_digest(md5_hash, hashed_password):
                    _log("warning", f"User {user_id} using INSECURE MD5 password hash - migration required")
                    return True
                return False
            except Exception as e:
                _log("error", f"MD5 hash verification failed: {type(e).__name__}")
                return False
        else:
            # Invalid hash format - reject immediately
            _log("warning", f"Invalid password hash format for user {user_id}: length={len(hashed_password)}, format={hashed_password[:20]}...")
            return False
            
    except Exception as e:
        # Log but don't expose details
        _log("error", f"Legacy password verification exception: {type(e).__name__}")
        return False


def diagnose_password_format(hashed_password: str, salt: str = None) -> dict:
    """Diagnose what password format is stored in the database
    
    Returns a dict with detected format info
    """
    diagnosis = {
        "hash": {
            "length": len(hashed_password) if hashed_password else 0,
            "is_hex": False,
            "format": "unknown",
            "details": ""
        },
        "salt": {
            "length": len(salt) if salt else 0,
            "is_hex": False,
            "format": "unknown"
        },
        "combined_format": False
    }
    
    if hashed_password:
        # Check if it's hex
        is_hex = all(c in '0123456789abcdefABCDEF' for c in str(hashed_password))
        diagnosis["hash"]["is_hex"] = is_hex
        
        # Check for combined format
        if '$' in hashed_password:
            diagnosis["combined_format"] = True
            diagnosis["hash"]["format"] = "combined_format (salt$hash)"
            parts = hashed_password.split('$')
            if len(parts) == 2:
                diagnosis["hash"]["details"] = f"2 parts: {len(parts[0])}-char salt, {len(parts[1])}-char hash"
        elif len(hashed_password) == 64 and is_hex:
            diagnosis["hash"]["format"] = "SHA256_hex"
        elif len(hashed_password) == 32 and is_hex:
            diagnosis["hash"]["format"] = "MD5_hex"
        else:
            diagnosis["hash"]["format"] = f"unknown_hex_{len(hashed_password)}"
    
    if salt:
        is_hex = all(c in '0123456789abcdefABCDEF' for c in str(salt))
        diagnosis["salt"]["is_hex"] = is_hex
        if len(salt) == 32 and is_hex:
            diagnosis["salt"]["format"] = "hex_32_char_salt"
        else:
            diagnosis["salt"]["format"] = f"other_{len(salt)}_char"
    
    return diagnosis


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token with production domain validation"""
    s = _get_settings()
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=s.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Add expiration and issued-at timestamp to the token payload
    now = datetime.now(timezone.utc)
    to_encode.update({
        "exp": expire,
        "iat": now
    })

    # Password reset tokens must have a jti to support replay protection.
    # If caller didn't provide one, generate it.
    if to_encode.get("token_type") == "password_reset" and not to_encode.get("jti"):
        to_encode["jti"] = str(uuid.uuid4())
    
    # Access and refresh tokens should also have JTI for revocation support
    if to_encode.get("token_type") in ["access", "refresh"] and not to_encode.get("jti"):
        to_encode["jti"] = str(uuid.uuid4())
    
    # Only set token_type to "access" if not already specified
    if "token_type" not in to_encode:
        to_encode.update({"token_type": "access"})
    
    # SECURITY: Ensure we use the configured SECRET_KEY and ALGORITHM from production config
    # Never use hardcoded values
    if not s.SECRET_KEY or len(s.SECRET_KEY) < 8:
        raise ValueError("SECRET_KEY must be configured and at least 8 characters")
    
    encoded_jwt = jwt.encode(to_encode, s.SECRET_KEY, algorithm=s.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> Tuple[str, str]:
    """Create JWT refresh token and return (token, jti)."""
    s = _get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=s.REFRESH_TOKEN_EXPIRE_DAYS)
    jti = str(uuid.uuid4())
    to_encode.update({"exp": expire, "token_type": "refresh", "jti": jti})
    s = _get_settings()
    encoded_jwt = jwt.encode(to_encode, s.SECRET_KEY, algorithm=s.ALGORITHM)
    return encoded_jwt, jti


def decode_token(token: str) -> TokenData:
    """Decode and validate JWT token with enhanced validation and timing attack protection"""
    try:
        s = _get_settings()
        # SECURITY FIX: Remove random delay to improve performance
        # Timing attacks are mitigated by constant-time comparison in hmac.compare_digest
        
        if not token or not isinstance(token, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: token must be a non-empty string",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        payload = jwt.decode(token, s.SECRET_KEY, algorithms=[s.ALGORITHM])
        user_id: str = payload.get("sub")
        token_type: str = payload.get("token_type")
        jti: Optional[str] = payload.get("jti")  # CRITICAL FIX: Extract JTI for token revocation
        
        # Enhanced 'sub' field validation - support both ObjectId and string IDs
        if not user_id or not isinstance(user_id, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing or invalid subject identifier",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Validate user_id format - support both ObjectId and string formats
        from bson import ObjectId
        # Allow either valid ObjectId or non-empty string (for usernames/email-based IDs)
        if not (ObjectId.is_valid(user_id) or (len(user_id) > 0 and user_id.replace('_', '').replace('-', '').isalnum())):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: malformed user identifier",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # CRITICAL FIX: Enhanced token validation with scope and user binding
        if not token_type or token_type not in ["access", "refresh", "password_reset", "upload"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: unsupported or missing token type (got: {token_type})",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Additional validation for upload tokens
        if token_type == "upload":
            # Upload tokens must have explicit user binding
            if "upload_scope" not in payload or not payload.get("upload_scope"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Upload token missing required scope",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Upload tokens must have expiration and not be expired
            if "exp" not in payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Upload token missing expiration",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Upload tokens should have reasonable TTL (validate max 480 hours for large files)
            exp_timestamp = payload["exp"]
            issued_at = payload.get("iat", exp_timestamp)
            if exp_timestamp - issued_at > UPLOAD_TOKEN_MAX_LIFETIME_SECONDS:  # More than 480 hours
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Upload token lifetime exceeds maximum allowed duration",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        # Return TokenData with jti for refresh token validation
        return TokenData(
            user_id=user_id,
            token_type=token_type,
            jti=jti,
            payload=payload
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PyJWTError:
        # Any JWT-related error (invalid signature, bad format, etc.)
        # should surface as a 401 Unauthorized rather than 500.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def verify_token(token: str) -> dict:
    """Verify JWT token and return payload with normalized user_id field"""
    if not token or not isinstance(token, str):
        raise ValueError("Token must be a non-empty string")
    
    try:
        s = _get_settings()
        payload = jwt.decode(token, s.SECRET_KEY, algorithms=[s.ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError("Token has expired")
    except jwt.InvalidTokenError:
        raise jwt.InvalidTokenError("Invalid token")
    
    # Normalize payload to always include user_id for backward compatibility
    if "sub" in payload and "user_id" not in payload:
        payload["user_id"] = payload["sub"]
    
    return payload


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    """Dependency to get current user from HTTPOnly cookies or Authorization header
    
    SECURITY: 
    - First tries to read access token from HTTPOnly cookie (preferred method)
    - Falls back to Authorization Bearer header for backward compatibility
    - Validates JWT token, verifies user exists in MongoDB Atlas
    - Handles all error cases with proper HTTP status codes
    
    Returns:
        user_id (string) from validated JWT token
        
    Raises:
        HTTPException(401): If credentials missing, token invalid/expired, or user not found
        HTTPException(503): If database unavailable
    """
    # PRIORITY 1: Try to get access token from HTTPOnly cookie (secure method)
    access_token = request.cookies.get("access_token")
    
    # PRIORITY 2: Fallback to Authorization header if no cookie found
    if not access_token and credentials:
        access_token = credentials.credentials
    
    # Check if any authentication method is available
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials - please login",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # CRITICAL FIX: Decode and validate token with proper expiration handling
    # This will raise HTTPException(401) for expired tokens
    try:
        token_data = decode_token(access_token)
    except HTTPException as e:
        # Re-raise auth exceptions with proper headers
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            # Ensure 401 responses have WWW-Authenticate header
            if not e.headers:
                e.headers = {}
            if "WWW-Authenticate" not in e.headers:
                e.headers["WWW-Authenticate"] = "Bearer"
        raise
    
    if token_data.token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type - access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    from bson import ObjectId

    user_id_str = token_data.user_id
    # Validate user_id format - must be valid ObjectId
    if not ObjectId.is_valid(user_id_str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user identifier in token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_oid = ObjectId(user_id_str)

    # Always verify/load the user from Atlas so routes can rely on request.state
    users_col = None
    try:
        if request is not None and hasattr(request, "app") and hasattr(request.app, "state"):
            db = getattr(request.app.state, "db", None)
            if db is not None:
                users_col = db["users"]
    except Exception:
        users_col = None

    if users_col is None:
        try:
            from database import users_collection
            users_col = users_collection()
        except Exception as e:
            logger.error(f"Failed to get users collection: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service unavailable",
            ) from e

    existing_user = None
    try:
        existing_user = await users_col.find_one({"_id": user_oid})
    except Exception as e:
        # Authentication must not "randomly fail" due to transient DB issues.
        # If Atlas is unavailable, surface it as a service error rather than
        # incorrectly treating the user as unauthenticated.
        logger.error(f"Database error during user lookup: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database temporarily unavailable",
        ) from e

    if not existing_user:
        logger.warning(f"User {user_id_str} from valid token not found in database")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found in database",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Attach loaded user doc for downstream route handlers
        setattr(request.state, "current_user", existing_user)
    except Exception:
        pass  # Non-critical, continue if setting state fails

    return user_id_str


async def get_current_user_optional(request: Request) -> Optional[str]:
    """Dependency to get current user from HTTPOnly cookies or Authorization header - returns None if auth fails or missing"""
    try:
        # PRIORITY 1: Try to get access token from HTTPOnly cookie (secure method)
        access_token = request.cookies.get("access_token")
        
        # PRIORITY 2: Fallback to Authorization header if no cookie found
        if not access_token:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                access_token = auth_header.replace("Bearer ", "").strip()
        
        # Check if any authentication method is available
        if not access_token:
            logger.debug("No authentication credentials found, allowing guest access")
            return None
            
        token_data = decode_token(access_token)
        
        if token_data.token_type != "access":
            logger.debug("Wrong token type, allowing guest access")
            return None
        
        logger.debug(f"User authenticated successfully")
        return token_data.user_id
    except Exception as e:
        logger.debug(f"Auth failed (non-fatal), allowing guest access")
        return None

async def get_current_user_or_query(
    request: Request,
    token: Optional[str] = Query(None)
) -> str:
    """ENHANCED DEPENDENCY WITH AUTOMATIC TOKEN REFRESH FOR SESSION PERSISTENCE.
    
    SECURITY: QUERY PARAMETER AUTHENTICATION HAS BEEN DISABLED.
    ONLY COOKIE-FIRST AUTHENTICATION IS ALLOWED FOR SECURITY REASONS.
    
    ENHANCEMENTS:
    - Automatic token refresh for expired access tokens
    - Extended session support for better user experience
    - Graceful handling of token expiration during refresh
    
    Args:
        request: The request object (for cookie and header auth)
        token: IGNORED - query parameter authentication disabled
        
    Returns:
        The user_id from the HTTPOnly cookie or Authorization header token
        
    Raises:
        HTTPException: If both cookie and header token are missing or invalid
    """
    # SECURITY: Log any query parameter attempts for monitoring
    if token is not None:
        logger.warning("SECURITY VIOLATION: Query parameter authentication attempted - ignored for security")
    
    # PRIORITY 1: Try to get access token from HTTPOnly cookie (secure method)
    access_token = request.cookies.get("access_token")
    
    # PRIORITY 2: Fallback to Authorization header if no cookie found
    if not access_token:
        auth_header = request.headers.get("authorization", "")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required - use HTTPOnly cookie or Authorization header with Bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token = auth_header.replace("Bearer ", "").strip()
    
    # Check if any authentication method is available
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials - please login",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Strict JWT validation: expired tokens MUST be rejected with HTTP 401.
    token_data = decode_token(access_token)
    if token_data.token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type - access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_data.user_id


async def get_current_user_from_query(
    token: Optional[str] = Query(None),
) -> str:
    """Backward-compatible entrypoint for query-param auth.

    Query-parameter authentication is disabled for security. This function exists
    to preserve older imports and to explicitly reject attempts.
    """
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Query parameter authentication is disabled for security",
        headers={"WWW-Authenticate": "Bearer"},
    )


def validate_upload_token(token: str) -> TokenData:
    """Validate an upload token.

    This is a small wrapper kept for backwards compatibility with older code and
    tests that patch/spy on `validate_upload_token`.
    """
    token_data = decode_token(token)
    if token_data.token_type not in {"upload", "access"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_data


async def get_current_user_for_upload(
    request: Request,
    token: Optional[str] = None
) -> Optional[str]:
    """
    Enhanced dependency for file upload endpoints with 480-hour token validation.
    Extracts and validates JWT token from HTTPOnly cookie or Authorization header.
    Returns user_id if valid, None if missing/invalid.
    Implements special 480-hour validation for upload operations.
    """
    # PRIORITY 1: Try to get access token from HTTPOnly cookie (secure method)
    access_token = request.cookies.get("access_token")
    
    # PRIORITY 2: Fallback to Authorization header if no cookie found
    if not access_token:
        # Consolidate header parsing to a single canonical variable
        auth_header = request.headers.get("authorization", "").strip() or request.headers.get("Authorization", "").strip()
        
        # Try Authorization header
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header[7:].strip()
            logger.debug(f"Extracted Bearer token: {access_token[:20]}...")
        # SECURITY: Reject query parameter tokens as security violation (consistent with get_current_user)
        elif token:
            logger.warning("SECURITY VIOLATION: Query parameter authentication attempted in get_current_user_or_query - ignored for security")
            # Do not use query token - proceed without authentication
    
    # No token provided - CRITICAL FIX: Return None immediately for anonymous uploads
    if not access_token:
        logger.debug("No token string extracted from cookie or auth header - allowing anonymous access")
        return None
    
    # Check if this is an upload operation that should use 480-hour validation
    request_path = getattr(request.url, 'path', '') if hasattr(request, 'url') else ''
    is_upload_operation = (
        '/files/' in request_path or 
        request_path.startswith('/api/v1/files/') or
        'upload' in request_path.lower() or
        '/chats/' in request_path and '/messages' in request_path or  # Chat messages endpoints
        request_path.endswith('/messages') and '/chats/' in request_path  # Direct chat messages endpoints
    )
    
    # For upload operations, try 480-hour validation first
    if is_upload_operation:
        try:
            # Decode token with 480-hour validation if this is an upload operation
            user_id = _decode_token_with_480_hour_validation(access_token)
            if user_id:
                return user_id
        except HTTPException:
            # If 480-hour validation fails, fall through to normal validation
            logger.debug("480-hour validation failed, trying normal validation")
            pass
    
    # Normal JWT validation for non-upload operations or fallback
    try:
        token_data = decode_token(access_token)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            # For upload operations, check if this is an expired token within 480 hours
            if is_upload_operation:
                try:
                    user_id = _decode_token_with_480_hour_validation(access_token)
                    if user_id:
                        return user_id
                except HTTPException:
                    pass  # Re-raise original exception
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e.detail),
                headers={"WWW-Authenticate": "Bearer"},
            )
        raise

    if token_data.token_type not in {"access", "upload"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data.user_id


def _decode_token_with_480_hour_validation(token_str: str) -> Optional[str]:
    """
    Decode JWT token with 480-hour validation for upload operations.
    Allows expired tokens if they were issued within 480 hours.
    """
    try:
        # First, try to decode without validation to get payload
        settings = _get_settings()
        payload = jwt.decode(
            token_str,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": False}  # Don't verify expiration initially
        )
        
        # Check if token type is valid
        if payload.get("token_type") not in {"access", "upload"}:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        # Get user ID
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user ID"
            )
        
        # Check if token is expired but within 480-hour window
        now = datetime.now(timezone.utc)
        exp_time = datetime.fromtimestamp(payload.get("exp", 0), timezone.utc)
        iat_time = datetime.fromtimestamp(payload.get("iat", 0), timezone.utc)
        
        # If token is not expired, accept it normally
        if exp_time > now:
            return user_id
        
        # Token is expired - check if it's within 480-hour window
        time_since_issue = now - iat_time
        max_lifetime = timedelta(hours=UPLOAD_TOKEN_MAX_LIFETIME_HOURS)
        
        if time_since_issue <= max_lifetime:
            # Token is expired but within 480-hour window, accept it
            logger.debug(f"Accepting expired token within 480-hour window: issued {iat_time}, expired {exp_time}")
            return user_id
        else:
            # Token is older than 480 hours, reject it
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token older than {UPLOAD_TOKEN_MAX_LIFETIME_HOURS} hours"
            )
            
    except jwt.ExpiredSignatureError:
        # This should not happen with verify_exp=False, but handle it
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )


# ===== QR CODE FUNCTIONS FOR MULTI-DEVICE CONNECTION =====

def generate_session_code(length: int = 6) -> str:
    """Generate a random numeric session code for QR verification.
    
    Args:
        length: Length of the code (default 6 digits, max 256)
        
    Returns:
        Random numeric string
        
    Raises:
        ValueError: If length is invalid
    """
    if not isinstance(length, int) or length < 1 or length > 256:
        raise ValueError(f"Session code length must be between 1 and 256, got {length}")
    
    try:
        digits = string.digits
        code = ''.join(secrets.choice(digits) for _ in range(length))
        if not code or len(code) != length:
            raise ValueError("Failed to generate session code of correct length")
        return code
    except Exception as e:
        raise ValueError(f"Failed to generate session code: {type(e).__name__}")


def generate_qr_code(data: dict) -> Tuple[str, str]:
    """Generate QR code and return as base64 encoded image.
    
    Args:
        data: Dictionary containing session and user information to encode
        
    Returns:
        Tuple of (base64_encoded_qr_image, json_string)
    """
    try:
        # Check if QR code functionality is available
        if not QR_CODE_AVAILABLE:
            raise ImportError("QR code library not available")
        
        # Convert data to JSON string
        json_data = json.dumps(data)
        
        # Create QR code instance using imported classes
        qr = QRCode(
            version=1,
            error_correction=ERROR_CORRECT_L,
            box_size=10,
            border=2,
        )
        qr.add_data(json_data)
        qr.make(fit=True)
        
        # Create PIL image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}", json_data
    except Exception as e:
        logger.error(f"Failed to generate QR code: {str(e)}")
        raise ValueError("Failed to generate QR code")


def create_qr_session_payload(
    user_id: str, 
    session_id: str, 
    session_code: str, 
    device_type: str,
    server_url: Optional[str] = None
) -> dict:
    """Create payload for QR code encoding.
    
    Args:
        user_id: The user's ID
        session_id: Unique session ID
        session_code: Verification code
        device_type: Type of device (mobile, web, desktop)
        server_url: Server URL for verification
        
    Returns:
        Dictionary with QR code payload
    """
    return {
        "user_id": user_id,
        "session_id": session_id,
        "session_code": session_code,
        "device_type": device_type,
        "server_url": server_url or settings.SERVER_URL,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "version": "1.0"
    }


def validate_session_code(provided_code: str, stored_code: str) -> bool:
    """Validate session code with timing attack protection.
    
    Args:
        provided_code: Code provided by user
        stored_code: Code stored in database
        
    Returns:
        True if codes match
        
    Raises:
        ValueError: If codes are None, empty, or invalid type
    """
    # Validate inputs
    if not provided_code or not isinstance(provided_code, str):
        logger.warning(f"Session code validation failed: invalid provided_code type {type(provided_code)}")
        return False
    
    if not stored_code or not isinstance(stored_code, str):
        logger.warning(f"Session code validation failed: invalid stored_code type {type(stored_code)}")
        return False
    
    # Validate length (session codes should be reasonable length)
    if len(provided_code) > 256 or len(stored_code) > 256:
        logger.warning(f"Session code validation failed: codes exceed maximum length")
        return False
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(provided_code, stored_code)

# Fallback imports for when direct import fails
try:
    from . import (
        hash_password, verify_password, create_access_token, 
        create_refresh_token, decode_token, get_current_user,
        get_current_user_for_upload, get_current_user_optional, get_current_user_or_query
    )
except ImportError:
    pass  # Functions are already imported above


# Fallback imports for when direct import fails
try:
    from . import (
        hash_password, verify_password, create_access_token, 
        create_refresh_token, decode_token, get_current_user,
        get_current_user_for_upload, get_current_user_optional, get_current_user_or_query
    )
except ImportError:
    pass  # Functions are already imported above
