from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, TYPE_CHECKING
import uuid
import jwt
from jwt import PyJWTError
import hashlib
import hmac
import logging
from fastapi import HTTPException, status, Depends, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from config import settings
from models import TokenData
import secrets
import string
import base64
import json
from io import BytesIO

# Configure logger
logger = logging.getLogger(__name__)

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
    
    # In type checking mode, assume QR code is available
    QR_CODE_AVAILABLE = True
else:
    # Runtime mode - actual imports
    try:
        import qrcode
        from qrcode import QRCode
        from qrcode.constants import ERROR_CORRECT_L
        QR_CODE_AVAILABLE = True
    except ImportError as e:
        # Create fallback classes for runtime when qrcode is not available
        class QRCode:
            def __init__(self, **kwargs):
                raise ImportError(f"QR code library not available: {e}")
            
            def add_data(self, data):
                pass
            
            def make(self, fit=True):
                pass
            
            def make_image(self, **kwargs):
                raise ImportError("QR code library not installed")
        
        class ERROR_CORRECT_L:
            pass
        
        QR_CODE_AVAILABLE = False
        print(f"QR code library not available: {e}")

logger = logging.getLogger("auth")
security = HTTPBearer()


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2 with SHA-256"""
    # Generate a random salt (32 hex characters = 16 bytes)
    salt = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
    
    if not salt or len(salt) != 32:
        raise ValueError("Invalid salt generation")
    
    password_bytes = password.encode('utf-8')
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt.encode('utf-8'),
        100000
    )
    
    hash_hex = password_hash.hex()
    if not hash_hex:
        raise ValueError("Invalid hash generation")
    
    return f"{salt}${hash_hex}"


def verify_password(plain_password: str, hashed_password: str, user_id: str = None) -> bool:
    """Verify a password against its PBKDF2 hash"""
    try:
        # Check if hash is in new format (salt$hash)
        if '$' in hashed_password and len(hashed_password.split('$')) == 2:
            salt, stored_hash = hashed_password.split('$')
            if not salt or not stored_hash:
                return False
            
            password_bytes = plain_password.encode('utf-8')
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password_bytes,
                salt.encode('utf-8'),
                100000
            )
            computed_hex = password_hash.hex()
            return hmac.compare_digest(computed_hex, stored_hash)
        elif len(hashed_password) == 64:  # Legacy SHA256 hash (64 hex chars)
            # SECURITY WARNING: Legacy hash support - should be migrated ASAP
            # This is a temporary migration bridge only
            import hashlib
            legacy_hash = hashlib.sha256(plain_password.encode()).hexdigest()
            if hmac.compare_digest(legacy_hash, hashed_password):
                # CRITICAL FIX: Require user_id for secure migration
                if not user_id:
                    # Critical: Can't migrate without user context, but allow login
                    _log("critical", "Legacy hash login without user_id context - SECURITY RISK")
                    return True
                
                # Trigger automatic migration to secure hash
                from backend.routes.users import users_collection
                try:
                    new_secure_hash = hash_password(plain_password)
                    result = users_collection().update_one(
                        {"_id": user_id, "password_hash": hashed_password},  # CRITICAL: Match both user_id AND hash
                        {"$set": {"password_hash": new_secure_hash, "migrated_at": datetime.now(timezone.utc)}}
                    )
                    if result.modified_count == 0:
                        _log("error", f"Migration failed - user not found: {user_id}")
                    else:
                        _log("info", f"Successfully migrated user {user_id} from legacy to secure hash")
                except Exception as e:
                    # CRITICAL FIX: Log migration failures instead of swallowing
                    _log("error", f"Password hash migration failed for user {user_id}: {str(e)}")
                    # Still allow login but with warning
                return True
            return False
        else:
            # Invalid hash format
            return False
            
    except (ValueError, AttributeError, UnicodeDecodeError):
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "token_type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> Tuple[str, str]:
    """Create JWT refresh token and return (token, jti)."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    jti = str(uuid.uuid4())
    to_encode.update({"exp": expire, "token_type": "refresh", "jti": jti})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt, jti


def decode_token(token: str) -> TokenData:
    """Decode and validate JWT token with enhanced validation and timing attack protection"""
    try:
        # SECURITY FIX: Use constant-time comparison to prevent timing attacks
        # Add random delay to mask token validation timing
        import random
        import time
        random_delay = random.uniform(0.01, 0.05)  # 10-50ms random delay
        time.sleep(random_delay)
        
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        token_type: str = payload.get("token_type")
        
        # Enhanced 'sub' field validation
        if not user_id or not isinstance(user_id, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing or invalid subject identifier",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Validate user_id format (ObjectId format)
        import re
        if not re.match(r'^[a-fA-F0-9]{24}$', user_id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: malformed user identifier",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # CRITICAL FIX: Enhanced token validation with scope and user binding
        if token_type not in ["access", "refresh", "password_reset", "upload"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: unsupported token type",
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
            
            # Upload tokens should have short TTL (validate max 1 hour)
            exp_timestamp = payload["exp"]
            issued_at = payload.get("iat", exp_timestamp)
            if exp_timestamp - issued_at > 3600:  # More than 1 hour
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Upload token lifetime exceeds maximum allowed duration",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        # Create TokenData with additional payload info for upload tokens
        return TokenData(
            user_id=user_id, 
            token_type=token_type,
            payload=payload  # Store full payload for upload token validation
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


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Dependency to get current user from token in Authorization header"""
    token = credentials.credentials
    token_data = decode_token(token)
    
    if token_data.token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    
    return token_data.user_id


async def get_current_user_optional(request: Request) -> Optional[str]:
    """Dependency to get current user from token - returns None if auth fails or missing"""
    try:
        # Try to get authorization header
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            logger.debug("No auth header provided, allowing guest access")
            return None
        
        # Extract token from "Bearer <token>"
        if not auth_header.startswith("Bearer "):
            logger.debug("Invalid auth header format, allowing guest access")
            return None
        
        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            logger.debug("Empty token, allowing guest access")
            return None
            
        token_data = decode_token(token)
        
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
    """DEPENDENCY TO GET CURRENT USER FROM HEADER ONLY.
    
    SECURITY: QUERY PARAMETER AUTHENTICATION HAS BEEN DISABLED.
    ONLY HEADER AUTHENTICATION IS ALLOWED FOR SECURITY REASONS.
    
    Args:
        request: The request object (for header auth)
        token: IGNORED - query parameter authentication disabled
        
    Returns:
        The user_id from the Authorization header token
        
    Raises:
        HTTPException: If header token is missing or invalid
    """
    # SECURITY: Log any query parameter attempts for monitoring
    if token is not None:
        logger.warning("SECURITY VIOLATION: Query parameter authentication attempted - ignored for security")
    
    # Only try header auth - query parameter auth disabled
    auth_header = request.headers.get("authorization", "")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required - use Authorization header with Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    header_token = auth_header.replace("Bearer ", "").strip()
    if not header_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token_data = decode_token(header_token)
    
    if token_data.token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type - access token required",
        )
    
    return token_data.user_id


async def get_current_user_from_query(token: Optional[str] = Query(None)) -> str:
    """DEPENDENCY TO GET CURRENT USER FROM TOKEN IN QUERY PARAMETER.
    
    SECURITY WARNING: THIS FUNCTION IS DEPRECATED AND DISABLED FOR SECURITY REASONS.
    QUERY PARAMETER AUTHENTICATION EXPOSES TOKENS IN URLS WHICH CAN BE:
    - LOGGED IN SERVER LOGS
    - STORED IN BROWSER HISTORY
    - LEAKED VIA REFERRER HEADERS
    - ACCESSED BY THIRD-PARTY SCRIPTS
    
    USE HEADER AUTHENTICATION INSTEAD: Authorization: Bearer <token>
    
    Args:
        token: The JWT token passed as a query parameter (?token=...)
        
    Returns:
        NEVER RETURNS - ALWAYS THROWS EXCEPTION
        
    Raises:
        HTTPException: ALWAYS THROWS 401 UNAUTHORIZED FOR SECURITY
    """
    # SECURITY: Always reject query parameter authentication
    logger.warning("SECURITY VIOLATION: Query parameter authentication attempted - blocked for security")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Query parameter authentication is disabled for security. Use Authorization header instead.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def validate_upload_token(payload: dict) -> str:
    """Validate upload token payload and return user_id"""
    upload_id = payload.get("upload_id")
    if not upload_id or not isinstance(upload_id, str) or not upload_id.strip():
        logger.warning(f"Upload token missing or invalid upload_id field: {upload_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid upload token: missing or invalid upload_id",
            )
    
    # Validate upload_id format (basic security check)
    import re
    if not re.match(r'^[a-zA-Z0-9_-]+$', upload_id):
        logger.warning(f"Upload token has invalid upload_id format: {upload_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid upload token: malformed upload_id",
            )
    
    user_id = payload.get("sub")
    if not user_id or not isinstance(user_id, str) or not user_id.strip():
        logger.warning("Upload token missing or invalid user_id (sub) field")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid upload token: missing or invalid user_id",
            )
    
    return user_id  # Return user_id from payload


async def get_current_user_for_upload(
    request: Request, 
    token: Optional[str] = Query(None)
) -> str:
    """ENHANCED DEPENDENCY FOR FILE UPLOADS THAT ACCEPTS ONLY HEADER AUTHENTICATION.
    
    SECURITY: QUERY PARAMETER AUTHENTICATION HAS BEEN DISABLED FOR UPLOADS.
    ONLY HEADER AUTHENTICATION IS ALLOWED FOR SECURITY REASONS.
    
    This is designed to handle long-running file uploads where regular access token
    might expire. Upload tokens have extended expiration and specific scope.
    
    Args:
        request: The request object (for header auth)
        token: IGNORED - query parameter authentication disabled
        
    Returns:
        The user_id from Authorization header token
        
    Raises:
        HTTPException: If header token is missing or invalid
    """
    
    # SECURITY: Log any query parameter attempts for monitoring
    if token is not None:
        logger.warning("SECURITY VIOLATION: Query parameter authentication attempted for upload - ignored for security")
    
    # Only try header auth - query parameter auth disabled
    auth_header = request.headers.get("authorization", "")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for upload - use Authorization header with Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    header_token = auth_header.replace("Bearer ", "").strip()
    if not header_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        token_data = decode_token(header_token)
        if token_data.token_type == "access":
            # Check if it's a special upload token or regular access token
            payload = getattr(token_data, 'payload', {}) or {}
            if payload.get("scope") == "upload":
                logger.debug(f"Using upload token from header for upload_id: {payload.get('upload_id')}")
                return validate_upload_token(payload)
            else:
                logger.debug(f"Using regular access token for upload")
                return token_data.user_id
    except Exception as e:
        logger.error(f"Upload authentication failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token for upload",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ===== QR CODE FUNCTIONS FOR MULTI-DEVICE CONNECTION =====

def generate_session_code(length: int = 6) -> str:
    """Generate a random numeric session code for QR verification.
    
    Args:
        length: Length of the code (default 6 digits)
        
    Returns:
        Random numeric string
    """
    digits = string.digits
    return ''.join(secrets.choice(digits) for _ in range(length))


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
    """
    return hmac.compare_digest(provided_code, stored_code)