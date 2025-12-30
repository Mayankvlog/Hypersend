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
        logger.warning(f"QR code library not available: {e}")

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


def verify_password(plain_password: str, hashed_password: str) -> bool:
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
    """Decode and validate JWT token with enhanced validation"""
    try:
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
        
        # Validate token type
        if token_type not in ["access", "refresh", "password_reset"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: unsupported token type",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return TokenData(user_id=user_id, token_type=token_type)
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

async def get_current_user_from_query(token: Optional[str] = Query(None)) -> str:
    """Dependency to get current user from token in query parameter.
    
    Args:
        token: The JWT token passed as a query parameter (?token=...)
        
    Returns:
        The user_id from the token
        
    Raises:
        HTTPException: If token is missing, invalid, or of wrong type
    """
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is required in query parameters",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token_data = decode_token(token)
    
    if token_data.token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    
    return token_data.user_id

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