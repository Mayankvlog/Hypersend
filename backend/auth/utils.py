from datetime import datetime, timedelta
from typing import Optional, Tuple
import uuid
import jwt
from jwt import PyJWTError
import hashlib
import hmac
from fastapi import HTTPException, status, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from config import settings
from models import TokenData

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
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        token_type: str = payload.get("token_type")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
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
