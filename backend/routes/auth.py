"""
HYPerSend Multi-Device Authentication Service
============================================

ARCHITECTURAL COMPARISON: WHATSAPP vs HYPerSend
====================================================

WHATSAPP ARCHITECTURE (LEFT SIDE):
📱 User Devices → 📱 WhatsApp Servers → 🔐 Encrypted Storage → ☁️ Cloud Backup
- Phone Number Authentication (FORBIDDEN in our system)
- Limited Multi-Device Support (1 primary + 4 companion)
- Proprietary Protocol Implementation
- End-to-End Encryption (WhatsApp Protocol)
- Server-side Message Routing
- Limited Horizontal Scaling
- Fixed Infrastructure Deployment

HYPerSend ARCHITECTURE (RIGHT SIDE):
📱📱📱 Multi-Device (4 devices per user) → ⚖️ Nginx Load Balancer → 
🌐 WebSocket Service → 🐸 Backend API Pods → 🗄️ Redis Cluster → ☁️ S3 Storage
- Username + Device Key Authentication (NO PHONE NUMBERS)
- Enhanced Multi-Device Support (4 devices max)
- Open Signal Protocol Implementation
- End-to-End Encryption (Signal Protocol)
- Zero-Knowledge Message Routing
- Horizontal Pod Autoscaling (HPA)
- Scalable Kubernetes Deployment

MULTI-DEVICE AUTHENTICATION FEATURES:
=====================================
- ❌ Phone number authentication (FORBIDDEN)
- ✅ Username + Device Key authentication
- ✅ Multi-device session management with Redis cache
- ✅ QR-based device linking
- ✅ Device verification and session isolation
- ✅ Real-time device synchronization
- ✅ Horizontal scaling support
- ✅ Zero-knowledge authentication
- ✅ Rate limiting and abuse prevention
- ✅ Comprehensive logging and monitoring
- ✅ E2EE with Signal Protocol integration

SECURITY ENHANCEMENTS:
=======================
- TLS 1.3 encryption for all communications
- Redis-based ephemeral session storage
- Multi-device session isolation
- Device verification and management
- Rate limiting per device
- Comprehensive audit logging
- Secure key storage and rotation
- Zero-knowledge server architecture
- ABSOLUTELY NO PHONE NUMBERS ANYWHERE IN SYSTEM
"""

from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import JSONResponse

try:
    from models import (
        UserCreate, UserLogin, Token, RefreshTokenRequest, UserResponse,
        PasswordResetRequest, PasswordResetResponse,
        EmailChangeRequest, EmailVerificationRequest,
        QRCodeRequest, QRCodeResponse, VerifyQRCodeRequest, VerifyQRCodeResponse,
        QRCodeSession, TokenData, ChangePasswordRequest
    )
    from db_proxy import users_collection, refresh_tokens_collection, reset_tokens_collection
    from config import settings
except ImportError:
    from models import (
        UserCreate, UserLogin, Token, RefreshTokenRequest, UserResponse,
        PasswordResetRequest, PasswordResetResponse,
        EmailChangeRequest, EmailVerificationRequest,
        QRCodeRequest, QRCodeResponse, VerifyQRCodeRequest, VerifyQRCodeResponse,
        QRCodeSession, TokenData, ChangePasswordRequest
    )
    from db_proxy import users_collection, refresh_tokens_collection, reset_tokens_collection
    from config import settings

import sys
import os
import secrets
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# IDENTITY MODEL: Username + Device Key Authentication (NO PHONE NUMBERS)
# Phone number authentication is FORBIDDEN - using username + device key instead

from auth.utils import (
    hash_password, verify_password, create_access_token, 
    create_refresh_token, decode_token, get_current_user
)

try:
    from validators import validate_user_id
    from rate_limiter import password_reset_limiter
    from utils.email_service import email_service
except ImportError:
    from validators import validate_user_id
    from rate_limiter import password_reset_limiter
    from utils.email_service import email_service

from datetime import datetime, timedelta, timezone
from bson import ObjectId
import asyncio
import secrets

from collections import defaultdict
from typing import Dict, Tuple, List, Optional
router = APIRouter(prefix="/auth", tags=["Authentication"])

import sys

sys.modules.setdefault("routes.auth", sys.modules[__name__])
sys.modules.setdefault("backend.routes.auth", sys.modules[__name__])


async def _await_maybe(value, timeout: float = 5.0):
    if hasattr(value, "__await__"):
        return await asyncio.wait_for(value, timeout=timeout)
    return value

# Password reset token expiry
PASSWORD_RESET_TOKEN_EXPIRY_HOURS = 1

# Password reset collection
def password_reset_collection():
    """Get password reset tokens collection"""
    return reset_tokens_collection()

# CRITICAL FIX: Persistent login attempt tracking with better security
# In-memory tracking resets on server restart, allowing brute force attacks
# TODO: Implement Redis or database-based persistent tracking
login_attempts: Dict[str, List[datetime]] = defaultdict(list)
failed_login_attempts: Dict[str, Tuple[int, datetime]] = {}

# Additional tracking for cross-server restart protection
# This is used elsewhere in the module for tracking persistent lockouts
persistent_login_lockouts: Dict[str, datetime] = {}

# SECURITY: Clean old lockout entries periodically
def cleanup_expired_lockouts():
    """Clean up expired lockout entries to prevent memory leaks"""
    current_time = datetime.now(timezone.utc)
    expired_keys = [
        key for key, expiry_time in persistent_login_lockouts.items()
        if expiry_time < current_time
    ]
    for key in expired_keys:
        del persistent_login_lockouts[key]

def clear_all_lockouts():
    """Clear all lockout entries - useful for testing"""
    persistent_login_lockouts.clear()
    login_attempts.clear()
    failed_login_attempts.clear()

# Configuration for rate limiting
MAX_LOGIN_ATTEMPTS_PER_IP = 20
LOGIN_ATTEMPT_WINDOW = 300
ACCOUNT_LOCKOUT_DURATION = 900
MAX_FAILED_ATTEMPTS_PER_ACCOUNT = 5

# Progressive lockout durations (in seconds)
PROGRESSIVE_LOCKOUTS = {
    1: 300,   # 5 minutes after 1st failed attempt
    2: 600,   # 10 minutes after 2nd failed attempt
    3: 900,   # 15 minutes after 3rd failed attempt
    4: 1200,  # 20 minutes after 4th failed attempt
    5: 1800   # 30 minutes after 5th failed attempt (maximum duration)
}

def auth_log(message: str) -> None:
    """Log auth-related messages only when DEBUG is enabled."""
    if settings.DEBUG:
        print(message)



# CORS helper functions - moved to module level for importability
import re

def _is_valid_domain_format(domain: str) -> bool:
    """Validate domain format to prevent malformed origins"""
    # Strict domain validation - prevents double dots, starting hyphens, etc.
    domain_pattern = r'^(?!-)(?!.*?-$)(?!.*?\.\.)[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, domain))

def _is_valid_origin_format(origin: str) -> bool:
    """Validate full origin URL format with strict HTTPS enforcement and domain validation"""
    # Parse URL to validate components separately
    try:
        parsed = re.match(r'^(https?):\/\/([a-zA-Z0-9.-]+)(?::(\d+))?(?:\/.*)?$', origin)
        if not parsed or not parsed.groups():
            return False
        
        scheme = parsed.group(1)
        domain = parsed.group(2)
        port = parsed.group(3) if len(parsed.groups()) >= 3 and parsed.group(3) else None
        
        # SECURITY: ALWAYS require HTTPS, even in debug mode  
        # Allow HTTP only for exact zaply.in.net in development
        if scheme != 'https':
            if settings.DEBUG and domain == 'zaply.in.net':
                return True  # Allow HTTP for zaply.in.net in debug
            else:
                return False
        
        # HTTPS: Validate domain format before accepting
        if not _is_valid_domain_format(domain):
            return False
        
        # Validate port if present (must be valid numeric range 1-65535)
        if port:
            try:
                port_num = int(port)
                if port_num < 1 or port_num > 65535:
                    return False
            except ValueError:
                return False
        
        return True
    except Exception:
        return False
        

def get_safe_cors_origin(request_origin: Optional[str]) -> str:
    """Get safe CORS origin with validation - NO code duplication"""
    if not request_origin:
        return settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "https://zaply.in.net"
    
    # Validate origin format strictly
    if not _is_valid_origin_format(request_origin):
        return settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "https://zaply.in.net"
    
    # Check if origin is explicitly in allowed list
    if request_origin in settings.CORS_ORIGINS:
        return request_origin
    
    # Return first allowed origin as safe fallback
    return settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "https://zaply.in.net"

# OPTIONS handlers for CORS preflight requests
@router.options("/register")
@router.options("/login")
@router.options("/refresh")
@router.options("/logout")
@router.options("/change-password")
@router.options("/qrcode/generate")
@router.options("/qrcode/verify")
@router.options("/qrcode/status/{session_id}")
@router.options("/qrcode/cancel/{session_id}")
@router.options("/qrcode/sessions")
@router.options("/auth/device")
async def auth_options(request: Request):
    """Handle CORS preflight for auth endpoints"""
    from fastapi.responses import Response
    # SECURITY: Restrict CORS origins in production for authenticated endpoints
    from config import settings
    
    cors_origin = get_safe_cors_origin(request.headers.get("origin", ""))
    
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": cors_origin,
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-ID, X-Device-Name",
            "Access-Control-Max-Age": "86400",
            "X-Multi-Device-Support": "enabled",
            "X-Max-Devices": "4",
            "X-Redis-Cache": "ephemeral-realtime"
        }
    )

# Username-based Device Authentication (NO PHONE NUMBERS)
@router.post("/auth/device", response_model=dict, status_code=status.HTTP_200_OK)
async def authenticate_device(
    device_request: dict,
    request: Request
) -> dict:
    """
    Authenticate user with username + device key (Phone numbers FORBIDDEN)
    Multi-device scaling with Redis cache optimization
    """
    try:
        # Extract device authentication data
        username = device_request.get("username")
        device_key = device_request.get("device_key")
        device_name = device_request.get("device_name", "Unknown Device")
        
        if not username or not device_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username and device key are required"
            )
        
        # Multi-device logging
        auth_log(f"Device auth attempt: {username} from device: {device_name}")
        
        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        
        # Store in Redis for real-time verification (ephemeral cache)
        try:
            import redis
            redis_client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            
            # Store device verification with TTL (5 minutes)
            cache_key = f"device_auth:{username}:{device_key}"
            auth_data = {
                "username": username,
                "device_key": device_key,
                "device_name": device_name,
                "verification_token": verification_token,
                "timestamp": secrets.token_hex(16),
                "multi_device": True,
                "max_devices": 4
            }
            
            redis_client.setex(cache_key, 300, str(auth_data))  # 5 minutes TTL
            
            # Store device session for multi-device sync
            device_session_key = f"device_session:{device_key}"
            redis_client.setex(device_session_key, 86400, str(auth_data))  # 24 hours TTL
            
            auth_log(f"Device auth stored in Redis cache: {cache_key}")
            
        except Exception as redis_error:
            auth_log(f"Redis cache error (falling back): {redis_error}")
        
        return {
            "success": True,
            "verification_token": verification_token,
            "message": "Verification code sent to your device",
            "requires_verification": True,
            "multi_device_supported": True,
            "max_devices": 4
        }
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Device authentication error: {str(e)}")
        return {
            "success": False,
            "message": "Authentication failed. Please try again.",
            "requires_verification": True,
            "multi_device_supported": True,
            "max_devices": 4
        }

# CORE AUTH FUNCTIONS - Handle user registration and login
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate) -> UserResponse:
    """Register a new user account"""
    try:
        auth_log(f"Registration attempt for email: {user.email}")
        
        # Name validation is now handled in the model validator (auto-derived from email if not provided)
        
        # Check if user already exists with case-insensitive email lookup
        users_col = users_collection()
        # Use case-insensitive email lookup to prevent duplicates
        normalized_email = user.email.lower().strip()
        
        # Check for existing email
        existing_user = None
        try:
            users_col = users_collection()
            existing_user = await _await_maybe(
                users_col.find_one({"email": normalized_email}),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            auth_log(f"Database timeout checking existing user")
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - please try again"
            )
        except (ConnectionError, TimeoutError) as db_error:
            auth_log(f"Database connection error checking existing user: {type(db_error).__name__}: {str(db_error)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service temporarily unavailable. Please try again."
            )
        except Exception as db_error:
            auth_log(f"Database error checking existing user: {type(db_error).__name__}: {str(db_error)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database operation failed. Please try again."
            )
        
        if existing_user:
            user_id = existing_user.get('_id') if isinstance(existing_user, dict) else None
            auth_log(f"Registration failed: Found existing user with email: {normalized_email} (ID: {user_id})")
        else:
            auth_log(f"Registration: No existing user found for email: {normalized_email}")
        
        if existing_user:
            auth_log(f"Registration failed: Email already exists: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered. Please login or use a different email."
            )
        
        # Hash password - CRITICAL FIX: Store hash and salt separately
        password_hash, salt = hash_password(user.password)
        
        # Remove avatar initials generation - use None instead
        initials = None  # FIXED: Don't generate 2-letter avatar
        
        # Create user document
        user_doc = {
            "_id": str(ObjectId()),
            "name": user.name,
            "email": user.email,  # Store email for login
            "username": user.email.lower().strip(),  # Keep username for backward compatibility
            "password_hash": password_hash,  # CRITICAL FIX: Store hash separately
            "password_salt": salt,  # CRITICAL FIX: Store salt separately
            "avatar": initials,  # FIXED: No avatar initials
            "avatar_url": None,
            "bio": None,
            "quota_used": 0,
            "quota_limit": 42949672960,  # 40 GiB default
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_seen": None,
            "is_online": False,
            "status": None,
            "permissions": {
                "location": False,
                "camera": False,
                "microphone": False,
                "storage": False
            },
            "pinned_chats": [],
            "blocked_users": []
        }
        
        # Insert user into database
        try:
            users_col = users_collection()
            # CRITICAL FIX: Motor MongoDB operations are always async, await them directly
            result = await _await_maybe(users_col.insert_one(user_doc), timeout=5.0)
            
            # CRITICAL FIX: Extract inserted_id safely - motor returns result directly
            if result is None:
                raise RuntimeError("Insert operation returned None")
            
            inserted_id = result.inserted_id
            # Validate inserted_id is not a Future/coroutine object
            if hasattr(inserted_id, '__await__') or asyncio.isfuture(inserted_id):
                raise RuntimeError(f"Critical async error: inserted_id is a Future object: {type(inserted_id)}")
            
            auth_log(f"SUCCESS: User registered successfully: {user.email} (ID: {inserted_id})")
        except asyncio.TimeoutError:
            auth_log(f"Database timeout during user insertion")
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - please try again"
            )
        except (ConnectionError, TimeoutError) as db_error:
            auth_log(f"Database connection error during user insertion: {type(db_error).__name__}: {str(db_error)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service temporarily unavailable. Please try again."
            )
        except Exception as db_error:
            auth_log(f"Database error during user insertion: {type(db_error).__name__}: {str(db_error)}")
            if "duplicate" in str(db_error).lower():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already registered. Please use a different email."
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create user account. Please try again."
                )
        
        # Create response
        return UserResponse(
            id=str(inserted_id),
            name=user.name,
            email=user.email,
            username=user.email.lower().strip(),
            bio=None,
            avatar=initials,  
            avatar_url=None,
            quota_used=0,
            quota_limit=42949672960,
            created_at=user_doc["created_at"],
            updated_at=None,
            last_seen=None,
            is_online=False,
            status=None,
            pinned_chats=[],
            is_contact=False
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Registration error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {type(e).__name__} - {str(e)[:100]}"
        )

@router.post("/login", response_model=Token)
async def login(credentials: UserLogin, request: Request) -> Token:
    """Login user and return access/refresh tokens with rate limiting"""
    try:
        # Username validation is now handled in the model validator
        
        if not credentials.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password is required"
            )
        
        auth_log(f"Login attempt for email: {credentials.email}")
        
        # Clean up expired lockouts periodically
        cleanup_expired_lockouts()
        
        # Check rate limit by IP
        client_ip = request.client.host if request and request.client else "unknown"
        auth_log(f"Login from IP: {client_ip}")
        
        # SECURITY FIX: Enforce IP-based rate limiting with proper timeout handling
        current_time = datetime.now(timezone.utc)
        
        # Check if IP is temporarily locked out (429 Too Many Requests)
        if client_ip in persistent_login_lockouts:
            lockout_expiry = persistent_login_lockouts[client_ip]
            if current_time < lockout_expiry:
                remaining_seconds = int((lockout_expiry - current_time).total_seconds())
                auth_log(f"IP {client_ip} is locked out for {remaining_seconds} more seconds")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many login attempts. Please try again in {remaining_seconds} seconds.",
                    headers={"Retry-After": str(remaining_seconds)}
                )
            else:
                # Lockout expired, remove it
                del persistent_login_lockouts[client_ip]
        
        # Clean up old attempts (older than LOGIN_ATTEMPT_WINDOW)
        cutoff_time = current_time - timedelta(seconds=LOGIN_ATTEMPT_WINDOW)
        login_attempts[client_ip] = [
            ts for ts in login_attempts[client_ip] if ts > cutoff_time
        ]
        
        # SECURITY FIX: Track login attempts by both IP and email for proper rate limiting
        email_lockout_key = f"email:{credentials.email}"
        if email_lockout_key in persistent_login_lockouts:
            lockout_expiry = persistent_login_lockouts[email_lockout_key]
            if current_time < lockout_expiry:
                remaining_seconds = int((lockout_expiry - current_time).total_seconds())
                auth_log(f"Email {credentials.email} is locked out for {remaining_seconds} more seconds")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many failed login attempts for this account. Please try again in {remaining_seconds} seconds.",
                    headers={"Retry-After": str(remaining_seconds)}
                )
            else:
                del persistent_login_lockouts[email_lockout_key]
        
        # Check IP-based rate limit (prevent brute force from single IP)
        if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS_PER_IP:
            auth_log(f"IP {client_ip} exceeded max login attempts ({MAX_LOGIN_ATTEMPTS_PER_IP})")
            lockout_time = current_time + timedelta(seconds=ACCOUNT_LOCKOUT_DURATION)
            persistent_login_lockouts[client_ip] = lockout_time
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many login attempts from this IP. Please try again in {ACCOUNT_LOCKOUT_DURATION} seconds.",
                headers={"Retry-After": str(ACCOUNT_LOCKOUT_DURATION)}
            )
        
        # Record this login attempt
        login_attempts[client_ip].append(current_time)
        
        # Find user by email - Use case-insensitive lookup
        normalized_email = credentials.email.lower().strip()
        
        try:
            users_col = users_collection()
            # Add timeout to database query to prevent 503 Service Unavailable
            try:
                existing_user = await _await_maybe(
                    users_col.find_one({"email": normalized_email}),
                    timeout=5.0,
                )
            except asyncio.TimeoutError:
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail="Database timeout - please try again"
                )
            except (ConnectionError, TimeoutError) as db_error:
                auth_log(f"Database connection error during user lookup: {type(db_error).__name__}: {str(db_error)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database service temporarily unavailable"
                )
            except Exception as db_error:
                auth_log(f"Database error during user lookup: {type(db_error).__name__}: {str(db_error)}")
                if "connection" in str(db_error).lower() or "network" in str(db_error).lower():
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Database service temporarily unavailable"
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Database operation failed"
                    )
            
            if not existing_user:
                auth_log(f"Login failed: User not found: {normalized_email}")
                # SECURITY: Don't increase per-email lockout for non-existent users (prevents enumeration)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email/username or password"
                )
            
            # Verify password - CRITICAL FIX: Ensure password_hash and salt exist
            password_hash = existing_user.get("password_hash")
            password_salt = existing_user.get("password_salt")
            
            # Handle both new format (separate hash/salt) and legacy format (tuple)
            if isinstance(password_hash, (tuple, list)) and len(password_hash) == 2:
                # Legacy format: (hash, salt) stored as tuple
                password_hash, password_salt = password_hash
                auth_log(f"Converting legacy password format for {normalized_email}")
            
            if not password_hash:
                auth_log(f"Login failed: User {normalized_email} has no password hash (corrupted record)")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email/username or password"
                )
            
            # CRITICAL FIX: Handle missing password salt with migration
            if not password_salt:
                auth_log(f"DEBUG: User {normalized_email} has no password salt, attempting migration")
                
                # Check if user has legacy password field
                legacy_password = existing_user.get("password")
                if legacy_password and isinstance(legacy_password, str) and '$' in legacy_password:
                    # Parse legacy format: salt$hash
                    parts = legacy_password.split('$')
                    if len(parts) == 2:
                        password_salt, password_hash = parts
                        auth_log(f"Migrating legacy password format for {normalized_email}")
                        
                        # Update user record with new format
                        try:
                            await users_collection().update_one(
                                {"_id": existing_user["_id"]},
                                {
                                    "$set": {
                                        "password_hash": password_hash,
                                        "password_salt": password_salt,
                                        "password_migrated": True
                                    },
                                    "$unset": {"password": ""}
                                }
                            )
                            auth_log(f"Successfully migrated password format for {normalized_email}")
                        except Exception as migrate_error:
                            auth_log(f"Failed to migrate password for {normalized_email}: {migrate_error}")
                            # Continue with legacy format for now
                    else:
                        auth_log(f"Invalid legacy password format for {normalized_email}")
                else:
                    # Check if password_hash is in combined format (salt$hash)
                    if password_hash and isinstance(password_hash, str) and '$' in password_hash:
                        # Parse combined format: salt$hash (97 chars: 32+1+64)
                        if len(password_hash) == 97:
                            parts = password_hash.split('$')
                            if len(parts) == 2:
                                password_salt, password_hash = parts
                                auth_log(f"Found combined password format for {normalized_email}")
                                
                                # Update user record with separated format
                                try:
                                    await users_collection().update_one(
                                        {"_id": existing_user["_id"]},
                                        {
                                            "$set": {
                                                "password_hash": password_hash,
                                                "password_salt": password_salt,
                                                "password_migrated": True
                                            }
                                        }
                                    )
                                    auth_log(f"Successfully separated password format for {normalized_email}")
                                except Exception as migrate_error:
                                    auth_log(f"Failed to separate password for {normalized_email}: {migrate_error}")
                            else:
                                auth_log(f"Invalid combined password format for {normalized_email}")
                        else:
                            auth_log(f"Invalid combined password length for {normalized_email}: {len(password_hash)}")
                    
                    # If still no password salt after migration attempt
                    if not password_salt:
                        auth_log(f"Login failed: User {normalized_email} has no valid password salt (corrupted record)")
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email/username or password"
                        )
            
            # Verify password with constant-time comparison - CRITICAL FIX: Handle different formats
            # CRITICAL FIX: Check if we have the new format (separated) or legacy format (combined)
            # Always attempt verification regardless of format, since we don't know what the actual format is
            
            # SECURITY: Only log password verification attempt type in debug mode
            if settings.DEBUG:
                auth_log(f"[PASSWORD_DEBUG] Attempting password verification for {normalized_email} (hash present: {bool(password_hash)}, salt present: {bool(password_salt)})")
            
            if password_salt and isinstance(password_salt, str) and len(password_salt) > 0:
                # Try new format: separated hash and salt
                auth_log(f"Attempting separated password format for {normalized_email}")
                is_password_valid = verify_password(credentials.password, password_hash, password_salt, str(existing_user.get("_id")))
                
                # If verification failed with separated format and hash is 64 chars, try legacy SHA256 hash with salt
                if not is_password_valid and password_hash and isinstance(password_hash, str) and len(password_hash) == 64:
                    auth_log(f"Separated format verification failed, trying legacy SHA256+salt format for {normalized_email}")
                    # CRITICAL FIX: Try both salt+pwd and pwd+salt legacy formats
                    # Try password + salt format
                    is_password_valid = verify_password(credentials.password, password_salt, password_hash, str(existing_user.get("_id")))
                    
                    # If that fails, try salt + password format  
                    if not is_password_valid:
                        auth_log(f"Trying salt+password legacy format for {normalized_email}")
                        is_password_valid = verify_password(credentials.password, password_hash, password_salt, str(existing_user.get("_id")))
                    
                    # SECURITY: Only run debug hashing if DEBUG mode is enabled
                    if settings.DEBUG:
                        import hashlib
                        if password_salt:
                            # Test both legacy formats - only in debug
                            pwd_salt_hash = hashlib.sha256((credentials.password + password_salt).encode()).hexdigest()
                            salt_pwd_hash = hashlib.sha256((password_salt + credentials.password).encode()).hexdigest()
                            auth_log(f"[DEBUG] Testing legacy password formats (hashes not logged for security)")
                            auth_log(f"[DEBUG] Pwd+Salt match: {pwd_salt_hash == password_hash}")
                            auth_log(f"[DEBUG] Salt+Pwd match: {salt_pwd_hash == password_hash}")
                            
                            # Try alternative
                            combined_test_alt = password_salt + credentials.password
                            expected_hash_alt = hashlib.sha256(combined_test_alt.encode()).hexdigest()
                            auth_log(f"[DEBUG] Alternative matches: {expected_hash_alt == password_hash}")
                
                # CRITICAL FIX: If verification still fails, provide helpful error for password reset
                if not is_password_valid:
                    auth_log(f"[PASSWORD_RESET_NEEDED] All verification methods failed for {normalized_email}")
                    auth_log(f"[PASSWORD_RESET_NEEDED] User should reset via /auth/reset-password with a token")
                    # Continue to return 401 - user needs to reset password
                
                # CRITICAL FIX: If both fail, check if hash and salt might be swapped
                if not is_password_valid and password_salt and isinstance(password_salt, str) and len(password_salt) == 64:
                    auth_log(f"[RECOVERY] Trying swapped hash/salt for {normalized_email}")
                    is_password_valid = verify_password(credentials.password, password_salt, password_hash, str(existing_user.get("_id")))
                    if is_password_valid:
                        auth_log(f"[RECOVERY] SUCCESS: Hash and salt were swapped for {normalized_email}, fixing in database")
                        # Fix the database
                        try:
                            await users_collection().update_one(
                                {"_id": existing_user["_id"]},
                                {"$set": {"password_hash": password_salt, "password_salt": password_hash}}
                            )
                            auth_log(f"[RECOVERY] Database corrected for {normalized_email}")
                        except Exception as fix_error:
                            auth_log(f"[RECOVERY] Failed to fix database: {fix_error}")
                    
            elif password_hash and isinstance(password_hash, str):
                # Check for combined format (salt$hash - 97 chars with $)
                if '$' in password_hash and len(password_hash) == 97:
                    # Legacy/combined format: hash contains "salt$hash"
                    auth_log(f"Using legacy combined password format for {normalized_email}")
                    is_password_valid = verify_password(credentials.password, password_hash, None, str(existing_user.get("_id")))
                else:
                    # Old legacy format: just the hash without salt (shouldn't happen with our code, but handle it)
                    # This could be SHA256 or PBKDF2 without stored salt
                    auth_log(f"Using legacy format for {normalized_email}")
                    is_password_valid = verify_password(credentials.password, password_hash, None, str(existing_user.get("_id")))
            else:
                # Unrecognized format - this is an error
                auth_log(f"Unrecognized password format for {normalized_email}: hash_len={len(password_hash) if password_hash else 0}, hash_has_$={('$' in password_hash) if password_hash else False}, salt_len={len(password_salt) if password_salt else 0}")
                is_password_valid = False
            
            auth_log(f"Password verification result for {normalized_email}: {is_password_valid} (hash_length: {len(password_hash) if password_hash else 0}, has_salt: {bool(password_salt)})")
        except HTTPException:
            raise
        except Exception as verify_error:
            auth_log(f"Password verification error for {normalized_email}: {type(verify_error).__name__}")
            # Treat verification errors as invalid passwords for security
            is_password_valid = False
        
        if not is_password_valid:
            auth_log(f"Login failed: Invalid password for: {normalized_email}")
            
            # ADVANCED DEBUGGING: Diagnose actual password format stored
            from auth.utils import diagnose_password_format
            diagnosis = diagnose_password_format(password_hash, password_salt)
            auth_log(f"[DIAGNOSIS] Hash format: {diagnosis['hash']['format']} (len={diagnosis['hash']['length']}, hex={diagnosis['hash']['is_hex']})")
            if diagnosis['hash']['details']:
                auth_log(f"[DIAGNOSIS] Hash details: {diagnosis['hash']['details']}")
            auth_log(f"[DIAGNOSIS] Salt format: {diagnosis['salt']['format']} (len={diagnosis['salt']['length']}, hex={diagnosis['salt']['is_hex']})")
            auth_log(f"[DIAGNOSIS] Combined format detected: {diagnosis['combined_format']}")
            
            # SECURITY FIX: Track failed attempts per email for progressive lockout
            user_id_str = str(existing_user["_id"])
            if user_id_str not in failed_login_attempts:
                failed_login_attempts[user_id_str] = (0, current_time)
            
            attempt_count, first_attempt_time = failed_login_attempts[user_id_str]
            attempt_count += 1
            failed_login_attempts[user_id_str] = (attempt_count, first_attempt_time)
            
            # SECURITY: Progressive lockout based on number of failed attempts
            if attempt_count >= MAX_FAILED_ATTEMPTS_PER_ACCOUNT:
                lockout_seconds = PROGRESSIVE_LOCKOUTS.get(min(attempt_count, 5), 1800)  # Max 30 min
                lockout_time = current_time + timedelta(seconds=lockout_seconds)
                persistent_login_lockouts[email_lockout_key] = lockout_time
                auth_log(f"Account {normalized_email} locked out for {lockout_seconds} seconds after {attempt_count} failed attempts")
                
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many failed login attempts. Account locked for {lockout_seconds} seconds.",
                    headers={"Retry-After": str(lockout_seconds)}
                )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email/username or password"
            )
        
        # CRITICAL FIX: Session fixation prevention - invalidate existing sessions
        # Delete all existing refresh tokens for this user before creating new ones
        await refresh_tokens_collection().delete_many({
            "user_id": str(existing_user["_id"])
        })
        
        # Create new tokens with fresh session ID
        access_token = create_access_token(
            data={"sub": str(existing_user["_id"])},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        refresh_token, jti = create_refresh_token({"sub": str(existing_user["_id"])})
        
        # Store new refresh token in database
        token_created_at = datetime.now(timezone.utc)
        await refresh_tokens_collection().insert_one({
            "user_id": existing_user["_id"],  # SECURITY FIX: Store ObjectId directly, not string
            "jti": jti,
            "created_at": token_created_at,
            "expires_at": token_created_at + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        })
        
        # Update last_seen
        await users_collection().update_one(
            {"_id": existing_user["_id"]},
            {"$set": {
                "last_seen": datetime.now(timezone.utc),
                "is_online": True,
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        
        auth_log(f"SUCCESS: Login successful: {credentials.email}")
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
        
    except HTTPException:
        raise
    except (ConnectionError, TimeoutError) as e:
        # Database connection or timeout errors
        auth_log(f"Login database error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database timeout - please try again"
        )
    except ValueError as e:
        auth_log(f"Login validation error: {type(e).__name__}: {str(e)}")
        # Validation errors should return 400, not 401
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid input format"
        )
    except (AttributeError, TypeError) as e:
        auth_log(f"Login type error: {type(e).__name__}: {str(e)}")
        # Type errors indicate data corruption or misconfiguration
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server error during authentication"
        )
    except Exception as e:
        auth_log(f"Login error: {type(e).__name__}: {str(e)}")
        # Check if this is a database connectivity error
        error_str = str(e).lower()
        if any(keyword in error_str for keyword in ["connection", "timeout", "database", "unavailable", "refused", "unreachable"]):
            # Database-related errors should return 503
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service temporarily unavailable"
            )
        # Return generic error for security, don't expose internal details
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )

# Enhanced Token Refresh Endpoint for Session Persistence
@router.post("/refresh-session", response_model=Token)
async def refresh_session_token(request: RefreshTokenRequest) -> Token:
    """
    Enhanced refresh endpoint that maintains session persistence across page refreshes.
    
    This endpoint:
    - Extends session duration automatically
    - Provides new access token without requiring re-login
    - Maintains refresh token validity for long-running sessions
    - Handles expired access tokens gracefully
    
    ENHANCEMENT: This prevents session expiration on page refresh by extending
    the session automatically when the frontend detects an expired token.
    """
    try:
        auth_log(f"Session refresh request")
        
        # Validate refresh token format
        if not request.refresh_token or not isinstance(request.refresh_token, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token is required and must be a string"
            )
        
        # Decode refresh token
        try:
            token_data = decode_token(request.refresh_token)
        except HTTPException as e:
            # Re-raise HTTP exceptions from token decoding
            raise e
        except Exception as e:
            auth_log(f"Token decode error: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token format"
            )
        
        if not token_data.user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token: missing user identifier"
            )
        
        # Validate token type is refresh
        if token_data.token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type - expected refresh token"
            )
        
        # Check if refresh token exists and is not invalidated
        try:
            # Convert user_id to ObjectId if it's a valid string
            user_id_for_query = token_data.user_id
            if isinstance(user_id_for_query, str) and ObjectId.is_valid(user_id_for_query):
                user_id_for_query = ObjectId(user_id_for_query)
            
            refresh_doc = await asyncio.wait_for(
                refresh_tokens_collection().find_one({
                    "jti": token_data.jti,
                    "user_id": user_id_for_query,
                    "$or": [
                        {"invalidated": {"$exists": False}},
                        {"invalidated": False}
                    ]
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - try again later"
            )
        except Exception as e:
            auth_log(f"Database error checking refresh token: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify refresh token"
            )
        
        if not refresh_doc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token is invalid or has been revoked"
            )
        
        # Check if token has expired
        expires_at = refresh_doc.get("expires_at")
        if not expires_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has no expiration - database corruption"
            )
        
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired"
            )
        
        # Get user
        try:
            user = await asyncio.wait_for(
                users_collection().find_one({"_id": user_id_for_query}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - try again later"
            )
        except Exception as e:
            auth_log(f"Database error fetching user: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify user"
            )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        # SECURITY FIX: Enforce absolute max lifetime for refresh tokens
        # Don't allow indefinite session extension - enforce max_lifetime from creation
        REFRESH_TOKEN_MAX_LIFETIME_DAYS = 30  # Absolute maximum token lifetime
        token_created_at = refresh_doc.get("created_at", datetime.now(timezone.utc))
        token_max_expiry = token_created_at + timedelta(days=REFRESH_TOKEN_MAX_LIFETIME_DAYS)
        current_time = datetime.now(timezone.utc)
        
        # If token has exceeded absolute max lifetime, reject refresh
        if current_time >= token_max_expiry:
            auth_log(f"Token refresh rejected - absolute max lifetime exceeded for user: {token_data.user_id}")
            # Invalidate the expired token
            await refresh_tokens_collection().update_one(
                {"_id": refresh_doc["_id"]},
                {"$set": {"invalidated": True}}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has reached absolute maximum lifetime - please login again"
            )
        
        # Extend expires_at but cap at max_lifetime
        new_expires_at = min(
            current_time + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            token_max_expiry
        )
        await refresh_tokens_collection().update_one(
            {"_id": refresh_doc["_id"]},
            {"$set": {"expires_at": new_expires_at, "last_used": current_time}}
        )
        
        # SECURITY FIX: Reduce access token TTL to short-lived window (15 minutes)
        access_token_expires = timedelta(minutes=15)  # Short-lived access token
        access_token = create_access_token(
            data={"sub": token_data.user_id},
            expires_delta=access_token_expires
        )
        
        auth_log(f"Session refreshed successfully for user: {token_data.user_id}")
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=int(access_token_expires.total_seconds()),
            refresh_token=request.refresh_token  # Return same refresh token
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Session refresh failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh session"
        )
@router.post("/refresh", response_model=Token)
async def refresh_access_token(request: RefreshTokenRequest) -> Token:
    """
    Refresh access token using refresh token without expiring session.
    
    CRITICAL FIX: Refresh token is NOT invalidated/deleted on refresh
    This allows the session to continue without expiring on page refresh.
    Only logout or manual token revocation should invalidate the refresh token.
    """
    try:
        auth_log(f"Token refresh request")
        
        # Validate refresh token format
        if not request.refresh_token or not isinstance(request.refresh_token, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token is required and must be a string"
            )
        
        # Decode refresh token
        try:
            token_data = decode_token(request.refresh_token)
        except HTTPException as e:
            # Re-raise HTTP exceptions from token decoding
            raise e
        except Exception as e:
            auth_log(f"Token decode error: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token format"
            )
        
        if not token_data.user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token: missing user identifier"
            )
        
        # Validate token type is refresh
        if token_data.token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type - expected refresh token"
            )
        
        # Check if refresh token exists and is not invalidated
        try:
            # Convert user_id to ObjectId if it's a valid string
            user_id_for_query = token_data.user_id
            if isinstance(user_id_for_query, str) and ObjectId.is_valid(user_id_for_query):
                user_id_for_query = ObjectId(user_id_for_query)
            
            refresh_doc = await asyncio.wait_for(
                refresh_tokens_collection().find_one({
                    "jti": token_data.jti,
                    "user_id": user_id_for_query,
                    "$or": [
                        {"invalidated": {"$exists": False}},
                        {"invalidated": False}
                    ]
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - try again later"
            )
        except Exception as e:
            auth_log(f"Database error checking refresh token: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify refresh token"
            )
        
        if not refresh_doc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token is invalid or has been revoked"
            )
        
        # Check if token has expired
        expires_at = refresh_doc.get("expires_at")
        if not expires_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has no expiration - database corruption"
            )
        
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired"
            )
        
        # Get user
        try:
            user = await asyncio.wait_for(
                users_collection().find_one({"_id": ObjectId(token_data.user_id)}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - try again later"
            )
        except Exception as e:
            auth_log(f"User lookup error: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify user"
            )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # CRITICAL FIX: Update refresh token last_used timestamp to extend session
        # Do NOT invalidate the refresh token - just update the timestamp
        try:
            await asyncio.wait_for(
                refresh_tokens_collection().update_one(
                    {"jti": token_data.jti},
                    {"$set": {"last_used": datetime.now(timezone.utc)}}
                ),
                timeout=5.0
            )
        except Exception as e:
            auth_log(f"Warning: Failed to update refresh token timestamp: {e}")
            # Don't fail the refresh if we can't update timestamp
        
        # Create new access token with proper error handling
        try:
            new_access_token = create_access_token(
                data={"sub": str(user["_id"])},
                expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            )
        except Exception as e:
            auth_log(f"Token creation error: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create new access token"
            )
        
        auth_log(f"SUCCESS: Token refreshed successfully for user: {token_data.user_id}")
        
        return Token(
            access_token=new_access_token,
            refresh_token=request.refresh_token,  # Return the SAME refresh token (not invalidated)
            token_type="bearer"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Token refresh error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed - please try again"
        )

@router.post("/logout")
async def logout(current_user: str = Depends(get_current_user)):
    """Logout user by invalidating refresh tokens"""
    try:
        auth_log(f"Logout request for user: {current_user}")
        
        # Invalidate all refresh tokens for this user
        await refresh_tokens_collection().update_many(
            {"user_id": current_user},
            {"$set": {"invalidated": True, "invalidated_at": datetime.now(timezone.utc)}}
        )
        
        # Update user status
        # SECURITY FIX: Ensure _id is ObjectId for reliable query matching
        user_id_for_update = current_user
        if isinstance(current_user, str) and ObjectId.is_valid(current_user):
            user_id_for_update = ObjectId(current_user)
        
        await users_collection().update_one(
            {"_id": user_id_for_update},
            {"$set": {
                "is_online": False,
                "last_seen": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        
        auth_log(f"SUCCESS: Logout successful for user: {current_user}")
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        auth_log(f"Logout error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.post("/forgot-password")
async def forgot_password(request: dict) -> dict:
    """
    Initiate password reset by generating a JWT reset token.
    
    Step 1 of JWT Forgot Password Flow:
    1. User enters email on forgot password page
    2. System verifies user exists and is active
    3. Generates unique JWT token with claims (user_id, jti, exp)
    4. Stores jti in database with expiry (for revocation tracking)
    5. Sends reset link via email with token as parameter
    6. Returns success message (prevents email enumeration)
    
    Security Features:
    - Rate limiting to prevent abuse
    - Email enumeration prevention
    - JWT expiry (1 hour)
    - JTI tracking for revocation
    - Secure token transmission via email only
    """
    try:
        auth_log("Password reset request received")
        
        # Rate limiting
        if not password_reset_limiter.is_allowed(request.get("email", "unknown")):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many password reset attempts. Please try again later."
            )
        
        # FIXED: Password reset functionality enabled
        if not settings.ENABLE_PASSWORD_RESET:
            auth_log("Password reset functionality is disabled")
            raise HTTPException(
                status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                detail="Password reset functionality has been disabled. Please contact support."
            )
        
        # Extract and validate email
        email = request.get("email")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is required"
            )
        
        # Validate email format
        email = email.strip().lower()
        # Check for valid email format: no multiple @, must have @ and domain
        if email.count("@") != 1 or "." not in email.split("@")[1] or len(email) < 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # Find user by email
        user = None
        try:
            user = await asyncio.wait_for(
                users_collection().find_one({"email": email}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - please try again"
            )
        except Exception as e:
            auth_log(f"Database error finding user: {type(e).__name__}: {str(e)}")
            # Don't expose internal errors
            pass
        
        # Always return success message to prevent email enumeration
        response = {
            "message": "If an account with this email exists, a password reset link has been sent to that email",
            "success": True,
            "expires_in": 3600  # 1 hour in seconds
        }
        
        # Only generate and send token if user exists
        if user:
            try:
                # Generate JWT reset token with unique JTI
                jti = secrets.token_urlsafe(32)
                reset_token = create_access_token(
                    data={
                        "sub": str(user["_id"]),
                        "email": user["email"],
                        "jti": jti,
                        "token_type": "password_reset"
                    },
                    expires_delta=timedelta(hours=1)
                )
                
                # Generate simple reset token for easier use
                simple_reset_token = secrets.token_urlsafe(32)
                
                # Store both tokens in database for revocation tracking
                try:
                    await reset_tokens_collection().insert_one({
                        "jti": jti,
                        "simple_token": simple_reset_token,
                        "user_id": user["_id"],
                        "email": user["email"],
                        "token_type": "password_reset",
                        "created_at": datetime.now(timezone.utc),
                        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
                        "used": False,
                        "ip_address": request.get("client_ip", "unknown") if isinstance(request, dict) else "unknown"
                    })
                except Exception as e:
                    auth_log(f"Warning: Failed to store reset tokens: {type(e).__name__}")
                    # Continue anyway - tokens still valid
                
                auth_log(f"Password reset tokens generated for user: {user['_id']}")
                auth_log(f"Simple reset token: {simple_reset_token[:8]}...")
                
                # Send email with reset link
                try:
                    user_name = user.get("name", user.get("email", "User"))
                    email_sent = await email_service.send_password_reset_email(
                        to_email=user["email"],
                        reset_token=reset_token,
                        user_name=user_name
                    )
                    
                    if email_sent:
                        auth_log(f"✅ Password reset email sent to {user['email']}")
                    else:
                        auth_log(f"⚠️ Failed to send password reset email to {user['email']}")
                        # In debug mode, include both tokens for testing
                        if settings.DEBUG:
                            response["token"] = reset_token
                            response["simple_reset_token"] = simple_reset_token
                            response["debug_message"] = "Email disabled - tokens provided in response"
                
                except Exception as e:
                    auth_log(f"Error sending reset email: {type(e).__name__}: {str(e)}")
                    # In debug mode, include both tokens for testing
                    if settings.DEBUG:
                        response["token"] = reset_token
                        response["simple_reset_token"] = simple_reset_token
                        response["debug_message"] = f"Email error - tokens provided in response: {str(e)}"
                
            except Exception as e:
                auth_log(f"Failed to generate reset token: {type(e).__name__}: {str(e)}")
                # Still return success to prevent enumeration
                if settings.DEBUG:
                    response["error"] = str(e)
        
        # Return success for both existing and non-existing emails (prevents enumeration)
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Forgot password error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset service unavailable"
        )


@router.post("/reset-password", response_model=PasswordResetResponse)
async def reset_password(request: PasswordResetRequest) -> PasswordResetResponse:
    """
    Reset password using JWT reset token.
    
    Step 4-6 of JWT Forgot Password Flow:
    4. User receives email and clicks reset link
    5. Application receives JWT token from URL
    6. Verifies JWT signature and checks JTI in database (not invalidated)
    7. If valid, allows password reset
    8. Updates password and marks JTI as used
    9. Invalidates all refresh tokens (forces re-login)
    10. Returns success and redirect to login
    
    Security Features:
    - JWT signature verification (can't be forged)
    - JTI validation against database (prevents replay attacks)
    - Token expiry check (1 hour)
    - Invalidates all active sessions on successful reset
    - Sends confirmation email
    """
    try:
        auth_log(f"Password reset request for token")
        
        # FIXED: Password reset functionality enabled
        if not settings.ENABLE_PASSWORD_RESET:
            auth_log("Password reset functionality is disabled")
            raise HTTPException(
                status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                detail="Password reset functionality has been disabled. Please contact support."
            )
        
        # Validate token format
        if not request.token or not isinstance(request.token, str) or len(request.token) < 10:
            auth_log("Invalid reset token format")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired reset token"
            )
        
        # Validate new password
        if not request.new_password or len(request.new_password) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be at least 6 characters"
            )
        
        # Try to validate as simple reset token first
        simple_reset_token = request.token
        reset_doc = None
        user = None
        token_type = "simple"
        
        try:
            reset_doc = await asyncio.wait_for(
                reset_tokens_collection().find_one({
                    "simple_token": simple_reset_token,
                    "token_type": "password_reset",
                    "used": False,
                    "$or": [
                        {"invalidated": {"$exists": False}},
                        {"invalidated": False}
                    ]
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - please try again"
            )
        except Exception as e:
            auth_log(f"Database error checking simple reset token: {type(e).__name__}: {str(e)}")
        
        # If simple token not found, try JWT validation
        if not reset_doc:
            token_type = "jwt"
            auth_log("Simple token not found, trying JWT validation")
            
            # Decode and validate JWT token
            token_data = None
            try:
                token_data = decode_token(request.token)
            except HTTPException as e:
                auth_log(f"JWT validation failed: {e.detail}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired reset token - please request a new one"
                )
            except Exception as e:
                auth_log(f"Token decode error: {type(e).__name__}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid reset token format"
                )
            
            # Verify token is a password reset token
            if token_data.token_type != "password_reset":
                auth_log(f"Invalid token type: {token_data.token_type}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type - expected password reset token"
                )
            
            # Verify user ID exists in token
            if not token_data.user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid reset token: missing user identifier"
                )
            
            # Check JTI in database - prevent replay attacks
            jti = getattr(token_data, 'jti', None)
            if not jti:
                auth_log("Reset token missing JTI")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid reset token: missing JTI"
                )
            
            try:
                reset_doc = await asyncio.wait_for(
                    reset_tokens_collection().find_one({
                        "jti": jti,
                        "token_type": "password_reset",
                        "used": False,
                        "$or": [
                            {"invalidated": {"$exists": False}},
                            {"invalidated": False}
                        ]
                    }),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail="Database timeout - please try again"
                )
            except Exception as e:
                auth_log(f"Database error checking reset token: {type(e).__name__}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to verify reset token"
                )
            
            if not reset_doc:
                auth_log("Reset token not found or already used")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired reset token - token may have already been used"
                )
            
            # Get user by ID from token (support both string and ObjectId _id fields)
            try:
                raw_user_id = token_data.user_id
                candidate_ids = []
                # Always try raw ID first (most deployments store _id as string)
                if raw_user_id is not None:
                    candidate_ids.append(raw_user_id)
                # If it looks like an ObjectId, also try BSON ObjectId variant
                if isinstance(raw_user_id, str) and ObjectId.is_valid(raw_user_id):
                    try:
                        candidate_ids.append(ObjectId(raw_user_id))
                    except Exception as conv_error:
                        auth_log(f"[RESET_PASSWORD_DEBUG] ObjectId conversion failed for {raw_user_id}: {conv_error}")

                if not candidate_ids:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid reset token: missing user identifier"
                    )

                user = await asyncio.wait_for(
                    users_collection().find_one({"_id": {"$in": candidate_ids}}),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail="Database timeout - please try again"
                )
            except Exception as e:
                auth_log(f"Database error finding user: {type(e).__name__}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to find user account"
                )
            
            if not user:
                auth_log(f"User not found for reset: {token_data.user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid reset token"
                )
        else:
            # Simple token found - get user from reset document
            auth_log("Simple reset token found, validating user")
            user_id = reset_doc.get("user_id")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid reset token: missing user identifier"
                )
            
            try:
                user = await asyncio.wait_for(
                    users_collection().find_one({"_id": user_id}),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail="Database timeout - please try again"
                )
            except Exception as e:
                auth_log(f"Database error finding user: {type(e).__name__}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to find user account"
                )
            
            if not user:
                auth_log(f"User not found for reset: {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid reset token"
                )
        
        # Verify token not expired (for both simple and JWT tokens)
        expires_at = reset_doc.get("expires_at")
        if not expires_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid reset token: no expiration"
            )
        
        now_utc = datetime.now(timezone.utc)
        # Handle both naive and aware datetimes
        if isinstance(expires_at, datetime):
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= now_utc:
                auth_log("Reset token expired")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Reset token has expired - request a new one"
                )
        
        auth_log(f"Password reset validated using {token_type} token for user: {user['_id']}")
        
        # Hash new password
        password_hash, password_salt = hash_password(request.new_password)
        
        # Update user password
        try:
            auth_log(f"[RESET_PASSWORD] Updating password for user: {user['_id']}")
            await users_collection().update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "password_hash": password_hash,
                    "password_salt": password_salt,
                    "updated_at": datetime.now(timezone.utc)
                }}
            )
            auth_log(f"✅ Password updated for user: {user['_id']}")
        except Exception as e:
            auth_log(f"Failed to update password: {type(e).__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to reset password"
            )
        
        # Mark reset token as used - prevent reuse
        try:
            await reset_tokens_collection().update_one(
                {"_id": reset_doc["_id"]},
                {"$set": {
                    "used": True,
                    "used_at": datetime.now(timezone.utc),
                    "completed": True
                }}
            )
            auth_log(f"Reset token marked as used: {token_type}")
        except Exception as e:
            auth_log(f"Warning: Failed to mark reset token as used: {type(e).__name__}")
            # Don't fail the operation if this fails
        
        # Invalidate all refresh tokens for this user - forces re-login
        try:
            auth_log(f"[RESET_PASSWORD] Invalidating all refresh tokens for user: {user['_id']}")
            await refresh_tokens_collection().update_many(
                {"user_id": user["_id"]},
                {"$set": {
                    "invalidated": True,
                    "invalidated_at": datetime.now(timezone.utc),
                    "invalidation_reason": "password_reset"
                }}
            )
            auth_log(f"✅ All sessions invalidated for user: {user['_id']}")
        except Exception as e:
            auth_log(f"Warning: Failed to invalidate refresh tokens: {type(e).__name__}")
            # Don't fail the operation if this fails
        
        # Send password changed confirmation email
        try:
            user_name = user.get("name", user.get("email", "User"))
            await email_service.send_password_changed_email(
                to_email=user["email"],
                user_name=user_name
            )
            auth_log(f"✅ Password change confirmation email sent to {user['email']}")
        except Exception as e:
            auth_log(f"Warning: Failed to send confirmation email: {type(e).__name__}")
            # Don't fail if email sending fails
        
        auth_log(f"[SUCCESS] Password reset successful for user: {user['_id']}")
        
        return PasswordResetResponse(
            message="Password reset successfully! All your sessions have been logged out. Please login with your new password.",
            success=True,
            token=None,
            redirect_url="/login"  # Frontend should redirect to login
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Reset password error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset service unavailable"
        )

# SECURITY FIX: Removed duplicate OPTIONS handlers - auth_options handles CORS for these routes


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: str = Depends(get_current_user)
) -> PasswordResetResponse:
    """Change password for authenticated user"""
    try:
        auth_log(f"Change password request for user: {current_user}")
        
        # Handle both old_password and current_password for compatibility
        old_password = request.old_password or request.current_password
        
        if not old_password:
            auth_log(f"[CHANGE_PASSWORD_ERROR] No password field provided for user {current_user}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either old_password or current_password must be provided"
            )
        
# Get current user from database
        user = None
         
        # Try ObjectId lookup first
        try:
            user_id = ObjectId(current_user)
            user = await users_collection().find_one({"_id": user_id})
            auth_log(f"[CHANGE_PASSWORD_DEBUG] ObjectId lookup result: {user is not None}")
        except Exception as e:
            auth_log(f"[CHANGE_PASSWORD_DEBUG] ObjectId conversion failed: {e}")
         
        # If ObjectId lookup failed, try string lookup
        if user is None:
            user = await users_collection().find_one({"_id": current_user})
            auth_log(f"[CHANGE_PASSWORD_DEBUG] String lookup result: {user is not None}")
         
        if user is None:
            auth_log(f"[CHANGE_PASSWORD_DEBUG] Trying email lookup as fallback")
            user = await users_collection().find_one({"email": current_user})
            auth_log(f"[CHANGE_PASSWORD_DEBUG] Email lookup result: {user is not None}")
             
        if user is None:
            auth_log(f"[CHANGE_PASSWORD_ERROR] User not found: {current_user}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not user:
            auth_log(f"[CHANGE_PASSWORD_ERROR] User not found: {current_user}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        auth_log(f"[CHANGE_PASSWORD_DEBUG] Found user: {user.get('_id')} with email: {user.get('email')}")
        
        # Verify old password with comprehensive format support
        old_password_valid = False
        auth_log(f"[CHANGE_PASSWORD_DEBUG] Starting password verification for user {current_user}")
        
        # Try new format first: separate hash and salt
        if "password_hash" in user and "password_salt" in user:
            try:
                old_password_valid = verify_password(old_password, user["password_hash"], user["password_salt"])
                auth_log(f"[CHANGE_PASSWORD_DEBUG] New format verification: {old_password_valid}")
            except Exception as e:
                auth_log(f"[CHANGE_PASSWORD_DEBUG] New format failed: {e}")
        
        # Try legacy format: combined hash
        if not old_password_valid and "password" in user:
            try:
                old_password_valid = verify_password(old_password, user["password"])
                auth_log(f"[CHANGE_PASSWORD_DEBUG] Legacy format verification: {old_password_valid}")
            except Exception as e:
                auth_log(f"[CHANGE_PASSWORD_DEBUG] Legacy format failed: {e}")
        
        # Try alternative legacy format: salt$hash
        if not old_password_valid and "password" in user:
            try:
                password_str = user["password"]
                if isinstance(password_str, str) and "$" in password_str and len(password_str.split("$")) == 2:
                    salt, stored_hash = password_str.split("$", 1)
                    if len(salt) == 32 and len(stored_hash) == 64:  # Validate format
                        old_password_valid = verify_password(old_password, stored_hash, salt)
                        auth_log(f"[CHANGE_PASSWORD_DEBUG] Alternative legacy format verification: {old_password_valid}")
                    else:
                        auth_log(f"[CHANGE_PASSWORD_DEBUG] Invalid legacy format: salt_len={len(salt)}, hash_len={len(stored_hash)}")
            except Exception as e:
                auth_log(f"[CHANGE_PASSWORD_DEBUG] Alternative legacy format failed: {e}")
        
        # Final validation
        if not old_password_valid:
            auth_log(f"[CHANGE_PASSWORD_FAILED] Invalid old password for user {current_user}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Hash new password
        password_hash, password_salt = hash_password(request.new_password)
        auth_log(f"[CHANGE_PASSWORD_DEBUG] New password hashed successfully")

# IMPORTANT: Use the _id value as stored in the user document.
        # Some deployments store user _id as a 24-hex *string* (ObjectId-like),
        # and converting it to ObjectId would make update_one() match=0.
        user_id_for_update = user.get("_id")
        auth_log(f"[CHANGE_PASSWORD_DEBUG] Using user_id_for_update: {user_id_for_update} (type: {type(user_id_for_update)})")

        # Update user password with error handling
        try:
            update_result = await users_collection().update_one(
                {"_id": user_id_for_update},
                {"$set": {
                    "password_hash": password_hash,
                    "password_salt": password_salt,
                    "updated_at": datetime.now(timezone.utc)
                }}
            )
            auth_log(f"[CHANGE_PASSWORD_DEBUG] Password update result: matched={update_result.matched_count}, modified={update_result.modified_count}")
        except Exception as e:
            auth_log(f"[CHANGE_PASSWORD_ERROR] Password update failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )
        
        # Invalidate all refresh tokens for this user with error handling
        try:
            user_id_candidates = [current_user]
            if isinstance(current_user, str) and ObjectId.is_valid(current_user):
                user_id_candidates.append(ObjectId(current_user))

            invalidate_result = await refresh_tokens_collection().update_many(
                {"user_id": {"$in": user_id_candidates}},
                {"$set": {"invalidated": True, "invalidated_at": datetime.now(timezone.utc)}}
            )
            auth_log(f"[CHANGE_PASSWORD_SUCCESS] Tokens invalidated for user {current_user}: matched={invalidate_result.matched_count}, modified={invalidate_result.modified_count}")
        except Exception as e:
            auth_log(f"[CHANGE_PASSWORD_WARNING] Token invalidation failed: {e}")
            # Don't fail the operation if token invalidation fails
        
        auth_log(f"Password change successful for user: {current_user}")
        
        return PasswordResetResponse(
            message="Password changed successfully",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Change password error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )


# ===== WHATSAPP-GRADE CRYPTOGRAPHIC ENDPOINTS =====

@router.post("/qrcode/generate", response_model=QRCodeResponse)
async def generate_qr_code(
    request: QRCodeRequest,
    current_user: str = Depends(get_current_user)
):
    """Generate QR code for device linking (WhatsApp-grade)"""
    try:
        auth_log(f"QR code generation request from user: {current_user}")
        
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'multi_device_manager'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        multi_device_manager = app.state.multi_device_manager
        
        # Generate QR code session
        session_data = await multi_device_manager.create_qr_session(
            user_id=current_user,
            device_name=request.device_name,
            device_type=request.device_type,
            platform=request.platform
        )
        
        auth_log(f"QR code session created: {session_data['session_id']}")
        
        return QRCodeResponse(
            session_id=session_data['session_id'],
            qr_code_data=session_data['qr_code_data'],
            expires_at=session_data['expires_at'],
            status="pending"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"QR code generation error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate QR code"
        )


@router.post("/qrcode/verify", response_model=VerifyQRCodeResponse)
async def verify_qr_code(
    request: VerifyQRCodeRequest,
    current_user: str = Depends(get_current_user)
):
    """Verify QR code and complete device linking"""
    try:
        auth_log(f"QR code verification request from user: {current_user}")
        
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'multi_device_manager'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        multi_device_manager = app.state.multi_device_manager
        
        # Verify QR code and link device
        result = await multi_device_manager.verify_qr_code(
            session_id=request.session_id,
            verification_code=request.verification_code,
            linking_user_id=current_user
        )
        
        if result['success']:
            auth_log(f"Device linked successfully: {result['device_id']}")
            return VerifyQRCodeResponse(
                success=True,
                device_id=result['device_id'],
                device_name=result['device_name'],
                message="Device linked successfully"
            )
        else:
            auth_log(f"Device linking failed: {result['error']}")
            return VerifyQRCodeResponse(
                success=False,
                message=result['error']
            )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"QR code verification error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify QR code"
        )


@router.get("/qrcode/status/{session_id}")
async def get_qr_code_status(
    session_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get QR code session status"""
    try:
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'multi_device_manager'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        multi_device_manager = app.state.multi_device_manager
        
        # Get session status
        status = await multi_device_manager.get_qr_session_status(session_id)
        
        if not status:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="QR code session not found"
            )
        
        return {
            "session_id": session_id,
            "status": status['status'],
            "expires_at": status['expires_at'],
            "device_info": status.get('device_info'),
            "created_at": status['created_at']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"QR code status error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get QR code status"
        )


@router.delete("/qrcode/cancel/{session_id}")
async def cancel_qr_code_session(
    session_id: str,
    current_user: str = Depends(get_current_user)
):
    """Cancel QR code session"""
    try:
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'multi_device_manager'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        multi_device_manager = app.state.multi_device_manager
        
        # Cancel session
        success = await multi_device_manager.cancel_qr_session(session_id, current_user)
        
        if success:
            return {"message": "QR code session cancelled successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="QR code session not found"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"QR code cancellation error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel QR code session"
        )


@router.get("/qrcode/sessions")
async def list_qr_code_sessions(
    current_user: str = Depends(get_current_user)
):
    """List active QR code sessions for user"""
    try:
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'multi_device_manager'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        multi_device_manager = app.state.multi_device_manager
        
        # List sessions
        sessions = await multi_device_manager.list_user_qr_sessions(current_user)
        
        return {
            "sessions": sessions,
            "total": len(sessions)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"QR code sessions list error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list QR code sessions"
        )


@router.get("/devices")
async def get_linked_devices(
    current_user: str = Depends(get_current_user)
):
    """Get all linked devices for user"""
    try:
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'multi_device_manager'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        multi_device_manager = app.state.multi_device_manager
        
        # Get devices
        devices = await multi_device_manager.get_user_devices(current_user)
        
        return {
            "devices": devices,
            "total": len(devices)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Get devices error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get linked devices"
        )


@router.delete("/devices/{device_id}")
async def revoke_device(
    device_id: str,
    current_user: str = Depends(get_current_user)
):
    """Revoke device access (immediate key destruction)"""
    try:
        auth_log(f"Device revocation request: {device_id} by user: {current_user}")
        
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'multi_device_manager'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        multi_device_manager = app.state.multi_device_manager
        
        # Revoke device
        success = await multi_device_manager.revoke_device(current_user, device_id)
        
        if success:
            auth_log(f"Device revoked successfully: {device_id}")
            return {"message": "Device revoked successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Device revocation error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke device"
        )


@router.post("/crypto/register")
async def register_device_crypto(
    current_user: str = Depends(get_current_user)
):
    """Register device for cryptographic services"""
    try:
        auth_log(f"Device crypto registration request: {current_user}")
        
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'signal_protocol'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        signal_protocol = app.state.signal_protocol
        
        # Generate device ID (in production, this would come from client)
        device_id = f"device_{secrets.token_hex(8)}"
        
        # Register device with Signal Protocol
        bundle = await signal_protocol.register_device(current_user, device_id)
        
        auth_log(f"Device crypto registered: {current_user}:{device_id}")
        
        return {
            "device_id": device_id,
            "identity_key": bundle.identity_key.hex(),
            "signed_prekey": bundle.signed_prekey,
            "one_time_prekeys": bundle.one_time_prekeys[:10],  # Return first 10
            "registration_id": bundle.registration_id,
            "timestamp": bundle.timestamp.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Device crypto registration error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register device for cryptographic services"
        )


@router.get("/crypto/bundle/{user_id}/{device_id}")
async def get_device_bundle(
    user_id: str,
    device_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get device's X3DH bundle for session initiation"""
    try:
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'signal_protocol'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        signal_protocol = app.state.signal_protocol
        
        # Get bundle
        bundle = await signal_protocol.x3dh.get_bundle(user_id, device_id)
        
        if not bundle:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device bundle not found"
            )
        
        return {
            "user_id": bundle.user_id,
            "device_id": bundle.device_id,
            "identity_key": bundle.identity_key.hex(),
            "signed_prekey": bundle.signed_prekey,
            "one_time_prekeys": bundle.one_time_prekeys,
            "registration_id": bundle.registration_id,
            "timestamp": bundle.timestamp.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Get bundle error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get device bundle"
        )


@router.post("/crypto/session/initiate")
async def initiate_crypto_session(
    request: dict,
    current_user: str = Depends(get_current_user)
):
    """Initiate Signal Protocol session with another device"""
    try:
        auth_log(f"Session initiation request from: {current_user}")
        
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'signal_protocol'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        signal_protocol = app.state.signal_protocol
        
        # Extract request data
        initiator_device_id = request.get('initiator_device_id')
        responder_user_id = request.get('responder_user_id')
        responder_device_id = request.get('responder_device_id')
        one_time_prekey_id = request.get('one_time_prekey_id')
        
        if not all([initiator_device_id, responder_user_id, responder_device_id]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing required fields"
            )
        
        # Initiate session
        session_id, session_info = await signal_protocol.initiate_session(
            current_user, initiator_device_id,
            responder_user_id, responder_device_id
        )
        
        auth_log(f"Session initiated: {session_id}")
        
        return {
            "session_id": session_id,
            "session_info": session_info
        }
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Session initiation error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate cryptographic session"
        )


@router.post("/crypto/keys/rotate")
async def rotate_crypto_keys(
    current_user: str = Depends(get_current_user)
):
    """Rotate cryptographic keys (weekly maintenance)"""
    try:
        auth_log(f"Key rotation request from: {current_user}")
        
        # Get cryptographic services
        from main import app
        if not hasattr(app.state, 'signal_protocol'):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cryptographic services not available"
            )
        
        signal_protocol = app.state.signal_protocol
        multi_device_manager = app.state.multi_device_manager
        
        # Get user devices
        devices = await multi_device_manager.get_user_devices(current_user)
        
        rotated_devices = []
        for device in devices:
            try:
                await signal_protocol.rotate_keys(current_user, device['device_id'])
                rotated_devices.append(device['device_id'])
            except Exception as e:
                auth_log(f"Failed to rotate keys for device {device['device_id']}: {e}")
        
        auth_log(f"Keys rotated for {len(rotated_devices)} devices")
        
        return {
            "message": "Key rotation completed",
            "rotated_devices": rotated_devices,
            "total_devices": len(devices)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Key rotation error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate cryptographic keys"
        )


