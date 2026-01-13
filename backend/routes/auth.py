from fastapi import APIRouter, HTTPException, status, Depends, Request
from models import (
    UserCreate, UserLogin, Token, RefreshTokenRequest, UserResponse,
    ForgotPasswordRequest, PasswordResetRequest, PasswordResetResponse,
    ChangePasswordRequest,
    QRCodeRequest, QRCodeResponse, VerifyQRCodeRequest, VerifyQRCodeResponse,
    QRCodeSession, TokenData
)
from db_proxy import users_collection, refresh_tokens_collection, reset_tokens_collection
from auth.utils import (
    hash_password, verify_password, create_access_token, 
    create_refresh_token, decode_token, get_current_user
)
from config import settings
from rate_limiter import password_reset_limiter
from validators import validate_user_id
from datetime import datetime, timedelta, timezone
from bson import ObjectId
import asyncio
import smtplib
from email.message import EmailMessage
from collections import defaultdict
from typing import Dict, Tuple, List, Optional
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Email rate limiting tracking
email_rate_limits: Dict[str, List[datetime]] = defaultdict(list)
email_daily_limits: Dict[str, datetime] = defaultdict(datetime)

# CRITICAL FIX: Persistent login attempt tracking with better security
# In-memory tracking resets on server restart, allowing brute force attacks
# TODO: Implement Redis or database-based persistent tracking
login_attempts: Dict[str, List[datetime]] = defaultdict(list)
failed_login_attempts: Dict[str, Tuple[int, datetime]] = {}

# Additional tracking for cross-server restart protection
persistent_login_lockouts: Dict[str, datetime] = {}  # Store in database in production

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
    global persistent_login_lockouts, login_attempts, failed_login_attempts
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

def email_log(message: str) -> None:
    """Log email-related messages with proper formatting."""
    if settings.DEBUG:
        print(f"[EMAIL] {message}")

def check_email_rate_limit(email: str) -> Tuple[bool, str]:
    """Check if email is within rate limits."""
    current_time = datetime.now(timezone.utc)
    
    # Clean up old entries (older than 24 hours)
    cutoff_time = current_time - timedelta(hours=24)
    email_rate_limits[email] = [
        timestamp for timestamp in email_rate_limits[email] 
        if timestamp > cutoff_time
    ]
    
    # Check daily limit
    if len(email_rate_limits[email]) >= settings.EMAIL_RATE_LIMIT_PER_DAY:
        return False, f"Daily email limit reached ({settings.EMAIL_RATE_LIMIT_PER_DAY} emails per day)"
    
    # Check hourly limit
    hour_cutoff = current_time - timedelta(hours=1)
    hourly_count = len([
        timestamp for timestamp in email_rate_limits[email] 
        if timestamp > hour_cutoff
    ])
    
    if hourly_count >= settings.EMAIL_RATE_LIMIT_PER_HOUR:
        return False, f"Hourly email limit reached ({settings.EMAIL_RATE_LIMIT_PER_HOUR} emails per hour)"
    
    # Record this email request
    email_rate_limits[email].append(current_time)
    return True, "Email rate limit OK"

def test_email_service() -> Tuple[bool, str]:
    """Test email service connectivity and configuration with comprehensive validation."""
    if not settings.EMAIL_SERVICE_ENABLED:
        return False, "Email service not configured - check SMTP_* environment variables"
    
    try:
        import smtplib
        from email.message import EmailMessage
        
        email_log(f"Testing SMTP connection to {settings.SMTP_HOST}:{settings.SMTP_PORT}")
        
        # Test DNS resolution
        import socket
        try:
            socket.gethostbyname(settings.SMTP_HOST)
            email_log("DNS resolution successful")
        except socket.gaierror:
            return False, "DNS resolution failed - check hostname"
        
        # Test TCP connection
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as server:
            email_log("TCP connection established")
            
            # Test TLS setup
            if settings.SMTP_USE_TLS:
                try:
                    server.starttls()
                    email_log("TLS started")
                except smtplib.SMTPNotSupportedError:
                    return False, "TLS not supported - try with TLS disabled"
                except Exception:
                    return False, "TLS setup failed - check server configuration"
            else:
                email_log("Unencrypted connection established")
            
            # Test authentication
            if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                try:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    email_log("Authentication successful")
                except smtplib.SMTPAuthenticationError:
                    return False, "Authentication failed - check credentials"
                except Exception:
                    return False, "Login error - check credentials"
            else:
                email_log("No authentication credentials provided")
                return False, "SMTP username and password required"
        
        return True, "Email service test successful - all components working"
    
    except Exception as e:
        return False, f"Email service test failed: {type(e).__name__}: {str(e)}"

# CORS helper functions - moved to module level for importability
import re

def _is_valid_domain_format(domain: str) -> bool:
    """Validate domain format to prevent malformed origins"""
    # Strict domain validation - prevents double dots, starting hyphens, etc.
    domain_pattern = r'^(?!-)(?!.*?-$)(?!.*?\.\.)[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, domain))

def _is_valid_origin_format(origin: str) -> bool:
    """Validate full origin URL format with strict HTTPS enforcement in production"""
    # Parse URL to validate components separately
    try:
        parsed = re.match(r'^(https?):\/\/([a-zA-Z0-9.-]+)(?::(\d+))?(?:\/.*)?$', origin)
        if not parsed or not parsed.groups():
            return False
        
        scheme = parsed.group(1)
        domain = parsed.group(2)
        port = parsed.group(3) if len(parsed.groups()) >= 3 and parsed.group(3) else None
        
        # SECURITY: ALWAYS require HTTPS, even in debug mode  
        # Allow HTTP only for exact localhost in development
        if scheme != 'https':
            if settings.DEBUG and (domain == 'localhost' or domain == '127.0.0.1'):
                return True  # Allow HTTP for localhost in debug
            else:
                return False
        
        # HTTPS is always allowed for valid domains (including localhost)
        return True
    except Exception:
        return False
        

def get_safe_cors_origin(request_origin: Optional[str]) -> str:
    """Get safe CORS origin with validation - NO code duplication"""
    if not request_origin:
        return settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "http://localhost:8000"
    
    # Validate origin format strictly
    if not _is_valid_origin_format(request_origin):
        return settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "http://localhost:8000"
    
    # Check if origin is explicitly in allowed list
    if request_origin in settings.CORS_ORIGINS:
        return request_origin
    
    # Return first allowed origin as safe fallback
    return settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "http://localhost:8000"

# OPTIONS handlers for CORS preflight requests
@router.options("/register")
@router.options("/login")
@router.options("/refresh")
@router.options("/logout")
@router.options("/forgot-password")
@router.options("/reset-password")
@router.options("/change-password")
@router.options("/qrcode/generate")
@router.options("/qrcode/verify")
@router.options("/qrcode/status/{session_id}")
@router.options("/qrcode/cancel/{session_id}")
@router.options("/qrcode/sessions")
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
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400"
        }
    )

# CORE AUTH FUNCTIONS - Handle user registration and login
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate) -> UserResponse:
    """Register a new user account"""
    try:
        auth_log(f"Registration attempt for email: {user.email}")
        
        # Validate email and password with security checks
        import re
        
        # Security: Enhanced email validation to allow localhost
        email_pattern = r'^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost|127\.0\.0\.1)$'
        # Basic validation - allow consecutive dots but check format
        if not re.match(email_pattern, user.email):
            auth_log(f"Invalid email format: {user.email[:50]}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # Password validation is now handled in the model validator
        
        if not user.name or not user.name.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Name is required"
            )
        
        # Check if user already exists with case-insensitive email lookup
        users_col = users_collection()
        # CRITICAL FIX: Use case-insensitive email lookup with regex to prevent duplicates
        # Also normalize email to lowercase for consistent lookup
        normalized_email = user.email.lower().strip()
        
        # SECURITY: Validate email format before database operations
        email_pattern = r'^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost|127\.0\.0\.1)$'
        if not re.match(email_pattern, normalized_email):
            auth_log(f"Registration failed: Invalid email format: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid email format"
            )
        
        # CRITICAL FIX: Fix duplicate database query and handle async properly
        existing_user = None
        try:
            users_col = users_collection()
            # CRITICAL FIX: Motor MongoDB operations are always async, await them directly
            existing_user = await asyncio.wait_for(
                users_col.find_one({"email": normalized_email}),
                timeout=5.0
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
        
        # DEBUG: Log the search result for troubleshooting
        if existing_user:
            # CRITICAL FIX: Check if existing_user is a Future object
            if hasattr(existing_user, '__await__') or asyncio.isfuture(existing_user):
                auth_log(f"CRITICAL ERROR: existing_user is a Future object: {type(existing_user)}")
                raise RuntimeError("Database operation returned Future instead of result")
            
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
        
        # Extract initials from name for avatar
        initials = "".join([word[0].upper() for word in user.name.split() if word])[:2]
        
        # Create user document
        user_doc = {
            "_id": str(ObjectId()),
            "name": user.name,
            "email": user.email.lower().strip(),  # CRITICAL FIX: Store email in lowercase for consistency
            "password_hash": password_hash,  # CRITICAL FIX: Store hash separately
            "password_salt": salt,  # CRITICAL FIX: Store salt separately
            "avatar": initials,
            "avatar_url": None,
            "username": getattr(user, 'username', None),  # Set username if provided
            "bio": None,
            "quota_used": 0,
            "quota_limit": 42949672960,  # 40 GiB default
            "created_at": datetime.now(timezone.utc),
            "updated_at": None,
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
            result = await asyncio.wait_for(
                users_col.insert_one(user_doc),
                timeout=5.0
            )
            
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
            username=None,
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
        # Validate input with security checks
        import re
        
        # Security: Enhanced email validation to allow localhost
        email_pattern = r'^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost|127\.0\.0\.1)$'
        # Basic validation - allow consecutive dots but check format
        if not re.match(email_pattern, credentials.email):
            auth_log(f"Invalid email format in login attempt: {credentials.email[:50]}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
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
        
        # Find user by email - CRITICAL FIX: Use case-insensitive email lookup with proper validation
        import re
        normalized_email = credentials.email.lower().strip()
        
        # SECURITY: Validate email format before database query
        email_pattern = r'^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost|127\.0\.0\.1)$'
        if not re.match(email_pattern, normalized_email):
            auth_log(f"Login failed: Invalid email format: {credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        try:
            users_col = users_collection()
            # CRITICAL FIX: Add timeout to database query to prevent 503 Service Unavailable
            try:
                existing_user = await asyncio.wait_for(
                    users_col.find_one({"email": normalized_email}),
                    timeout=5.0
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
                    detail="Invalid email or password"
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
                    detail="Invalid email or password"
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
                            detail="Invalid email or password"
                        )
            
            # Verify password with constant-time comparison - CRITICAL FIX: Handle different formats
            # CRITICAL FIX: Check if we have the new format (separated) or legacy format (combined)
            # Always attempt verification regardless of format, since we don't know what the actual format is
            
            # DEEP DEBUGGING: Log all password details
            auth_log(f"[PASSWORD_DEBUG] Email: {normalized_email} | Hash type: {type(password_hash).__name__} | Hash len: {len(password_hash) if password_hash else 0} | Salt type: {type(password_salt).__name__} | Salt len: {len(password_salt) if password_salt else 0}")
            if password_hash and isinstance(password_hash, str) and len(password_hash) <= 100:
                auth_log(f"[PASSWORD_DEBUG] Hash value: {password_hash[:50]}..." if len(password_hash) > 50 else f"[PASSWORD_DEBUG] Hash value: {password_hash}")
            if password_salt and isinstance(password_salt, str) and len(password_salt) <= 50:
                auth_log(f"[PASSWORD_DEBUG] Salt value: {password_salt}")
            
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
                    
                    # DEBUG: Log what we're trying to match
                    import hashlib
                    if password_salt:
                        # Test both legacy formats
                        pwd_salt_hash = hashlib.sha256((credentials.password + password_salt).encode()).hexdigest()
                        salt_pwd_hash = hashlib.sha256((password_salt + credentials.password).encode()).hexdigest()
                        auth_log(f"[DEBUG] Expected SHA256(pwd+salt): {pwd_salt_hash[:20]}...")
                        auth_log(f"[DEBUG] Expected SHA256(salt+pwd): {salt_pwd_hash[:20]}...")
                        auth_log(f"[DEBUG] Database hash: {password_hash[:20]}...")
                        auth_log(f"[DEBUG] Pwd+Salt match: {pwd_salt_hash == password_hash}")
                        auth_log(f"[DEBUG] Salt+Pwd match: {salt_pwd_hash == password_hash}")
                        
                        # Try alternative
                        combined_test_alt = password_salt + credentials.password
                        expected_hash_alt = hashlib.sha256(combined_test_alt.encode()).hexdigest()
                        auth_log(f"[DEBUG] Expected SHA256(salt+pwd): {expected_hash_alt[:20]}...")
                        auth_log(f"[DEBUG] Alternative matches: {expected_hash_alt == password_hash}")
                
                # CRITICAL FIX: If verification still fails, provide helpful error for password reset
                if not is_password_valid:
                    auth_log(f"[PASSWORD_RESET_NEEDED] All verification methods failed for {normalized_email}")
                    auth_log(f"[PASSWORD_RESET_NEEDED] User should use forgot-password to reset")
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
                detail="Invalid email or password"
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
        await refresh_tokens_collection().insert_one({
            "user_id": str(existing_user["_id"]),
            "jti": jti,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
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
        
        # ENHANCEMENT: Extend refresh token expiration for session persistence
        new_expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        await refresh_tokens_collection().update_one(
            {"_id": refresh_doc["_id"]},
            {"$set": {"expires_at": new_expires_at, "last_used": datetime.now(timezone.utc)}}
        )
        
        # Create new access token with extended expiration
        access_token_expires = timedelta(hours=480)  # 480 hours for session persistence
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
        await users_collection().update_one(
            {"_id": current_user},
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

# Password Reset Endpoints
@router.post("/forgot-password", response_model=PasswordResetResponse)
async def forgot_password(request: ForgotPasswordRequest) -> PasswordResetResponse:
    """Send password reset email to user"""
    try:
        # Validate email
        if not request.email or '@' not in request.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format. Use format: user@zaply.in.net"
            )
        
        auth_log(f"Password reset request for email: {request.email}")
        
        # Rate limiting check
        if not password_reset_limiter.is_allowed(request.email):
            retry_after = password_reset_limiter.get_retry_after(request.email)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many password reset attempts. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)}
            )
        
        # Find user by email
        user = await users_collection().find_one({"email": request.email})
        if not user:
            # Don't reveal if email exists for security
            auth_log(f"Password reset requested for non-existent email: {request.email}")
            return PasswordResetResponse(
                message="If this email exists, a password reset link has been sent",
                success=True
            )
        
        # Generate reset token
        from auth.utils import create_access_token
        reset_token = create_access_token(
            data={"sub": str(user["_id"]), "token_type": "password_reset"},
            expires_delta=timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES)
        )
        
        # Store reset token in database
        await reset_tokens_collection().insert_one({
            "user_id": str(user["_id"]),
            "token": reset_token,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES),
            "used": False
        })
        
        # Send email (if configured)
        email_sent = False
        email_error = None
        
        if settings.EMAIL_SERVICE_ENABLED:
            try:
                reset_link = f"{settings.API_BASE_URL}/reset-password?token={reset_token}"
                import smtplib
                from email.message import EmailMessage
                
                email_message = EmailMessage()
                email_message["Subject"] = "Password Reset - Zaply"
                email_message["From"] = settings.EMAIL_FROM
                email_message["To"] = request.email
                email_message.set_content(f"""
Hello {user['name']},

You requested a password reset for your Zaply account.

Click the following link to reset your password:
{reset_link}

This link will expire in {settings.PASSWORD_RESET_EXPIRE_MINUTES} minutes.

If you didn't request this, please ignore this email.

Best regards,
Zaply Team
                """)
                
                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                    if settings.SMTP_USE_TLS:
                        server.starttls()
                    if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    server.send_message(email_message)
                
                email_sent = True
                auth_log(f"SUCCESS: Password reset email sent to: {request.email}")
                
            except Exception as e:
                email_error = str(e)
                auth_log(f"Failed to send password reset email: {email_error}")
        else:
            auth_log(f"Email service disabled - password reset token: {reset_token[:50]}...")
        
        # In DEBUG mode, return token in response if email fails
        debug_info = None
        if settings.DEBUG and not email_sent:
            debug_info = {
                "reset_token": reset_token,
                "email_error": email_error,
                "reset_link": f"{settings.API_BASE_URL}/reset-password?token={reset_token}"
            }
        
        return PasswordResetResponse(
            message="Password reset instructions sent to your email" if email_sent else "Password reset initiated (debug mode)",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Password reset error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        )

@router.post("/reset-password", response_model=PasswordResetResponse)
async def reset_password(request: PasswordResetRequest) -> PasswordResetResponse:
    """Reset user password using token"""
    try:
        # Validate token
        token_data = decode_token(request.token)
        if not token_data.user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired reset token"
            )
        
        # Check if token exists and is unused
        reset_doc = await reset_tokens_collection().find_one({
            "token": request.token,
            "user_id": token_data.user_id,
            "used": False
        })
        
        if not reset_doc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired reset token"
            )
        
        # Check if token has expired
        if reset_doc["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Reset token has expired"
            )
        
        # Get user
        # Handle both ObjectId and string IDs for mock database compatibility
        try:
            user_id = ObjectId(token_data.user_id)
        except:
            user_id = token_data.user_id
        
        user = await users_collection().find_one({"_id": user_id})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Hash new password - CRITICAL FIX: Store hash and salt separately
        from auth.utils import hash_password
        password_hash, password_salt = hash_password(request.new_password)
        
        # Update user password
        await users_collection().update_one(
            {"_id": user_id},
            {"$set": {
                "password_hash": password_hash,  # CRITICAL FIX: Store hash separately
                "password_salt": password_salt,  # CRITICAL FIX: Store salt separately
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        
        # Mark token as used
        await reset_tokens_collection().update_one(
            {"token": request.token},
            {"$set": {"used": True, "used_at": datetime.now(timezone.utc)}}
        )
        
        # Invalidate all refresh tokens for this user
        await refresh_tokens_collection().update_many(
            {"user_id": token_data.user_id},
            {"$set": {"invalidated": True, "invalidated_at": datetime.now(timezone.utc)}}
        )
        
        auth_log(f"Password reset successful for user: {token_data.user_id}")
        
        return PasswordResetResponse(
            message="Password reset successfully",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"Password reset error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        )


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
        try:
            user = await users_collection().find_one({"_id": ObjectId(current_user)})
        except Exception as e:
            auth_log(f"[CHANGE_PASSWORD_ERROR] Database query failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database error occurred"
            )
        
        if not user:
            auth_log(f"[CHANGE_PASSWORD_ERROR] User not found: {current_user}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
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
        
        # Update user password with error handling
        try:
            update_result = await users_collection().update_one(
                {"_id": ObjectId(current_user)},
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
            invalidate_result = await refresh_tokens_collection().update_many(
                {"user_id": current_user},
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