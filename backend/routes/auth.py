from fastapi import APIRouter, HTTPException, status, Depends, Request
from models import (
    UserCreate, UserLogin, Token, RefreshTokenRequest, UserResponse,
    ForgotPasswordRequest, PasswordResetRequest, PasswordResetResponse,
    QRCodeRequest, QRCodeResponse, VerifyQRCodeRequest, VerifyQRCodeResponse,
    QRCodeSession
)
from db_proxy import users_collection, refresh_tokens_collection, reset_tokens_collection
from auth.utils import (
    hash_password, verify_password, create_access_token, 
    create_refresh_token, decode_token, get_current_user, get_current_user_from_query,
    generate_session_code, generate_qr_code, create_qr_session_payload, validate_session_code
)
from config import settings
from rate_limiter import auth_rate_limiter, password_reset_limiter, qr_code_limiter
from validators import validate_user_id, safe_object_id_conversion
from datetime import datetime, timedelta, timezone
from bson import ObjectId
import asyncio
import jwt
import smtplib
from email.message import EmailMessage
from collections import defaultdict
from typing import Dict, Tuple, List
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Email rate limiting tracking
email_rate_limits: Dict[str, List[datetime]] = defaultdict(list)
email_daily_limits: Dict[str, datetime] = defaultdict(datetime)

# Login attempt tracking
login_attempts: Dict[str, List[datetime]] = defaultdict(list)
failed_login_attempts: Dict[str, Tuple[int, datetime]] = {}

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

def _get_email_troubleshooting_recommendations(email_service_status: str, email_error: str | None) -> list:
    """Get comprehensive troubleshooting recommendations for email issues."""
    recommendations = []
    
    if email_service_status == "not_configured":
        recommendations.extend([
            "Server Issue: Email service not configured",
            "Contact server administrator to set up email service",
            "Required settings: SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM",
            "Test configuration: POST /auth/test-email (DEBUG mode only)",
            "Fallback: In DEBUG mode, check debug info for reset token"
        ])
    elif email_service_status == "failed":
        recommendations.extend([
            "Email Service Configuration Issue",
            "Check server logs for detailed error information",
            "Test email service: POST /auth/test-email",
            "Verify network connectivity to SMTP server",
            "Check firewall rules for outbound SMTP connections (ports 25, 465, 587)",
            "Verify SMTP credentials are correct"
            "This is a SERVER CONFIGURATION issue, not user error"
        ])
        
        # Specific error-based recommendations
        if email_error:
            error_lower = email_error.lower()
            if "authentication" in error_lower:
                recommendations.extend([
                    "SMTP Authentication failed",
                    "Check SMTP_USERNAME and SMTP_PASSWORD are correct",
                    "For Gmail: Generate App Password at security.google.com",
                    "Enable 2-factor authentication on email account",
                    "Ensure 'Less secure app access' is enabled"
                ])
            elif "connection" in error_lower:
                recommendations.extend([
                    "Network connectivity issue",
                    "Check internet connection",
                    "Check if firewall is blocking SMTP connections",
                    "Verify SMTP_HOST and SMTP_PORT are correct"
                ])
            elif "tls" in error_lower:
                recommendations.extend([
                    "TLS configuration issue",
                    "Check SMTP_USE_TLS setting matches server requirements",
                    "Try with TLS enabled or disabled based on server"
                ])
            elif "timeout" in error_lower:
                recommendations.extend([
                    "Connection timeout",
                    "Check network latency",
                    "Try closer SMTP server or improve network"
                ])
            else:
                recommendations.extend([
                    "Unknown error",
                    "Check all SMTP configuration",
                    "Review server logs for detailed error information"
                ])
    else:
        recommendations.extend([
            "Email service is working correctly",
            "Check recipient email address for typos",
            "Check ALL email folders: Inbox, Spam, Junk, Promotions, Social, Updates",
            "Wait 2-5 minutes for email delivery",
            "Verify email is not blocked by recipient's email provider",
            "Check email service status: POST /auth/test-email"
        ])
    
    # Always add general troubleshooting steps
    recommendations.extend([
        "Test email service: POST /auth/test-email (DEBUG mode only)",
        "Verify all environment variables are set correctly",
        "Restart backend after configuration changes",
        "Check email provider SMTP documentation"
    ])
    
    return recommendations

def cleanup_old_login_attempts() -> None:
    """Clean up old login attempts and email rate limit entries."""
    current_time = datetime.now(timezone.utc)
    cutoff_time = current_time - timedelta(hours=24)
    
    # Clean up login attempts
    for email in list(login_attempts.keys()):
        login_attempts[email] = [
            timestamp for timestamp in login_attempts[email] 
            if timestamp > cutoff_time
        ]
        if not login_attempts[email]:
            del login_attempts[email]
    
    # Clean up email rate limits
    for email in list(email_rate_limits.keys()):
        email_rate_limits[email] = [
            timestamp for timestamp in email_rate_limits[email] 
            if timestamp > cutoff_time
        ]
        if not email_rate_limits[email]:
            del email_rate_limits[email]
    
    auth_log("Cleaned up old login attempts and email rate limits")

# OPTIONS handlers for CORS preflight requests
@router.options("/register")
@router.options("/login")
@router.options("/refresh")
@router.options("/logout")
@router.options("/forgot-password")
@router.options("/reset-password")
@router.options("/qrcode/generate")
@router.options("/qrcode/verify")
@router.options("/qrcode/status/{session_id}")
@router.options("/qrcode/cancel/{session_id}")
@router.options("/qrcode/sessions")
async def auth_options():
    """Handle CORS preflight for auth endpoints"""
    from fastapi.responses import Response
    # SECURITY: Restrict CORS origins in production for authenticated endpoints
    from config import settings
    
    cors_origin = settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "http://localhost:8000"
    
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": cors_origin,
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400"
        }
    )

# ✅ CORE AUTH FUNCTIONS - Handle user registration and login
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate) -> UserResponse:
    """Register a new user account"""
    try:
        auth_log(f"Registration attempt for email: {user.email}")
        
        # Check if user already exists
        existing_user = await users_collection().find_one({"email": user.email})
        if existing_user:
            auth_log(f"Registration failed: Email already exists: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered. Please login or use a different email."
            )
        
        # Hash password
        password_hash = hash_password(user.password)
        
        # Extract initials from name for avatar
        initials = "".join([word[0].upper() for word in user.name.split() if word])[:2]
        
        # Create user document
        user_doc = {
            "_id": str(ObjectId()),
            "name": user.name,
            "email": user.email,
            "password_hash": password_hash,
            "avatar": initials,
            "avatar_url": None,
            "username": None,
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
        result = await users_collection().insert_one(user_doc)
        auth_log(f"✓ User registered successfully: {user.email} (ID: {result.inserted_id})")
        
        # Create response
        return UserResponse(
            id=str(result.inserted_id),
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
        auth_log(f"❌ Registration error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@router.post("/login", response_model=Token)
async def login(credentials: UserLogin, request: Request) -> Token:
    """Login user and return access/refresh tokens"""
    try:
        auth_log(f"Login attempt for email: {credentials.email}")
        
        # Check rate limit
        client_ip = request.client.host if request and request.client else "unknown"
        auth_log(f"Login from IP: {client_ip}")
        
        # Find user by email
        user = await users_collection().find_one({"email": credentials.email})
        if not user:
            auth_log(f"Login failed: User not found: {credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Verify password
        if not verify_password(credentials.password, user["password_hash"]):
            auth_log(f"Login failed: Invalid password for: {credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Create tokens
        access_token = create_access_token(
            data={"sub": str(user["_id"])},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        refresh_token, jti = create_refresh_token({"sub": str(user["_id"])})
        
        # Store refresh token in database
        await refresh_tokens_collection().insert_one({
            "user_id": str(user["_id"]),
            "jti": jti,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        })
        
        # Update last_seen
        await users_collection().update_one(
            {"_id": user["_id"]},
            {"$set": {
                "last_seen": datetime.now(timezone.utc),
                "is_online": True,
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        
        auth_log(f"✓ Login successful: {credentials.email}")
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"❌ Login error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_request: RefreshTokenRequest) -> Token:
    """Refresh access token using refresh token"""
    try:
        auth_log(f"Token refresh attempt")
        
        # Decode refresh token
        token_data = decode_token(refresh_request.refresh_token)
        user_id = token_data.sub
        
        # Get user
        user = await users_collection().find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        # Create new access token
        access_token = create_access_token(
            data={"sub": user_id},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        auth_log(f"✓ Token refreshed for user: {user_id}")
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_request.refresh_token,
            token_type="bearer"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"❌ Token refresh error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token refresh failed"
        )

@router.post("/logout")
async def logout(current_user: str = Depends(get_current_user)) -> dict:
    """Logout user by invalidating refresh tokens"""
    try:
        auth_log(f"Logout for user: {current_user}")
        
        # Invalidate refresh tokens
        await refresh_tokens_collection().update_many(
            {"user_id": current_user},
            {"$set": {"invalidated": True, "invalidated_at": datetime.now(timezone.utc)}}
        )
        
        # Update user status
        await users_collection().update_one(
            {"_id": ObjectId(current_user)},
            {"$set": {"is_online": False, "updated_at": datetime.now(timezone.utc)}}
        )
        
        auth_log(f"✓ Logout successful for user: {current_user}")
        
        return {"message": "Logged out successfully", "success": True}
        
    except Exception as e:
        auth_log(f"❌ Logout error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )