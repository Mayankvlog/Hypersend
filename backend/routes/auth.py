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

# Email testing endpoint (DEBUG mode only)
@router.get("/test-email", status_code=status.HTTP_200_OK)
async def test_email_endpoint():
    """Test email service configuration and connectivity (DEBUG mode only)"""
    
    if not settings.DEBUG:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email testing is only available in DEBUG mode"
        )
    
    # Test email service
    test_ok, test_message = test_email_service()
    
    # Get current email configuration
    config_info = {
        "email_service_enabled": settings.EMAIL_SERVICE_ENABLED,
        "smtp_host": settings.SMTP_HOST if settings.DEBUG else None,
        "smtp_port": settings.SMTP_PORT if settings.DEBUG else None,
        "smtp_username": settings.SMTP_USERNAME if settings.DEBUG else None,
        "smtp_use_tls": settings.SMTP_USE_TLS,
        "email_from": settings.EMAIL_FROM if settings.DEBUG else None,
        "rate_limits": {
            "per_hour": settings.EMAIL_RATE_LIMIT_PER_HOUR,
            "per_day": settings.EMAIL_RATE_LIMIT_PER_DAY
        }
    }
    
    # Test sending a test email if service is configured
    test_email_sent = False
    test_email_error = None
    
    if settings.EMAIL_SERVICE_ENABLED and test_ok:
        try:
            import smtplib
            from email.message import EmailMessage
            
            msg = EmailMessage()
            msg["Subject"] = "Zaply - Email Service Test"
            msg["From"] = settings.EMAIL_FROM
            msg["To"] = settings.EMAIL_FROM  # Send to self for testing
            
            msg.set_content(
                "This is a test email from Zaply to verify that the email service is working correctly.\n\n"
                "If you receive this email, the email service is properly configured and functional.\n\n"
                f"Test sent at: {datetime.now(timezone.utc).isoformat()}\n"
                "Best regards,\nZaply Email Service"
            )
            
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                if settings.SMTP_USE_TLS:
                    server.starttls()
                if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(msg)
            
            test_email_sent = True
            email_log("Test email sent successfully")
            
        except Exception as e:
            test_email_error = str(e)
            email_log(f"Test email failed: {test_email_error}")
    
    return {
        "email_service_test": {
            "success": test_ok,
            "message": test_message
        },
        "configuration": config_info,
        "test_email_sent": test_email_sent,
        "test_email_error": test_email_error,
        "recommendations": _get_email_recommendations(test_ok, test_message, config_info)
    }

def _get_email_troubleshooting_recommendations(email_service_status: str, email_error: str?) -> list:
    """Get comprehensive troubleshooting recommendations for email issues."""
    recommendations = []
    
    if email_service_status == "not_configured":
        recommendations.extend([
            "🔧 Server Issue: Email service not configured",
            "📧 Contact server administrator to set up email service",
            "🔑 Required environment variables: SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM",
            "📧 Test configuration: POST /auth/test-email (DEBUG mode only)",
            "🔄 Fallback: In DEBUG mode, tokens are returned in response"
        ])
    
    elif email_service_status == "failed":
        recommendations.extend([
            "🔧 Email Service Configuration Issue",
            "📊 Check server logs for detailed error information",
            "🔍 Test email service: POST /auth/test-email",
            "🌐 Verify network connectivity to SMTP server",
            "🔥 Check firewall rules for outbound SMTP connections (ports 25, 465, 587)",
            "📱 Verify SMTP credentials are correct"
        ])
        
        # Specific error-based recommendations
        if email_error:
            error_lower = email_error.lower()
            if "authentication" in error_lower:
                recommendations.extend([
                    "🔐 Authentication failed - Check SMTP_USERNAME and SMTP_PASSWORD",
                    "📱 For Gmail: Generate App Password at security.google.com",
                    "🔐 Enable 2-factor authentication",
                    "⚠️ Ensure 'Less secure app access' is enabled"
                ])
            elif "connection" in error_lower:
                recommendations.extend([
                    "🌐 Network connectivity issue - Check internet connection",
                    "🔥 Firewall blocking - Allow outbound SMTP connections",
                    "🌍 DNS issue - Verify SMTP_HOST is correct",
                    "📡 Try telnet test: telnet smtp.gmail.com 587"
                ])
            elif "tls" in error_lower:
                recommendations.extend([
                    "🔒 TLS configuration issue - Check SMTP_USE_TLS setting",
                    "📞 Contact email provider for correct SMTP settings",
                    "🔄 Try different SMTP port (587 for TLS, 465 for SSL)"
                ])
            elif "timeout" in error_lower:
                recommendations.extend([
                    "⏰ Connection timeout - Check network latency",
                    "🌐 Try closer SMTP server or improve network",
                    "🔄 Increase timeout settings if network is slow"
                ])
            else:
                recommendations.extend([
                    "❓ Unknown error - Check all SMTP configuration",
                    "📧 Review server logs for detailed error information",
                    "🔄 Restart email service or application"
                ])
    
    else:  # email_service_status == "configured"
        recommendations.extend([
            "✅ Email service is working correctly",
            "📧 Check recipient email address for typos",
            "📱 Check spam/junk folder in email client",
            "🔍 Wait up to 5 minutes for email delivery",
            "🌐 Verify email isn't blocked by recipient's email provider",
            "📊 Check email service logs: POST /auth/test-email"
        ])
    
    # General troubleshooting steps
    recommendations.extend([
        "🧪 Use test endpoint: POST /auth/test-email (DEBUG mode only)",
        "📋 Check environment variables: SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM",
        "🔧 Restart application after configuration changes",
        "📖 Consult email provider documentation for SMTP settings"
    ])
    
    return recommendations

# Rate limiting with memory cleanup for production safety
# In production, replace with Redis or similar distributed storage
login_attempts: Dict[str, List[datetime]] = defaultdict(list)
failed_login_attempts: Dict[str, Tuple[int, datetime]] = {}

# Configuration for rate limiting
MAX_LOGIN_ATTEMPTS_PER_IP = 20  # Maximum attempts per IP per 5 minutes
LOGIN_ATTEMPT_WINDOW = 300  # 5 minutes in seconds
ACCOUNT_LOCKOUT_DURATION = 900  # 15 minutes in seconds (final lockout)
MAX_FAILED_ATTEMPTS_PER_ACCOUNT = 5  # Maximum failed attempts per account before lockout

# Progressive lockout durations (in seconds)
# Note: For attempts beyond 5, we use attempt 5's duration to prevent lockout decrease
PROGRESSIVE_LOCKOUTS = {
    1: 300,   # 5 minutes after 1st failed attempt
    2: 600,   # 10 minutes after 2nd failed attempt
    3: 900,   # 15 minutes after 3rd failed attempt
    4: 1200,  # 20 minutes after 4th failed attempt
    5: 1800,   # 30 minutes after 5th failed attempt (maximum duration)
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
    """Test email service connectivity and configuration."""
    if not settings.EMAIL_SERVICE_ENABLED:
        return False, "Email service not configured"
    
    try:
        import smtplib
        from email.message import EmailMessage
        
        # Test connection to SMTP server
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        
        return True, "Email service test successful"
    except Exception as e:
        return False, f"Email service test failed: {str(e)}"


def cleanup_old_attempts() -> None:
    """Clean up old rate limiting attempts to prevent memory leaks."""
    current_time = datetime.now(timezone.utc)
    cutoff_time = current_time - timedelta(seconds=LOGIN_ATTEMPT_WINDOW)
    
    # Clean up old IP-based attempts
    ips_to_remove = []
    for ip, attempts in login_attempts.items():
        # Remove old attempts
        login_attempts[ip] = [t for t in attempts if t > cutoff_time]
        # Mark for removal if no recent attempts
        if not login_attempts[ip]:
            ips_to_remove.append(ip)
    
    for ip in ips_to_remove:
        del login_attempts[ip]
    
    # Clean up expired account lockouts
    emails_to_remove = []
    for email, (attempts, lockout_until) in failed_login_attempts.items():
        if current_time > lockout_until:
            emails_to_remove.append(email)
    
    for email in emails_to_remove:
        del failed_login_attempts[email]
    
    if settings.DEBUG and (ips_to_remove or emails_to_remove):
        auth_log(f"[AUTH] Cleanup: removed {len(ips_to_remove)} IPs, {len(emails_to_remove)} expired lockouts")


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    """Register a new user"""
    try:
        # Validate password strength
        from security import SecurityConfig
        password_validation = SecurityConfig.validate_password_strength(user.password)
        if not password_validation["valid"] and settings.DEBUG is False:
            # Only enforce strict password strength in production
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password too weak: {', '.join(password_validation['issues'])}"
            )
        
        # Lowercase email for consistency
        user_email = user.email.lower().strip()
        auth_log(f"[AUTH] Registration request received")
        
        # Get users collection - this will raise RuntimeError if DB not connected
        try:
            users = users_collection()
        except RuntimeError as e:
            auth_log(f"[AUTH] Database not initialized: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable. Please try again later."
            )
        
        # Check if user already exists (with timeout)
        try:
            auth_log(f"[AUTH] Checking if user exists")
            existing_user = await asyncio.wait_for(
                users.find_one({"email": user_email}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Database query timeout during registration")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        if existing_user:
            auth_log(f"[AUTH] Registration failed - Email already exists")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered - this email is already in use"
            )
        
        # Create user document
        try:
            password_hash = hash_password(user.password)
            if not password_hash or '$' not in password_hash:
                raise ValueError("Password hash generation failed")
            auth_log(f"[AUTH] Password hash generated successfully for registration")
        except (ValueError, Exception) as e:
            auth_log(f"[AUTH] Password hashing failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Password processing failed. Please try again."
            )
        
        user_doc = {
            "_id": str(ObjectId()),
            "name": user.name,
            "email": user_email,
            "password_hash": password_hash,
            "quota_used": 0,
            "quota_limit": 42949672960,  # 40 GiB
            "created_at": datetime.now(timezone.utc)
        }
        
        try:
            await asyncio.wait_for(
                users.insert_one(user_doc),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Insert operation timeout during user registration")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        auth_log(f"[AUTH] User registered successfully: ID: {user_doc['_id']}")
        
        return UserResponse(
            id=user_doc["_id"],
            name=user_doc["name"],
            email=user_doc["email"],
            username=user_doc.get("username"),
            bio=user_doc.get("bio"),
            avatar=user_doc.get("avatar"),
            avatar_url=user_doc.get("avatar_url"),
            quota_used=user_doc["quota_used"],
            quota_limit=user_doc["quota_limit"],
            created_at=user_doc["created_at"],
            updated_at=user_doc.get("updated_at"),
            last_seen=user_doc.get("last_seen"),
            is_online=user_doc.get("is_online", False),
            status=user_doc.get("status"),
            pinned_chats=user_doc.get("pinned_chats", []) or [],
            is_contact=False
        )
    
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except asyncio.TimeoutError:
        auth_log("[AUTH] Timeout error during user registration")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registration failed due to database timeout. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        # Log the actual error for debugging when DEBUG is enabled
        if settings.DEBUG:
            import traceback
            auth_log(f"[AUTH] Registration failed with error: {type(e).__name__}: {str(e)}")
            traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again."
        )
    except Exception as e:
        # Catch all other unexpected exceptions
        auth_log(f"[AUTH] Unexpected exception during registration: {type(e).__name__}: {str(e)}")
        if settings.DEBUG:
            import traceback
            traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again."
        )


@router.post("/login", response_model=Token)
async def login(credentials: UserLogin, request: Request):
    """Login and receive JWT tokens"""
    try:
        # Cleanup old attempts to prevent memory leaks
        cleanup_old_attempts()
        
        # Rate limiting check - handle missing client info
        try:
            client_ip = request.client.host if request.client else "unknown"
        except Exception:
            client_ip = "unknown"
        current_time = datetime.now(timezone.utc)
        
        # Apply rate limiting
        if not auth_rate_limiter.is_allowed(client_ip):
            retry_after = auth_rate_limiter.get_retry_after(client_ip)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many login attempts. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)}
            )
        
        # IP-based rate limiting to prevent brute force attacks (check only, don't record yet)
        if client_ip in login_attempts:
            # Clean up old attempts (memory leak prevention)
            cutoff_time = current_time - timedelta(seconds=LOGIN_ATTEMPT_WINDOW)
            login_attempts[client_ip] = [
                t for t in login_attempts[client_ip]
                if t > cutoff_time
            ]
            
            # Check if IP exceeded rate limit
            if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS_PER_IP:
                retry_after = LOGIN_ATTEMPT_WINDOW - (current_time - login_attempts[client_ip][0]).total_seconds()
                auth_log(f"[AUTH] IP rate limit exceeded for {client_ip}: {len(login_attempts[client_ip])} attempts")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many login attempts from this IP. Please try again in {int(retry_after)} seconds.",
                    headers={"Retry-After": str(int(retry_after))}
                )
        
        auth_log(f"[AUTH] Login attempt received")
        
        # Get users collection
        try:
            users = users_collection()
        except RuntimeError as e:
            auth_log(f"[AUTH] Database not initialized: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable. Please try again later."
            )
        
        # Normalize email for search
        search_email = credentials.email.lower().strip()
        
        # Find user with timeout
        try:
            user = await asyncio.wait_for(
                users.find_one({"email": search_email}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Database query timeout during login")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        if not user:
            # Track failed attempt with proper progressive lockout
            if credentials.email in failed_login_attempts:
                attempts, _ = failed_login_attempts[credentials.email]
                new_attempts = attempts + 1
                
                # Use progressive lockout durations with maximum protection
                if new_attempts in PROGRESSIVE_LOCKOUTS:
                    lockout_duration = PROGRESSIVE_LOCKOUTS[new_attempts]
                else:
                    # For attempts beyond 5, use maximum duration (30 minutes)
                    # This prevents lockout duration from decreasing on attempts 6+
                    lockout_duration = PROGRESSIVE_LOCKOUTS[5]  # 1800 seconds (30 minutes)
                
                lockout_time = current_time + timedelta(seconds=lockout_duration)
                failed_login_attempts[credentials.email] = (new_attempts, lockout_time)
                auth_log(f"[AUTH] Progressive lockout applied: attempt {new_attempts}, duration {lockout_duration}s")
            else:
                # First failed attempt
                lockout_duration = PROGRESSIVE_LOCKOUTS[1]
                lockout_time = current_time + timedelta(seconds=lockout_duration)
                failed_login_attempts[credentials.email] = (1, lockout_time)
                auth_log(f"[AUTH] First failed attempt detected, {lockout_duration}s lockout initiated")
            
            # Record this failed attempt (after credential validation failure)
            login_attempts[client_ip].append(current_time)
            
            auth_log(f"[AUTH] Login failed - User not found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        # Check account lockout status
        if credentials.email in failed_login_attempts:
            attempts, lockout_until = failed_login_attempts[credentials.email]
            if current_time < lockout_until:
                remaining_time = int((lockout_until - current_time).total_seconds())
                auth_log(f"[AUTH] Account locked: attempts: {attempts}, remaining: {remaining_time}s")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Account temporarily locked due to too many failed attempts. Please try again in {remaining_time} seconds.",
                    headers={"Retry-After": str(remaining_time)}
                )
        
        auth_log(f"[AUTH] User found: {user.get('_id')} - Verifying password")
        
        # Debug: Check hash format
        stored_hash = user.get("password_hash", "")
        auth_log(f"[AUTH] Hash format check: contains '$': {'$' in stored_hash}, length: {len(stored_hash)}")
        
        # Verify password
        password_valid = verify_password(credentials.password, user["password_hash"])
        auth_log(f"[AUTH] Password verification result: {password_valid}")
        
        if not password_valid:
            # Track failed attempt with proper progressive lockout
            if credentials.email in failed_login_attempts:
                attempts, _ = failed_login_attempts[credentials.email]
                new_attempts = attempts + 1
                
                # Use progressive lockout durations with maximum protection
                if new_attempts in PROGRESSIVE_LOCKOUTS:
                    lockout_duration = PROGRESSIVE_LOCKOUTS[new_attempts]
                else:
                    # For attempts beyond 5, use maximum duration (30 minutes)
                    # This prevents lockout duration from decreasing on attempts 6+
                    lockout_duration = PROGRESSIVE_LOCKOUTS[5]  # 1800 seconds (30 minutes)
                
                lockout_time = current_time + timedelta(seconds=lockout_duration)
                failed_login_attempts[credentials.email] = (new_attempts, lockout_time)
                auth_log(f"[AUTH] Progressive lockout applied: attempt {new_attempts}, duration {lockout_duration}s")
            else:
                # First failed attempt
                lockout_duration = PROGRESSIVE_LOCKOUTS[1]
                lockout_time = current_time + timedelta(seconds=lockout_duration)
                failed_login_attempts[credentials.email] = (1, lockout_time)
                auth_log(f"[AUTH] First failed attempt detected, {lockout_duration}s lockout initiated")
            
            # Record this failed attempt (after credential validation failure)
            login_attempts[client_ip].append(current_time)
            
            auth_log(f"[AUTH] Login failed - Incorrect password")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        # Clear failed attempts on successful login
        if credentials.email in failed_login_attempts:
            del failed_login_attempts[credentials.email]
        
        # Record this login attempt ONLY after successful credential validation
        login_attempts[client_ip].append(current_time)
        
        auth_log(f"[AUTH] Password verified - Creating tokens for user: {user.get('_id')}")
        
        # Create tokens
        access_token = create_access_token(data={"sub": user["_id"]})
        refresh_token, jti = create_refresh_token(data={"sub": user["_id"]})
        
        auth_log("[AUTH] Tokens created - Storing refresh token")
        
        # Store refresh token with timeout
        try:
            await asyncio.wait_for(
                refresh_tokens_collection().insert_one({
                    "token": refresh_token,
                    "jti": jti,
                    "user_id": user["_id"],
                    "created_at": datetime.now(timezone.utc)
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log("[AUTH] Database operation timeout storing refresh token")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        auth_log(f"[AUTH] Login successful for user ID: {user.get('_id')}")
        
        return Token(access_token=access_token, refresh_token=refresh_token)
    
    except HTTPException:
        # Re-raise HTTP exceptions (like 401 Unauthorized)
        raise
    except asyncio.TimeoutError:
        auth_log("[AUTH] Unexpected timeout error during login")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Login failed due to database timeout. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        # Log the actual error for debugging when DEBUG is enabled
        if settings.DEBUG:
            import traceback
            auth_log(f"[AUTH] Login failed with unexpected error: {type(e).__name__}: {str(e)}")
            traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed. Please try again."
        )
    except Exception as e:
        # Catch all other unexpected exceptions
        auth_log(f"[AUTH] Unexpected exception during login: {type(e).__name__}: {str(e)}")
        if settings.DEBUG:
            import traceback
            traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed. Please try again."
        )


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_request: RefreshTokenRequest):
    """Refresh access token using refresh token"""
    try:
        token_data = decode_token(refresh_request.refresh_token)
        
        if token_data.token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        # Verify refresh token exists in database with timeout
        try:
            stored_token = await asyncio.wait_for(
                refresh_tokens_collection().find_one({
                    "token": refresh_request.refresh_token,
                    "user_id": token_data.user_id
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Token verification timeout for user: {token_data.user_id}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        if not stored_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Create new tokens
        access_token = create_access_token(data={"sub": token_data.user_id})
        new_refresh_token, new_jti = create_refresh_token(data={"sub": token_data.user_id})
        
        # Delete old refresh token with timeout
        try:
            await asyncio.wait_for(
                refresh_tokens_collection().delete_one({"token": refresh_request.refresh_token}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Delete token timeout for user: {token_data.user_id}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        # Store new refresh token with timeout
        try:
            await asyncio.wait_for(
                refresh_tokens_collection().insert_one({
                    "token": new_refresh_token,
                    "jti": new_jti,
                    "user_id": token_data.user_id,
                    "created_at": datetime.now(timezone.utc)
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Insert token timeout for user: {token_data.user_id}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        print(f"[AUTH] Token refresh successful for user: {token_data.user_id}")
        return Token(access_token=access_token, refresh_token=new_refresh_token)
    
    except HTTPException:
        raise
    except (ValueError, TypeError, KeyError, OSError) as e:
        if settings.DEBUG:
            import traceback
            print(f"[AUTH] Token refresh failed with error: {type(e).__name__}: {str(e)}")
            traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@router.post("/logout")
async def logout(refresh_request: RefreshTokenRequest, current_user: str = Depends(get_current_user)):
    """Logout by revoking refresh token"""
    try:
        # Delete refresh token with timeout
        try:
            await asyncio.wait_for(
                refresh_tokens_collection().delete_one({
                    "token": refresh_request.refresh_token,
                    "user_id": current_user
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Logout operation timeout for user: {current_user}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Logout operation timed out. Please try again."
            )
        
        auth_log(f"[AUTH] Logout successful for user: {current_user}")
        return {"message": "Logged out successfully"}
    
    except HTTPException:
        raise
    except (ValueError, TypeError, KeyError, OSError) as e:
        auth_log(f"[AUTH] Logout failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed. Please try again."
        )


# Password Reset Endpoints
@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    """Request password reset token with enhanced email validation and fallback"""
    
    try:
        # Normalize email
        email = request.email.lower().strip()
        auth_log(f"[AUTH] Password reset request received for: {email}")
        
        # Validate email format
        if not email or '@' not in email or '.' not in email.split('@')[1]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format. Please enter a valid email address."
            )
        
        # Check email rate limiting
        rate_limit_ok, rate_limit_message = check_email_rate_limit(email)
        if not rate_limit_ok:
            auth_log(f"[AUTH] Email rate limit exceeded for: {email}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=rate_limit_message,
                headers={"Retry-After": "3600"}  # 1 hour retry
            )
        
        users = users_collection()
        
        # Check if user exists (with timeout)
        try:
            user = await asyncio.wait_for(
                users.find_one({"email": email}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Database query timeout during password reset request")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        except Exception as e:
            auth_log(f"[AUTH] Database error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable. Please try again."
            )
        
        if not user:
            # Return success anyway (security: don't reveal if email exists)
            auth_log(f"[AUTH] Password reset requested for non-existent email: {email}")
            return {
                "message": "If an account exists with this email, a password reset link has been sent.",
                "success": True,
                "email_sent": False,
                "debug_info": {
                    "note": "For security reasons, we don't reveal if email exists in our system"
                }
            }
        
        # Create password reset token (valid for 1 hour)
        reset_token = create_access_token(
            data={"sub": str(user["_id"]), "type": "password_reset"},
            expires_delta=timedelta(hours=1)
        )
        
        # Store reset token in database
        reset_tokens = reset_tokens_collection()
        try:
            await asyncio.wait_for(
                reset_tokens.insert_one({
                    "token": reset_token,
                    "user_id": str(user["_id"]),
                    "email": email,
                    "created_at": datetime.now(timezone.utc),
                    "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
                    "used": False
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Timeout storing reset token")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to generate reset token. Please try again."
            )
        except Exception as e:
            auth_log(f"[AUTH] Error storing reset token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate reset token. Please try again."
            )
        
        # Enhanced email sending with validation and fallback
        email_result = await send_password_reset_email(email, user, reset_token)
        
        # Honest and detailed response about email service status
        email_service_status = "configured"
        email_status_description = "Email service is configured and operational"
        
        if not settings.EMAIL_SERVICE_ENABLED:
            email_service_status = "not_configured"
            email_status_description = "Email service is not configured on this server"
        elif not email_result["sent"]:
            email_service_status = "failed"
            email_status_description = f"Email service is configured but failed to send: {email_result.get('error', 'Unknown error')}"
        
        # Build response with honest status
        response = {
            "message": "If an account exists with this email, a password reset link has been sent.",
            "success": True,
            "email_sent": email_result["sent"],
            "email_service_configured": settings.EMAIL_SERVICE_ENABLED,
            "email_service_status": email_service_status,
            "email_status_description": email_status_description,
        }
        
        # Always include debug information for transparency
        response["debug_info"] = {
            "email_service_enabled": settings.EMAIL_SERVICE_ENABLED,
            "email_service_status": email_service_status,
            "smtp_host": settings.SMTP_HOST if settings.EMAIL_SERVICE_ENABLED else None,
            "smtp_port": settings.SMTP_PORT if settings.EMAIL_SERVICE_ENABLED else None,
            "smtp_username": settings.SMTP_USERNAME if settings.EMAIL_SERVICE_ENABLED else None,
            "email_from": settings.EMAIL_FROM if settings.EMAIL_SERVICE_ENABLED else None,
            "reset_token": reset_token,
            "email_error": email_result.get("error"),
            "email_test_result": email_result.get("test_result"),
            "email_attempt_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommendations": _get_email_troubleshooting_recommendations(email_service_status, email_result.get("error"))
        }
        
        # Adjust message based on actual email status
        if not email_result["sent"]:
            if not settings.EMAIL_SERVICE_ENABLED:
                response["message"] = "Email service is not configured on this server. Please contact administrator."
                response["user_action"] = "Contact server administrator to configure email service"
            else:
                response["message"] = f"Failed to send password reset email: {email_result.get('error', 'Unknown error')}"
                response["user_action"] = "Try again later or contact support"
        else:
            if not settings.EMAIL_SERVICE_ENABLED:
                response["message"] = "Email service not configured, but for testing purposes: token included in response"
                response["user_action"] = "Use the token below to reset password (DEBUG MODE ONLY)"
            else:
                response["message"] = "Password reset email sent successfully. Please check your inbox."
                response["user_action"] = "Check your email inbox (including spam folder)"
        
        # Log the result with enhanced details
        if email_result["sent"]:
            auth_log(f"[AUTH] ✅ Password reset email sent successfully to: {email}")
        else:
            auth_log(f"[AUTH] ❌ Password reset email failed: {email} - {email_result.get('error')}")
            if not settings.EMAIL_SERVICE_ENABLED:
                auth_log("[AUTH] ❌ Root cause: Email service not configured in backend")
            else:
                auth_log("[AUTH] ❌ Root cause: Email service configuration issue")
        
        return response
    
    except HTTPException:
        raise
    except (ValueError, TypeError, KeyError, OSError) as e:
        auth_log(f"[AUTH] Forgot password failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process password reset request."
        )

async def send_password_reset_email(email: str, user: dict, reset_token: str) -> dict:
    """Send password reset email with comprehensive error handling and validation."""
    
    if not settings.EMAIL_SERVICE_ENABLED:
        email_log("Email service not configured - skipping email send")
        return {
            "sent": False,
            "error": "Email service not configured",
            "test_result": None
        }
    
    # Test email service before attempting to send
    test_ok, test_error = test_email_service()
    if not test_ok:
        email_log(f"Email service test failed: {test_error}")
        return {
            "sent": False,
            "error": f"Email service unavailable: {test_error}",
            "test_result": test_error
        }
    
    try:
        import smtplib
        from email.message import EmailMessage
        
        email_log(f"Attempting to send password reset email to: {email}")
        
        # Create email message
        msg = EmailMessage()
        msg["Subject"] = "Zaply - Password Reset Request"
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = email
        msg["Reply-To"] = settings.EMAIL_FROM
        
        # Create reset link
        base_url = settings.API_BASE_URL.replace('/api/v1', '')
        reset_link = f"{base_url}/#/reset-password?token={reset_token}"
        
        # Enhanced email content with HTML support
        text_content = f"""Hi {user.get('name', 'User')},

You requested a password reset for your Zaply account.

Click here to reset your password:
{reset_link}

Or copy and paste this link:
{reset_link}

Alternative: Use this reset token: {reset_token}

This link is valid for 1 hour from the time of this email.
If you did not request this password reset, you can safely ignore this email.

For security, please:
- Never share this link with anyone
- Reset your password to something strong and unique
- Enable two-factor authentication if available

Best regards,
The Zaply Team
---
If you're having trouble clicking the reset link, copy and paste it into your browser.
"""

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Zaply Password Reset</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #4CAF50; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; background: #f9f9f9; }}
        .button {{ display: inline-block; padding: 12px 24px; background: #4CAF50; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }}
        .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; }}
        .security {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Zaply Password Reset</h1>
        </div>
        <div class="content">
            <p>Hi {user.get('name', 'User')},</p>
            <p>You requested a password reset for your Zaply account. Click the button below to reset your password:</p>
            
            <div style="text-align: center;">
                <a href="{reset_link}" class="button">Reset Password</a>
            </div>
            
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #eee; padding: 10px; border-radius: 4px;">{reset_link}</p>
            
            <p>Or use this reset token:</p>
            <p style="background: #e8f4fd; padding: 10px; border-radius: 4px; font-family: monospace;"><strong>{reset_token}</strong></p>
            
            <div class="security">
                <strong>🔒 Security Notice:</strong>
                <ul>
                    <li>This link is valid for 1 hour</li>
                    <li>Never share this link with anyone</li>
                    <li>If you didn't request this, ignore this email</li>
                </ul>
            </div>
        </div>
        <div class="footer">
            <p>Best regards,<br>The Zaply Team</p>
            <p><small>If you're having trouble, contact support</small></p>
        </div>
    </div>
</body>
</html>
"""
        
        # Set both text and HTML content
        msg.set_content(text_content)
        msg.add_alternative(html_content, subtype="html")
        
        # Send email with enhanced error handling
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as server:
            server.set_debuglevel(1 if settings.DEBUG else 0)
            
            if settings.SMTP_USE_TLS:
                server.starttls()
                email_log("TLS started")
            
            if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                email_log(f"Logged in as: {settings.SMTP_USERNAME}")
            
            # Send the email
            result = server.send_message(msg)
            email_log(f"Email sent successfully. Server response: {result}")
        
        return {
            "sent": True,
            "error": None,
            "test_result": "Email sent successfully"
        }
        
    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"SMTP authentication failed: {str(e)}"
        email_log(f"SMTP Authentication Error: {error_msg}")
        return {
            "sent": False,
            "error": error_msg,
            "test_result": "Authentication failed - check SMTP credentials"
        }
    
    except smtplib.SMTPConnectError as e:
        error_msg = f"Failed to connect to SMTP server: {str(e)}"
        email_log(f"SMTP Connection Error: {error_msg}")
        return {
            "sent": False,
            "error": error_msg,
            "test_result": "Connection failed - check SMTP host and port"
        }
    
    except smtplib.SMTPServerDisconnected as e:
        error_msg = f"SMTP server disconnected: {str(e)}"
        email_log(f"SMTP Disconnection Error: {error_msg}")
        return {
            "sent": False,
            "error": error_msg,
            "test_result": "Server disconnected - try again later"
        }
    
    except smtplib.SMTPException as e:
        error_msg = f"SMTP error: {str(e)}"
        email_log(f"SMTP Error: {error_msg}")
        return {
            "sent": False,
            "error": error_msg,
            "test_result": "SMTP protocol error"
        }
    
    except Exception as e:
        error_msg = f"Unexpected error sending email: {type(e).__name__}: {str(e)}"
        email_log(f"Unexpected Email Error: {error_msg}")
        return {
            "sent": False,
            "error": error_msg,
            "test_result": "Unexpected error occurred"
        }
        
        users = users_collection()
        
        # Check if user exists (with timeout)
        try:
            user = await asyncio.wait_for(
                users.find_one({"email": email}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Database query timeout during password reset request")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        except Exception as e:
            auth_log(f"[AUTH] Database error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable. Please try again."
            )
        
        if not user:
            # Return success anyway (security: don't reveal if email exists)
            auth_log(f"[AUTH] Password reset requested for non-existent email")
            return {
                "message": "If an account exists with this email, a password reset link has been sent.",
                "success": True
            }
        
        # Create password reset token (valid for 1 hour)
        reset_token = create_access_token(
            data={"sub": str(user["_id"]), "type": "password_reset"},
            expires_delta=timedelta(hours=1)
        )
        
        # Store reset token in database
        reset_tokens = reset_tokens_collection()
        try:
            await asyncio.wait_for(
                reset_tokens.insert_one({
                    "token": reset_token,
                    "user_id": str(user["_id"]),
                    "email": email,
                    "created_at": datetime.now(timezone.utc),
                    "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
                    "used": False
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Timeout storing reset token")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to generate reset token. Please try again."
            )
        except Exception as e:
            auth_log(f"[AUTH] Error storing reset token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate reset token. Please try again."
            )
        
        # Try to send email with reset token if SMTP is configured
        email_sent = False
        smtp_error = None
        if settings.SMTP_HOST and settings.EMAIL_FROM:
            auth_log(f"[AUTH] SMTP configured - attempting to send password reset email")
            try:
                msg = EmailMessage()
                msg["Subject"] = "Zaply - Password Reset"
                msg["From"] = settings.EMAIL_FROM
                msg["To"] = email
                
                reset_link = f"{settings.API_BASE_URL.replace('/api/v1/', '')}/#/reset-password?token={reset_token}"
                
                msg.set_content(
                    f"Hi {user.get('name', 'User')},\n\n"
                    "You requested a password reset for your Zaply account.\n\n"
                    f"Reset Link:\n{reset_link}\n\n"
                    f"Or use this reset token:\n{reset_token}\n\n"
                    "This link is valid for 1 hour.\n"
                    "If you did not request this, you can safely ignore this email.\n\n"
                    "Best regards,\nZaply Team"
                )

                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                    if settings.SMTP_USE_TLS:
                        server.starttls()
                    if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    server.send_message(msg)

                email_sent = True
                auth_log(f"[AUTH] Password reset email sent successfully")
            except Exception as e:
                smtp_error = str(e)
                auth_log(f"[AUTH] Failed to send reset email: {type(e).__name__}: {e}")
        else:
            auth_log(f"[AUTH] SMTP not configured")

        # Security: Never include reset token in API response in production
        # But in DEBUG mode, return it if email fails to allow dev testing
        response = {
            "message": "If an account exists with this email, a password reset link has been sent.",
            "success": True,
            "email_sent": email_sent,
        }
        
        if settings.DEBUG:
            if not email_sent:
                response["debug_info"] = {
                    "token": reset_token,
                    "smtp_error": smtp_error or "SMTP not configured"
                }
                response["message"] = "DEBUG: Email not sent, token included in response."

        return response
    
    except HTTPException:
        raise
    except (ValueError, TypeError, KeyError, OSError) as e:
        auth_log(f"[AUTH] Forgot password failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process password reset request."
        )


@router.post("/reset-password", response_model=PasswordResetResponse)
async def reset_password(request: PasswordResetRequest):
    """Reset password using reset token"""
    
    try:
        auth_log("[AUTH] Password reset attempt")
        
        # Validate reset token by decoding JWT directly
        try:
            payload = jwt.decode(request.token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            token_type = payload.get("type")
            if token_type != "password_reset":
                auth_log(f"[AUTH] Invalid token type: {token_type}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid reset token type"
                )
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid reset token"
                )
        except jwt.ExpiredSignatureError:
            auth_log("[AUTH] Reset token expired")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired"
            )
        except jwt.JWTError as e:
            auth_log(f"[AUTH] Invalid reset token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        except Exception as e:
            auth_log(f"[AUTH] Unexpected error decoding token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        users = users_collection()
        reset_tokens = reset_tokens_collection()
        
        # Check if token was already used (with timeout)
        try:
            token_record = await asyncio.wait_for(
                reset_tokens.find_one({"token": request.token}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        if not token_record or token_record.get("used"):
            auth_log("[AUTH] Reset token already used or not found")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Validate new password strength
        from security import SecurityConfig
        password_validation = SecurityConfig.validate_password_strength(request.new_password)
        if not password_validation["valid"] and not settings.DEBUG:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password too weak: {', '.join(password_validation['issues'])}"
            )
        
        # Update user password (with timeout)
        hashed_password = hash_password(request.new_password)
        try:
            await asyncio.wait_for(
                users.update_one(
                    {"_id": user_id},
                    {"$set": {"password_hash": hashed_password}}
                ),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to update password. Please try again."
            )
        
        # Mark token as used
        try:
            await asyncio.wait_for(
                reset_tokens.update_one(
                    {"token": request.token},
                    {"$set": {"used": True}}
                ),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            pass  # Non-critical, continue anyway
        
        auth_log(f"[AUTH] Password reset successful for user: {user_id}")
        return PasswordResetResponse(
            message="Password has been reset successfully. Please login with your new password.",
            success=True
        )
    
    except HTTPException:
        raise
    except (ValueError, TypeError, KeyError, OSError) as e:
        auth_log(f"[AUTH] Password reset failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password. Please try again."
        )


# ===== QR CODE ROUTES FOR MULTI-DEVICE CONNECTION =====

@router.post("/qrcode/generate", response_model=QRCodeResponse)
async def generate_qr_code_endpoint(
    qr_request: QRCodeRequest,
    current_user: str = Depends(get_current_user)
):
    """
    Generate a QR code for connecting a new device to the same account.
    
    The QR code encodes:
    - User ID
    - Unique session ID
    - Verification code (6 digits)
    - Device type
    - Server URL
    
    The code is valid for 5 minutes.
    """
    try:
        # Validate device type
        valid_devices = ["mobile", "web", "desktop"]
        if qr_request.device_type not in valid_devices:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid device type. Must be one of: {', '.join(valid_devices)}"
            )
        
        auth_log(f"[QR_CODE] Generating QR code for user {current_user}, device: {qr_request.device_type}")
        
        # Get or create qr_sessions collection
        try:
            db = users_collection().client.get_database(settings.DATABASE_NAME)
            qr_sessions = db.qr_sessions
        except Exception as e:
            auth_log(f"[QR_CODE] Database error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable"
            )
        
        # Generate session data
        session_id = str(ObjectId())
        session_code = generate_session_code(6)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        # Create QR code payload
        payload = create_qr_session_payload(
            user_id=current_user,
            session_id=session_id,
            session_code=session_code,
            device_type=qr_request.device_type,
            server_url=getattr(settings, 'SERVER_URL', 'http://localhost:8000')
        )
        
        # Generate QR code image
        qr_code_data, qr_json = generate_qr_code(payload)
        
        # Store session in database
        session_doc = {
            "_id": ObjectId(session_id),
            "user_id": current_user,
            "session_code": session_code,
            "qr_code_data": qr_code_data,
            "device_type": qr_request.device_type,
            "device_name": qr_request.device_name,
            "created_at": datetime.now(timezone.utc),
            "expires_at": expires_at,
            "is_verified": False,
            "verified_at": None,
            "verified_from": None,
            "status": "pending"
        }
        
        try:
            await asyncio.wait_for(
                qr_sessions.insert_one(session_doc),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out"
            )
        
        auth_log(f"[QR_CODE] QR code generated successfully. Session: {session_id}")
        
        return QRCodeResponse(
            session_id=session_id,
            session_code=session_code,
            qr_code_data=qr_code_data,
            device_type=qr_request.device_type,
            expires_in_seconds=300,
            verification_url=f"/auth/qrcode/verify"
        )
    
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"[QR_CODE] Failed to generate QR code: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate QR code"
        )


@router.post("/qrcode/verify", response_model=VerifyQRCodeResponse)
async def verify_qr_code_endpoint(verify_request: VerifyQRCodeRequest):
    """
    Verify QR code with session code and return auth token.
    
    This endpoint is used by devices scanning the QR code to:
    1. Verify the session code (6-digit confirmation)
    2. Get authenticated as the same user who generated the QR code
    3. Establish a connection for multi-device sync
    
    The device can be a mobile app, web page, or desktop application.
    """
    try:
        auth_log(f"[QR_CODE] QR code verification attempt for session: {verify_request.session_id}")
        
        # Get qr_sessions collection
        try:
            db = users_collection().client.get_database(settings.DATABASE_NAME)
            qr_sessions = db.qr_sessions
        except Exception as e:
            auth_log(f"[QR_CODE] Database error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable"
            )
        
        # Find the session
        try:
            session = await asyncio.wait_for(
                qr_sessions.find_one({"_id": ObjectId(verify_request.session_id)}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out"
            )
        
        if not session:
            auth_log(f"[QR_CODE] Session not found: {verify_request.session_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="QR code session not found"
            )
        
        # Check if session has expired
        if datetime.now(timezone.utc) > session.get("expires_at"):
            auth_log(f"[QR_CODE] Session expired: {verify_request.session_id}")
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="QR code has expired. Please generate a new one."
            )
        
        # Check if session is already verified
        if session.get("is_verified"):
            auth_log(f"[QR_CODE] Session already verified: {verify_request.session_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This QR code has already been used"
            )
        
        # Verify the session code
        if not validate_session_code(verify_request.session_code, session.get("session_code", "")):
            auth_log(f"[QR_CODE] Invalid session code for session: {verify_request.session_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid verification code"
            )
        
        # Get the user
        user_id = session.get("user_id")
        # Validate user_id format before ObjectId conversion
        validated_user_id = validate_user_id(user_id)
        if not validated_user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user ID format"
            )
        
        try:
            users = users_collection()
            user = await asyncio.wait_for(
                users.find_one({"_id": validated_user_id}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out"
            )
        
        if not user:
            auth_log(f"[QR_CODE] User not found for session: {verify_request.session_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Create tokens for the connecting device
        access_token = create_access_token(
            data={"sub": user_id},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        refresh_token, jti = create_refresh_token(data={"sub": user_id})
        
        # Store refresh token
        try:
            refresh_tokens = refresh_tokens_collection()
            await asyncio.wait_for(
                refresh_tokens.insert_one({
                    "user_id": validated_user_id,
                    "token_jti": jti,
                    "created_at": datetime.now(timezone.utc),
                    "expires_at": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            pass  # Non-critical, continue anyway
        
        # Mark session as verified
        try:
            await asyncio.wait_for(
                qr_sessions.update_one(
                    {"_id": ObjectId(verify_request.session_id)},
                    {
                        "$set": {
                            "is_verified": True,
                            "verified_at": datetime.now(timezone.utc),
                            "verified_from": verify_request.device_info or "unknown",
                            "status": "verified"
                        }
                    }
                ),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            pass  # Non-critical, continue anyway
        
        auth_log(f"[QR_CODE] QR code verified successfully. User: {user_id}, Device: {session.get('device_type')}")
        
        return VerifyQRCodeResponse(
            success=True,
            message=f"Successfully connected {session.get('device_type')} device to account",
            auth_token=access_token,
            user_id=user_id
        )
    
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"[QR_CODE] QR code verification failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify QR code"
        )


@router.get("/qrcode/status/{session_id}")
async def get_qr_code_status(
    session_id: str,
    current_user: str = Depends(get_current_user)
):
    """
    Get the status of a QR code session.
    Only the user who generated the QR code can check its status.
    """
    try:
        auth_log(f"[QR_CODE] Status check for session: {session_id}")
        
        # Get qr_sessions collection
        try:
            db = users_collection().client.get_database(settings.DATABASE_NAME)
            qr_sessions = db.qr_sessions
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable"
            )
        
        # Find the session
        try:
            session = await asyncio.wait_for(
                qr_sessions.find_one({"_id": ObjectId(session_id)}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out"
            )
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="QR code session not found"
            )
        
        # Verify ownership
        if session.get("user_id") != current_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to check this session"
            )
        
        # Determine status based on expiration
        if datetime.now(timezone.utc) > session.get("expires_at"):
            status_value = "expired"
        else:
            status_value = session.get("status", "pending")
        
        return {
            "session_id": session_id,
            "device_type": session.get("device_type"),
            "device_name": session.get("device_name"),
            "status": status_value,
            "is_verified": session.get("is_verified", False),
            "verified_at": session.get("verified_at"),
            "verified_from": session.get("verified_from"),
            "created_at": session.get("created_at"),
            "expires_at": session.get("expires_at")
        }
    
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"[QR_CODE] Failed to get session status: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get QR code status"
        )


@router.delete("/qrcode/cancel/{session_id}")
async def cancel_qr_code_session(
    session_id: str,
    current_user: str = Depends(get_current_user)
):
    """
    Cancel a QR code session before it expires.
    Only the user who generated the QR code can cancel it.
    """
    try:
        auth_log(f"[QR_CODE] Cancelling session: {session_id}")
        
        # Get qr_sessions collection
        try:
            db = users_collection().client.get_database(settings.DATABASE_NAME)
            qr_sessions = db.qr_sessions
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable"
            )
        
        # Find the session
        try:
            session = await asyncio.wait_for(
                qr_sessions.find_one({"_id": ObjectId(session_id)}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out"
            )
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="QR code session not found"
            )
        
        # Verify ownership
        if session.get("user_id") != current_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to cancel this session"
            )
        
        # Cancel the session
        try:
            await asyncio.wait_for(
                qr_sessions.update_one(
                    {"_id": ObjectId(session_id)},
                    {"$set": {"status": "cancelled"}}
                ),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out"
            )
        
        auth_log(f"[QR_CODE] Session cancelled: {session_id}")
        
        return {
            "success": True,
            "message": "QR code session cancelled successfully"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"[QR_CODE] Failed to cancel session: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel QR code session"
        )


@router.get("/qrcode/sessions")
async def list_qr_sessions(current_user: str = Depends(get_current_user)):
    """
    List all QR code sessions for the current user.
    Shows both pending and verified sessions (up to last 30 days).
    """
    try:
        auth_log(f"[QR_CODE] Listing sessions for user: {current_user}")
        
        # Get qr_sessions collection
        try:
            db = users_collection().client.get_database(settings.DATABASE_NAME)
            qr_sessions = db.qr_sessions
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable"
            )
        
        # Get sessions from last 30 days
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        
        try:
            sessions = await asyncio.wait_for(
                qr_sessions.find({
                    "user_id": current_user,
                    "created_at": {"$gte": thirty_days_ago}
                }).sort("created_at", -1).to_list(100),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out"
            )
        
        # Format response
        result = []
        for session in sessions:
            result.append({
                "session_id": str(session.get("_id")),
                "device_type": session.get("device_type"),
                "device_name": session.get("device_name"),
                "status": "expired" if datetime.now(timezone.utc) > session.get("expires_at") else session.get("status"),
                "is_verified": session.get("is_verified", False),
                "created_at": session.get("created_at"),
                "verified_at": session.get("verified_at"),
                "verified_from": session.get("verified_from")
            })
        
        return {
            "total": len(result),
            "sessions": result
        }
    
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"[QR_CODE] Failed to list sessions: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list QR code sessions"
        )
