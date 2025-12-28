from fastapi import APIRouter, HTTPException, status, Depends, Request
from models import (
    UserCreate, UserLogin, Token, RefreshTokenRequest, UserResponse,
    ForgotPasswordRequest, PasswordResetRequest, PasswordResetResponse
)
from db_proxy import users_collection, refresh_tokens_collection, reset_tokens_collection
from auth.utils import (
    hash_password, verify_password, create_access_token, 
    create_refresh_token, decode_token, get_current_user, get_current_user_from_query
)
from config import settings
from datetime import datetime, timedelta, timezone
from bson import ObjectId
import asyncio
import jwt
import smtplib
from email.message import EmailMessage
from collections import defaultdict
from typing import Dict, Tuple, List

router = APIRouter(prefix="/auth", tags=["Authentication"])

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
            phone=user_doc.get("phone"),
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
            contacts_count=len(user_doc.get("contacts", [])),
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
    """Request password reset token"""
    
    try:
        # Normalize email
        email = request.email.lower().strip()
        auth_log(f"[AUTH] Password reset request received")
        
        # Validate email format
        if not email or '@' not in email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
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

