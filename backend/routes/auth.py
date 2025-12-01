from fastapi import APIRouter, HTTPException, status, Depends
from backend.models import (
    UserCreate, UserLogin, Token, RefreshTokenRequest, UserInDB, UserResponse,
    ForgotPasswordRequest, PasswordResetRequest, PasswordResetResponse
)
from backend.database import users_collection, refresh_tokens_collection, reset_tokens_collection
from backend.auth.utils import (
    hash_password, verify_password, create_access_token, 
    create_refresh_token, decode_token, get_current_user
)
from backend.config import settings
from datetime import datetime, timedelta
from bson import ObjectId
import asyncio
import jwt
import smtplib
from email.message import EmailMessage

router = APIRouter(prefix="/auth", tags=["Authentication"])


def auth_log(message: str) -> None:
    """Log auth-related messages only when DEBUG is enabled."""
    if settings.DEBUG:
        print(message)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    """Register a new user"""
    try:
        auth_log(f"[AUTH] Registration request for email: {user.email}")
        
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
            existing_user = await asyncio.wait_for(
                users.find_one({"email": user.email}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Database query timeout for {user.email}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        if existing_user:
            auth_log(f"[AUTH] Registration failed - Email already exists: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create user document
        user_doc = {
            "_id": str(ObjectId()),
            "name": user.name,
            "email": user.email,
            "password_hash": hash_password(user.password),
            "quota_used": 0,
            "quota_limit": 42949672960,  # 40 GiB
            "created_at": datetime.utcnow()
        }
        
        try:
            await asyncio.wait_for(
                users.insert_one(user_doc),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            print(f"[AUTH] Insert operation timeout for {user.email}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        auth_log(f"[AUTH] User registered successfully: {user.email} (ID: {user_doc['_id']})")
        
        return UserResponse(
            id=user_doc["_id"],
            name=user_doc["name"],
            email=user_doc["email"],
            quota_used=user_doc["quota_used"],
            quota_limit=user_doc["quota_limit"],
            created_at=user_doc["created_at"]
        )
    
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log the actual error for debugging when DEBUG is enabled
        if settings.DEBUG:
            import traceback
            print(f"[AUTH] Registration failed with error: {type(e).__name__}: {str(e)}")
            traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again."
        )


@router.post("/login", response_model=Token)
async def login(credentials: UserLogin):
    """Login and receive JWT tokens"""
    try:
        auth_log(f"[AUTH] Login attempt for email: {credentials.email}")
        
        # Get users collection
        try:
            users = users_collection()
        except RuntimeError as e:
            auth_log(f"[AUTH] Database not initialized: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable. Please try again later."
            )
        
        # Find user with timeout
        try:
            user = await asyncio.wait_for(
                users.find_one({"email": credentials.email}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Database query timeout for {credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        if not user:
            auth_log(f"[AUTH] Login failed - User not found: {credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        auth_log(f"[AUTH] User found: {user.get('_id')} - Verifying password")
        
        # Verify password
        if not verify_password(credentials.password, user["password_hash"]):
            auth_log(f"[AUTH] Login failed - Incorrect password for: {credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        auth_log(f"[AUTH] Password verified - Creating tokens for user: {user.get('_id')}")
        
        # Create tokens
        access_token = create_access_token(data={"sub": user["_id"]})
        refresh_token, jti = create_refresh_token(data={"sub": user["_id"]})
        
        auth_log(f"[AUTH] Tokens created - Storing refresh token")
        
        # Store refresh token with timeout
        try:
            await asyncio.wait_for(
                refresh_tokens_collection().insert_one({
                    "token": refresh_token,
                    "jti": jti,
                    "user_id": user["_id"],
                    "created_at": datetime.utcnow()
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Database operation timeout storing refresh token")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        auth_log(f"[AUTH] Login successful for: {credentials.email}")
        
        return Token(access_token=access_token, refresh_token=refresh_token)
    
    except HTTPException:
        # Re-raise HTTP exceptions (like 401 Unauthorized)
        raise
    except Exception as e:
        # Log the actual error for debugging when DEBUG is enabled
        if settings.DEBUG:
            import traceback
            print(f"[AUTH] Login failed with unexpected error: {type(e).__name__}: {str(e)}")
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
                    "created_at": datetime.utcnow()
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
    except Exception as e:
        if settings.DEBUG:
            import traceback
            print(f"[AUTH] Token refresh failed: {type(e).__name__}: {str(e)}")
            traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed. Please try again."
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
    except Exception as e:
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
        auth_log(f"[AUTH] Password reset request for email: {request.email}")
        
        users = users_collection()
        
        # Check if user exists (with timeout)
        try:
            user = await asyncio.wait_for(
                users.find_one({"email": request.email}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            auth_log(f"[AUTH] Database query timeout for {request.email}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out. Please try again."
            )
        
        if not user:
            # Return success anyway (security: don't reveal if email exists)
            auth_log(f"[AUTH] Password reset requested for non-existent email: {request.email}")
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
                    "email": request.email,
                    "created_at": datetime.utcnow(),
                    "expires_at": datetime.utcnow() + timedelta(hours=1),
                    "used": False
                }),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to generate reset token. Please try again."
            )
        
        # Try to send email with reset token if SMTP is configured
        email_sent = False
        if settings.SMTP_HOST and settings.EMAIL_FROM:
            try:
                msg = EmailMessage()
                msg["Subject"] = "Zaply password reset"
                msg["From"] = settings.EMAIL_FROM
                msg["To"] = request.email
                msg.set_content(
                    "You requested a password reset for your Zaply account.\n\n"
                    f"Your reset token is:\n\n{reset_token}\n\n"
                    "This token is valid for 1 hour. If you did not request this, you can ignore this email."
                )

                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                    if settings.SMTP_USE_TLS:
                        server.starttls()
                    if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    server.send_message(msg)

                email_sent = True
                auth_log(f"[AUTH] Password reset email sent to: {request.email}")
            except Exception as e:
                auth_log(f"[AUTH] Failed to send reset email: {type(e).__name__}: {e}")

        auth_log(f"[AUTH] Password reset token generated for: {request.email}")

        # Always include reset token in API response so users can reset their password
        # even if SMTP is misconfigured or emails are delayed.
        response = {
            "message": "If an account exists with this email, a password reset link has been sent.",
            "success": True,
            "email_sent": email_sent,
            "reset_token": reset_token,
        }

        return response
    
    except HTTPException:
        raise
    except Exception as e:
        auth_log(f"[AUTH] Forgot password failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process password reset request."
        )


@router.post("/reset-password", response_model=PasswordResetResponse)
async def reset_password(request: PasswordResetRequest):
    """Reset password using reset token"""
    
    try:
        auth_log(f"[AUTH] Password reset attempt")
        
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
            auth_log(f"[AUTH] Reset token expired")
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
            auth_log(f"[AUTH] Reset token already used or not found")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Update user password (with timeout)
        hashed_password = hash_password(request.new_password)
        try:
            await asyncio.wait_for(
                users.update_one(
                    {"_id": ObjectId(user_id)},
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
    except Exception as e:
        auth_log(f"[AUTH] Password reset failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password. Please try again."
        )

