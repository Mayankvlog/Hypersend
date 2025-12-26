from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File
from backend.models import UserResponse, UserInDB, PasswordChangeRequest, EmailChangeRequest, ProfileUpdate
from backend.database import users_collection
from backend.auth.utils import get_current_user
import asyncio
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional
import re
import logging
import json

# Setup detailed logging for profile operations
logger = logging.getLogger("profile_endpoint")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '[%(asctime)s] [PROFILE] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

router = APIRouter(prefix="/users", tags=["Users"])


class PermissionsUpdate(BaseModel):
    """Permissions update model"""
    location: bool = False
    camera: bool = False
    microphone: bool = False
    contacts: bool = False
    phone: bool = False
    storage: bool = False


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: str = Depends(get_current_user)):
    """Get current user profile"""
    try:
        # Add 5-second timeout to prevent hanging
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch user: {str(e)}"
        )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=user["_id"],
        name=user["name"],
        email=user["email"],
        username=user.get("username"),
        quota_used=user.get("quota_used", 0),
        quota_limit=user.get("quota_limit", 42949672960),
        created_at=user["created_at"],
        avatar_url=user.get("avatar_url"),
        pinned_chats=user.get("pinned_chats", [])
    )


# ProfileUpdate model is imported from backend.models


@router.put("/profile", response_model=UserResponse)
async def update_profile(
    profile_data: ProfileUpdate,
    current_user: str = Depends(get_current_user)
):
    """Update current user's profile with detailed logging"""
    try:
        logger.info(f"{'='*80}")
        logger.info(f"PROFILE UPDATE REQUEST STARTED")
        logger.info(f"{'='*80}")
        logger.info(f"User ID: {current_user}")
        
        # Log received data
        logger.info(f"Received ProfileUpdate model:")
        logger.info(f"  - name: {profile_data.name} (type: {type(profile_data.name).__name__})")
        logger.info(f"  - username: {profile_data.username} (type: {type(profile_data.username).__name__})")
        logger.info(f"  - email: {profile_data.email} (type: {type(profile_data.email).__name__})")
        logger.info(f"  - avatar: {profile_data.avatar} (type: {type(profile_data.avatar).__name__})")
        logger.info(f"  - bio: {profile_data.bio} (type: {type(profile_data.bio).__name__})")
        logger.info(f"  - phone: {profile_data.phone} (type: {type(profile_data.phone).__name__})")
        logger.info(f"  - avatar_url: {profile_data.avatar_url} (type: {type(profile_data.avatar_url).__name__})")
        
        # Check if at least one field is being updated
        if all(v is None for v in [profile_data.name, profile_data.email, profile_data.username, profile_data.bio, profile_data.phone, profile_data.avatar_url, profile_data.avatar]):
            logger.warning(f"No fields provided for update - all are None")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one field must be provided to update"
            )
        
        # Get current user data from database
        logger.info(f"Fetching current user data from database...")
        current_user_data = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not current_user_data:
            logger.error(f"Current user not found in database: {current_user}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Current user not found"
            )
        
        logger.info(f"Current user data retrieved:")
        logger.info(f"  - name: {current_user_data.get('name')}")
        logger.info(f"  - username: {current_user_data.get('username')}")
        logger.info(f"  - email: {current_user_data.get('email')}")
        
        # Prepare update data
        update_data = {}
        
        # Process name
        if profile_data.name is not None:
            name = profile_data.name.strip()
            if not name:
                logger.warning(f"Name validation failed: empty string after strip")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Name cannot be empty"
                )
            if len(name) < 2:
                logger.warning(f"Name validation failed: length {len(name)} < 2")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Name must be at least 2 characters"
                )
            logger.info(f"✓ Name validation passed: {name}")
            update_data["name"] = name
        
        # Process username
        if profile_data.username is not None:
            username = profile_data.username.strip()
            if not username:
                logger.warning(f"Username validation failed: empty string after strip")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username cannot be empty"
                )
            # Check if username is already taken
            if username != "":
                existing_username = await asyncio.wait_for(
                    users_collection().find_one({"username": username}),
                    timeout=5.0
                )
                if existing_username and existing_username.get("_id") != current_user:
                    logger.warning(f"Username already taken: {username} by {existing_username.get('_id')}")
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Username already taken"
                    )
            logger.info(f"✓ Username validation passed: {username}")
            update_data["username"] = username
        
        # Process bio and phone
        if profile_data.bio is not None:
            logger.info(f"✓ Bio set: {profile_data.bio[:50]}..." if len(profile_data.bio) > 50 else f"✓ Bio set: {profile_data.bio}")
            update_data["bio"] = profile_data.bio
        
        if profile_data.phone is not None:
            logger.info(f"✓ Phone set: {profile_data.phone}")
            update_data["phone"] = profile_data.phone
        
        # Process avatar
        if profile_data.avatar_url is not None:
            logger.info(f"✓ Avatar URL set: {profile_data.avatar_url}")
            update_data["avatar_url"] = profile_data.avatar_url
        
        if profile_data.avatar is not None:
            logger.info(f"✓ Avatar initials set: {profile_data.avatar}")
            update_data["avatar_url"] = profile_data.avatar  # Store avatar initials in avatar_url
        
        # Process email (enforce uniqueness)
        if profile_data.email is not None and profile_data.email.strip():
            logger.info(f"Processing email update: {profile_data.email}")
            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, profile_data.email):
                logger.warning(f"Email validation failed: invalid format for {profile_data.email}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid email format. Use format: user@example.com"
                )
            
            # Normalize email
            new_email = profile_data.email.lower().strip()
            logger.info(f"Email normalized: {new_email}")
            
            # Ensure no other user already uses this email
            existing = await asyncio.wait_for(
                users_collection().find_one({"email": new_email}),
                timeout=5.0
            )
            if existing and existing.get("_id") != current_user:
                logger.warning(f"Email already in use: {new_email} by {existing.get('_id')}")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already in use"
                )
            logger.info(f"✓ Email validation passed: {new_email}")
            update_data["email"] = new_email
        
        # Add updated timestamp
        update_data["updated_at"] = datetime.utcnow()
        
        logger.info(f"Update data prepared with fields: {list(update_data.keys())}")
        logger.info(f"Update data values: {json.dumps({k: str(v)[:100] if isinstance(v, str) else str(v) for k, v in update_data.items()}, default=str)}")
        
        # Update user profile in database
        logger.info(f"Executing database update...")
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": update_data}
            ),
            timeout=5.0
        )
        
        logger.info(f"Database update result:")
        logger.info(f"  - Matched documents: {result.matched_count}")
        logger.info(f"  - Modified documents: {result.modified_count}")
        
        if result.matched_count == 0:
            logger.error(f"User not found during update: {current_user}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if result.modified_count == 0:
            logger.warning(f"No documents were modified (may be identical data)")
        
        # Fetch and return updated user profile
        logger.info(f"Fetching updated user profile...")
        updated_user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not updated_user:
            logger.error(f"User not found after update: {current_user}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found after update"
            )
        
        logger.info(f"✓ Profile update successful!")
        logger.info(f"Updated user profile:")
        logger.info(f"  - ID: {updated_user.get('_id')}")
        logger.info(f"  - Name: {updated_user.get('name')}")
        logger.info(f"  - Username: {updated_user.get('username')}")
        logger.info(f"  - Email: {updated_user.get('email')}")
        logger.info(f"  - Updated at: {updated_user.get('updated_at')}")
        logger.info(f"{'='*80}")
        
        # Ensure all required fields for UserResponse are present with defaults if necessary
        return UserResponse(
            id=str(updated_user.get("_id", current_user)),
            name=str(updated_user.get("name", "User")),
            email=str(updated_user.get("email", "")),
            username=updated_user.get("username"),
            quota_used=int(updated_user.get("quota_used", 0)),
            quota_limit=int(updated_user.get("quota_limit", 42949672960)),
            created_at=updated_user.get("created_at", datetime.utcnow()),
            avatar_url=updated_user.get("avatar_url"),
            pinned_chats=updated_user.get("pinned_chats", []) or []
        )
    except asyncio.TimeoutError:
        logger.error(f"Database operation timed out")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except (ValueError, TypeError, KeyError, OSError) as e:
        logger.error(f"Error during profile update: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update profile: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected error during profile update: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}"
        )


@router.get("/stats")
async def get_user_stats(current_user: str = Depends(get_current_user)):
    """Get current user's statistics"""
    try:
        # Get user data
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Get message count from chats collection
        from database import chats_collection, messages_collection
        
        # Count total messages sent by user
        message_count = await asyncio.wait_for(
            messages_collection().count_documents({"sender_id": current_user}),
            timeout=5.0
        )
        
        # Count files shared by user
        from database import files_collection
        file_count = await asyncio.wait_for(
            files_collection().count_documents({"uploaded_by": current_user}),
            timeout=5.0
        )
        
        # Calculate storage usage
        quota_used = user.get("quota_used", 0)
        quota_limit = user.get("quota_limit", 1024 * 1024 * 1024)  # 1GB default
        
        return {
            "messages_sent": message_count,
            "files_shared": file_count,
            "storage_used_mb": round(quota_used / (1024 * 1024), 2),
            "storage_limit_mb": round(quota_limit / (1024 * 1024), 2),
            "storage_percentage": round((quota_used / quota_limit) * 100, 1) if quota_limit > 0 else 0,
            "account_created": user.get("created_at"),
            "last_active": user.get("last_active", datetime.utcnow())
        }
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch stats: {str(e)}"
        )


@router.get("/search")
async def search_users(q: str, current_user: str = Depends(get_current_user)):
    """Search users by name, email, or phone number"""
    
    if len(q) < 2:
        return {"users": []}
    
    try:
        # Sanitize regex input to prevent regex injection attacks
        # Escape special regex characters
        sanitized_q = re.escape(q)
        
        # Case-insensitive regex search - includes phone number
        users = []
        cursor = users_collection().find({
            "$or": [
                {"name": {"$regex": sanitized_q, "$options": "i"}},
                {"email": {"$regex": sanitized_q, "$options": "i"}},
                {"phone": {"$regex": sanitized_q, "$options": "i"}}
            ],
            "_id": {"$ne": current_user}  # Exclude current user
        }).limit(20)
        
        # Fetch results with timeout
        async def fetch_results():
            results = []
            async for user in cursor:
                results.append({
                    "id": user.get("_id", ""),
                    "name": user.get("name", ""),
                    "email": user.get("email", ""),
                    "phone": user.get("phone", ""),
                    "username": user.get("username", "")
                })
            return results
        
        users = await asyncio.wait_for(fetch_results(), timeout=5.0)
        return {"users": users}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Search operation timed out. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )


@router.get("/contacts")
async def list_contacts(current_user: str = Depends(get_current_user), limit: int = 50):
    """List users for contact selection (used for group creation)."""
    try:
        cursor = users_collection().find(
            {"_id": {"$ne": current_user}},
            {"_id": 1, "name": 1, "email": 1}
        ).sort("created_at", -1).limit(limit)

        async def fetch_results():
            results = []
            async for user in cursor:
                results.append({
                    "id": user.get("_id", ""),
                    "name": user.get("name", ""),
                    "email": user.get("email", ""),
                })
            return results

        users = await asyncio.wait_for(fetch_results(), timeout=5.0)
        return {"users": users}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch contacts: {str(e)}"
        )


@router.get("/permissions")
async def get_permissions(current_user: str = Depends(get_current_user)):
    """Get current user's app permissions"""
    try:
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Get permissions or return default (all denied)
        permissions = user.get("permissions", {
            "location": False,
            "camera": False,
            "microphone": False,
            "contacts": False,
            "phone": False,
            "storage": False
        })
        
        return permissions
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch permissions: {str(e)}"
        )


@router.put("/permissions")
async def update_permissions(
    permissions_data: PermissionsUpdate,
    current_user: str = Depends(get_current_user)
):
    """Update current user's app permissions"""
    try:
        # Prepare permissions dictionary
        permissions = {
            "location": permissions_data.location,
            "camera": permissions_data.camera,
            "microphone": permissions_data.microphone,
            "contacts": permissions_data.contacts,
            "phone": permissions_data.phone,
            "storage": permissions_data.storage
        }
        
        # Update user's permissions in database
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": {"permissions": permissions}}
            ),
            timeout=5.0
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {
            "message": "Permissions updated successfully",
            "permissions": permissions
        }
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update permissions: {str(e)}"
        )


# PasswordChangeRequest moved to backend.models


@router.post("/change-password")
async def change_password(
    request: PasswordChangeRequest,
    current_user: str = Depends(get_current_user)
):
    """Change user's password"""
    try:
        print(f"[PASSWORD_CHANGE] Request for user: {current_user}")
        
        if not request.old_password or not request.new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Old password and new password are required"
            )
        
        if request.new_password.strip() == "":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password cannot be empty"
            )
        
        if len(request.new_password) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be at least 6 characters"
            )
        
        # Get user from database
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Verify old password
        from backend.auth.utils import verify_password, hash_password
        
        if not verify_password(request.old_password, user.get("password_hash", "")):
            print(f"[PASSWORD_CHANGE] Old password verification failed for {current_user}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Old password is incorrect"
            )
        
        # Hash new password
        new_password_hash = hash_password(request.new_password)
        
        # Update password in database
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": {"password_hash": new_password_hash, "updated_at": datetime.utcnow()}}
            ),
            timeout=5.0
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        print(f"[PASSWORD_CHANGE] Successfully updated password for {current_user}")
        return {"message": "Password changed successfully"}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to change password: {str(e)}"
        )


# EmailChangeRequest moved to backend.models


@router.post("/change-email")
async def change_email(
    request: EmailChangeRequest,
    current_user: str = Depends(get_current_user)
):
    """Change user's email"""
    try:
        print(f"[EMAIL_CHANGE] Request for user: {current_user}")
        
        # Get user from database
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Verify password
        from backend.auth.utils import verify_password
        if not verify_password(request.password, user.get("password_hash", "")):
            print(f"[EMAIL_CHANGE] Password verification failed for {current_user}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password"
            )
        
        new_email = request.email.lower().strip()
        
        # Ensure no other user already uses this email
        existing = await asyncio.wait_for(
            users_collection().find_one({"email": new_email}),
            timeout=5.0
        )
        if existing and existing.get("_id") != current_user:
            print(f"[EMAIL_CHANGE] Email already in use by {existing.get('_id')}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use"
            )
        
        # Update email in database
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": {"email": new_email, "updated_at": datetime.utcnow()}}
            ),
            timeout=5.0
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        print(f"[EMAIL_CHANGE] Successfully updated email for {current_user} to {new_email}")
        return {"message": "Email changed successfully", "email": new_email}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to change email: {str(e)}"
        )


@router.post("/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    """Upload user avatar"""
    try:
        from backend.config import settings
        import shutil
        import os
        
        # Validate file type
        if not file.content_type.startswith("image/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an image"
            )
        
        # Create directory
        avatar_dir = settings.DATA_ROOT / "avatars"
        avatar_dir.mkdir(parents=True, exist_ok=True)
        
        # Save file
        file_ext = os.path.splitext(file.filename)[1]
        file_name = f"{current_user}{file_ext}"
        file_path = avatar_dir / file_name
        
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Generate URL
        avatar_url = f"/api/v1/users/avatar/{file_name}"
        
        # Update user in DB
        await users_collection().update_one(
            {"_id": current_user},
            {"$set": {"avatar_url": avatar_url, "updated_at": datetime.utcnow()}}
        )
        
        return {"avatar_url": avatar_url}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload avatar: {str(e)}"
        )


@router.get("/avatar/{filename}")
async def get_avatar(filename: str):
    """Get user avatar"""
    from backend.config import settings
    from fastapi.responses import FileResponse
    
    file_path = settings.DATA_ROOT / "avatars" / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Avatar not found")
    
    return FileResponse(file_path)
