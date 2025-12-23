from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File
from backend.models import UserResponse, UserInDB
from backend.database import users_collection
from backend.auth.utils import get_current_user
import asyncio
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional

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
        quota_used=user["quota_used"],
        quota_limit=user["quota_limit"],
        created_at=user["created_at"],
        pinned_chats=user.get("pinned_chats", []) or []
    )


class ProfileUpdate(BaseModel):
    """Profile update model"""
    name: Optional[str] = None
    email: Optional[str] = None  # Use str instead of EmailStr to allow custom validation
    username: Optional[str] = None
    bio: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None


@router.put("/profile", response_model=UserResponse)
async def update_profile(
    profile_data: ProfileUpdate,
    current_user: str = Depends(get_current_user)
):
    """Update current user's profile"""
    try:
        print(f"[PROFILE_UPDATE] Request for user: {current_user}")
        print(f"[PROFILE_UPDATE] Data received: {profile_data}")
        print(f"[PROFILE_UPDATE] Details - name={profile_data.name}, email={profile_data.email}, username={profile_data.username}")
        
        # Check if at least one field is being updated
        if all(v is None for v in [profile_data.name, profile_data.email, profile_data.username, profile_data.bio, profile_data.phone]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one field must be provided to update"
            )
        
        # Prepare update data
        update_data = {}
        if profile_data.name is not None:
            name = profile_data.name.strip()
            if not name:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Name cannot be empty"
                )
            if len(name) < 2:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Name must be at least 2 characters"
                )
            update_data["name"] = name
            print(f"[PROFILE_UPDATE] Name set to: {name}")
        if profile_data.username is not None:
            username = profile_data.username.strip()
            if not username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username cannot be empty"
                )
            update_data["username"] = username
            print(f"[PROFILE_UPDATE] Username set to: {username}")
        if profile_data.bio is not None:
            update_data["bio"] = profile_data.bio
        if profile_data.phone is not None:
            update_data["phone"] = profile_data.phone
        if profile_data.avatar_url is not None:
            update_data["avatar_url"] = profile_data.avatar_url
        # Handle email separately to enforce uniqueness
        if profile_data.email is not None and profile_data.email.strip():
            # Validate email format
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, profile_data.email):
                print(f"[PROFILE_UPDATE] Invalid email format: {profile_data.email}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid email format. Use format: user@example.com"
                )
            
            # Normalize email
            new_email = profile_data.email.lower().strip()
            print(f"[PROFILE_UPDATE] Email update requested: {new_email}")
            # Ensure no other user already uses this email
            existing = await asyncio.wait_for(
                users_collection().find_one({"email": new_email}),
                timeout=5.0
            )
            if existing and existing.get("_id") != current_user:
                print(f"[PROFILE_UPDATE] Email already in use by {existing.get('_id')}")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already in use"
                )
            update_data["email"] = new_email
            print(f"[PROFILE_UPDATE] Email validated and set to: {new_email}")
        
        # Add updated timestamp
        update_data["updated_at"] = datetime.utcnow()
        
        print(f"[PROFILE_UPDATE] Update data: {list(update_data.keys())}")
        
        # Update user profile in database
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": update_data}
            ),
            timeout=5.0
        )
        
        print(f"[PROFILE_UPDATE] DB result - matched: {result.matched_count}, modified: {result.modified_count}")
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        print(f"[PROFILE_UPDATE] Success - updated {result.modified_count} documents")
        
        # Fetch and return updated user profile
        updated_user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found after update"
            )
        
        print(f"[PROFILE_UPDATE] Returning updated user: {updated_user['_id']}")
        return UserResponse(
            id=updated_user["_id"],
            name=updated_user["name"],
            email=updated_user["email"],
            quota_used=updated_user["quota_used"],
            quota_limit=updated_user["quota_limit"],
            created_at=updated_user["created_at"],
            avatar_url=updated_user.get("avatar_url"),
            pinned_chats=updated_user.get("pinned_chats", []) or []
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update profile: {str(e)}"
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
    """Search users by name or email"""
    
    if len(q) < 2:
        return {"users": []}
    
    try:
        # Case-insensitive regex search
        users = []
        cursor = users_collection().find({
            "$or": [
                {"name": {"$regex": q, "$options": "i"}},
                {"email": {"$regex": q, "$options": "i"}}
            ],
            "_id": {"$ne": current_user}  # Exclude current user
        }).limit(20)
        
        # Fetch results with timeout
        async def fetch_results():
            results = []
            async for user in cursor:
                results.append({
                    "id": user["_id"],
                    "name": user["name"],
                    "email": user["email"]
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
                    "id": user["_id"],
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


class PasswordChangeRequest(BaseModel):
    """Password change request model"""
    old_password: str
    new_password: str


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
        
        if len(request.new_password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be at least 8 characters"
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
        from backend.security import verify_password, hash_password
        
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


class EmailChangeRequest(BaseModel):
    """Email change request model"""
    email: EmailStr
    password: str


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
        from backend.security import verify_password
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

