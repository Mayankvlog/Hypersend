from fastapi import APIRouter, HTTPException, status, Depends
from backend.models import UserResponse
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
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    bio: Optional[str] = None
    phone: Optional[str] = None


@router.put("/profile")
async def update_profile(
    profile_data: ProfileUpdate,
    current_user: str = Depends(get_current_user)
):
    """Update current user's profile"""
    try:
        print(f"[PROFILE_UPDATE] Request for user: {current_user}")
        print(f"[PROFILE_UPDATE] Data received: name={profile_data.name}, email={profile_data.email}, username={profile_data.username}")
        
        # Prepare update data
        update_data = {}
        if profile_data.name is not None:
            update_data["name"] = profile_data.name
            print(f"[PROFILE_UPDATE] Name set to: {profile_data.name}")
        if profile_data.username is not None:
            update_data["username"] = profile_data.username
            print(f"[PROFILE_UPDATE] Username set to: {profile_data.username}")
        if profile_data.bio is not None:
            update_data["bio"] = profile_data.bio
        if profile_data.phone is not None:
            update_data["phone"] = profile_data.phone
        # Handle email separately to enforce uniqueness
        if getattr(profile_data, "email", None) is not None:
            # Normalize email
            new_email = profile_data.email.lower()
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
        return {
            "message": "Profile updated successfully",
            "updated_fields": list(update_data.keys())
        }
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
