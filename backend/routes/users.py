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
        
        if all(v is None for v in [profile_data.name, profile_data.email, profile_data.username, profile_data.bio, profile_data.phone, profile_data.avatar_url, profile_data.avatar]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No profile fields to update"
            )
        
        # Fetch the current user document
        logger.info(f"Fetching current user document...")
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        logger.info(f"Current user document fetched: {user}")
        
        # Get the current values from the database
        update_data = {}
        
        # Process name
        if profile_data.name is not None:
            logger.info(f"✓ Name set: {profile_data.name}")
            update_data["name"] = profile_data.name
        
        # Process email
        if profile_data.email is not None:
            logger.info(f"✓ Email set: {profile_data.email}")
            update_data["email"] = profile_data.email
        
        # Process bio and phone
        if profile_data.bio is not None:
            logger.info(f"✓ Bio set: {profile_data.bio}")
            update_data["bio"] = profile_data.bio
        
        if profile_data.phone is not None:
            logger.info(f"✓ Phone set: {profile_data.phone}")
            update_data["phone"] = profile_data.phone
        
        # Process username
        if profile_data.username is not None:
            logger.info(f"✓ Username set: {profile_data.username}")
            update_data["username"] = profile_data.username
        
        # Check if avatar needs to be updated
        if profile_data.avatar is not None:
            logger.info(f"Avatar data received (size: {len(profile_data.avatar)} bytes)")
            # For avatar, convert string to bytes if necessary
            avatar_bytes = profile_data.avatar
            if isinstance(avatar_bytes, str):
                avatar_bytes = avatar_bytes.encode()
            update_data["avatar"] = avatar_bytes
            logger.info(f"✓ Avatar set: {len(avatar_bytes)} bytes")
        
        # Handle avatar_url
        if profile_data.avatar_url is not None:
            logger.info(f"Avatar URL set: {profile_data.avatar_url}")
            update_data["avatar_url"] = profile_data.avatar_url
        
        # Log the update data
        logger.info(f"Update data prepared: {update_data}")
        
        # Perform the update
        logger.info(f"Updating user in database...")
        update_result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": update_data}
            ),
            timeout=5.0
        )
        
        if update_result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found for update"
            )
        
        logger.info(f"✓ Update successful: {update_result.modified_count} documents modified")
        
        # Fetch and return the updated user
        logger.info(f"Fetching updated user profile...")
        updated_user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found after update"
            )
        
        logger.info(f"✓ Updated user profile fetched successfully")
        logger.info(f"{'='*80}")
        
        return UserResponse(
            id=updated_user["_id"],
            name=updated_user["name"],
            email=updated_user["email"],
            username=updated_user.get("username"),
            quota_used=updated_user.get("quota_used", 0),
            quota_limit=updated_user.get("quota_limit", 42949672960),
            created_at=updated_user["created_at"],
            avatar_url=updated_user.get("avatar_url"),
            pinned_chats=updated_user.get("pinned_chats", [])
        )
    
    except asyncio.TimeoutError:
        logger.error("Database operation timed out")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Profile update timed out. Please try again."
        )
    except HTTPException as e:
        logger.error(f"HTTP Exception: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Profile update failed: {str(e)}"
        )


@router.get("/search")
async def search_users(q: str, current_user: str = Depends(get_current_user)):
    """Search users by name, email, or phone number"""
    
    if len(q) < 2:
        return {"users": []}
    
    try:
        # Case-insensitive regex search - includes phone number
        users = []
        cursor = users_collection().find({
            "$or": [
                {"name": {"$regex": q, "$options": "i"}},
                {"email": {"$regex": q, "$options": "i"}},
                {"phone": {"$regex": q, "$options": "i"}}
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
                    "email": user["email"],
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
        
        # Fetch all results with timeout
        async def fetch_all():
            contacts = []
            async for user in cursor:
                contacts.append({
                    "id": user["_id"],
                    "name": user.get("name", ""),
                    "email": user.get("email", "")
                })
            return contacts
        
        contacts = await asyncio.wait_for(fetch_all(), timeout=5.0)
        return {"contacts": contacts}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Contacts fetch timed out. Please try again."
        )
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch contacts: {str(e)}"
        )


@router.post("/block/{user_id}")
async def block_user(user_id: str, current_user: str = Depends(get_current_user)):
    """Block a user"""
    if user_id == current_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot block yourself"
        )
    
    try:
        # Add to blocked list
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$addToSet": {"blocked_users": user_id}}
            ),
            timeout=5.0
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {"message": "User blocked successfully"}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Operation timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to block user: {str(e)}"
        )


@router.post("/unblock/{user_id}")
async def unblock_user(user_id: str, current_user: str = Depends(get_current_user)):
    """Unblock a user"""
    try:
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$pull": {"blocked_users": user_id}}
            ),
            timeout=5.0
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {"message": "User unblocked successfully"}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Operation timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to unblock user: {str(e)}"
        )


@router.get("/blocked")
async def get_blocked_users(current_user: str = Depends(get_current_user)):
    """Get list of blocked users"""
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
        
        blocked_ids = user.get("blocked_users", [])
        
        # Fetch blocked user details
        blocked_users = []
        async for blocked_user in users_collection().find({"_id": {"$in": blocked_ids}}):
            blocked_users.append({
                "id": blocked_user["_id"],
                "name": blocked_user.get("name"),
                "email": blocked_user.get("email")
            })
        
        return {"blocked_users": blocked_users}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Operation timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get blocked users: {str(e)}"
        )


@router.post("/permissions")
async def update_permissions(
    permissions: PermissionsUpdate,
    current_user: str = Depends(get_current_user)
):
    """Update user permissions"""
    try:
        update_data = {
            "permissions": {
                "location": permissions.location,
                "camera": permissions.camera,
                "microphone": permissions.microphone,
                "contacts": permissions.contacts,
                "phone": permissions.phone,
                "storage": permissions.storage
            }
        }
        
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": update_data}
            ),
            timeout=5.0
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {"message": "Permissions updated successfully"}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Operation timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update permissions: {str(e)}"
        )


@router.get("/permissions")
async def get_permissions(current_user: str = Depends(get_current_user)):
    """Get user permissions"""
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
        
        permissions_data = user.get("permissions", {})
        
        return {
            "location": permissions_data.get("location", False),
            "camera": permissions_data.get("camera", False),
            "microphone": permissions_data.get("microphone", False),
            "contacts": permissions_data.get("contacts", False),
            "phone": permissions_data.get("phone", False),
            "storage": permissions_data.get("storage", False)
        }
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Operation timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get permissions: {str(e)}"
        )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, current_user: str = Depends(get_current_user)):
    """Get user by ID"""
    try:
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": user_id}),
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
