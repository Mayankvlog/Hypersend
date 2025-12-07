from fastapi import APIRouter, HTTPException, status, Depends
from backend.models import UserResponse
from backend.database import users_collection
from backend.auth.utils import get_current_user
import asyncio
from pydantic import BaseModel

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
        created_at=user["created_at"]
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
