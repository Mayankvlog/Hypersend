from fastapi import APIRouter, HTTPException, status, Depends
from backend.models import UserResponse
from backend.database import users_collection
from backend.auth.utils import get_current_user

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: str = Depends(get_current_user)):
    """Get current user profile"""
    user = await users_collection().find_one({"_id": current_user})
    
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
    
    # Case-insensitive regex search
    users = []
    async for user in users_collection().find({
        "$or": [
            {"name": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}}
        ],
        "_id": {"$ne": current_user}  # Exclude current user
    }).limit(20):
        users.append({
            "id": user["_id"],
            "name": user["name"],
            "email": user["email"]
        })
    
    return {"users": users}
