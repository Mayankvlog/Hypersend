from fastapi import APIRouter, HTTPException, status, Depends
from backend.models import UserCreate, UserLogin, Token, RefreshTokenRequest, UserInDB, UserResponse
from backend.database import users_collection, refresh_tokens_collection
from backend.auth.utils import (
    hash_password, verify_password, create_access_token, 
    create_refresh_token, decode_token, get_current_user
)
from datetime import datetime
from bson import ObjectId

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    """Register a new user"""
    users = users_collection()
    
    # Check if user already exists
    existing_user = await users.find_one({"email": user.email})
    if existing_user:
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
    
    await users.insert_one(user_doc)
    
    return UserResponse(
        id=user_doc["_id"],
        name=user_doc["name"],
        email=user_doc["email"],
        quota_used=user_doc["quota_used"],
        quota_limit=user_doc["quota_limit"],
        created_at=user_doc["created_at"]
    )


@router.post("/login", response_model=Token)
async def login(credentials: UserLogin):
    """Login and receive JWT tokens"""
    users = users_collection()
    
    # Find user
    user = await users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    # Create tokens
    access_token = create_access_token(data={"sub": user["_id"]})
    refresh_token, jti = create_refresh_token(data={"sub": user["_id"]})
    
    # Store refresh token
    await refresh_tokens_collection().insert_one({
        "token": refresh_token,
        "jti": jti,
        "user_id": user["_id"],
        "created_at": datetime.utcnow()
    })
    
    return Token(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_request: RefreshTokenRequest):
    """Refresh access token using refresh token"""
    token_data = decode_token(refresh_request.refresh_token)
    
    if token_data.token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    
    # Verify refresh token exists in database
    stored_token = await refresh_tokens_collection().find_one({
        "token": refresh_request.refresh_token,
        "user_id": token_data.user_id
    })
    
    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Create new tokens
    access_token = create_access_token(data={"sub": token_data.user_id})
    new_refresh_token, new_jti = create_refresh_token(data={"sub": token_data.user_id})
    
    # Delete old refresh token and store new one
    await refresh_tokens_collection().delete_one({"token": refresh_request.refresh_token})
    await refresh_tokens_collection().insert_one({
        "token": new_refresh_token,
        "jti": new_jti,
        "user_id": token_data.user_id,
        "created_at": datetime.utcnow()
    })
    
    return Token(access_token=access_token, refresh_token=new_refresh_token)


@router.post("/logout")
async def logout(refresh_request: RefreshTokenRequest, current_user: str = Depends(get_current_user)):
    """Logout by revoking refresh token"""
    await refresh_tokens_collection().delete_one({
        "token": refresh_request.refresh_token,
        "user_id": current_user
    })
    return {"message": "Logged out successfully"}
