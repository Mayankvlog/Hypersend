from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File, Request
from fastapi.responses import JSONResponse
from models import (
    UserResponse, UserInDB, PasswordChangeRequest, EmailChangeRequest, ProfileUpdate,
    UserSearchResponse, GroupCreate, GroupUpdate, GroupMembersUpdate, GroupMemberRoleUpdate, ChatPermissions
)
from db_proxy import users_collection, chats_collection, messages_collection, files_collection, uploads_collection, refresh_tokens_collection, get_db
from auth.utils import get_current_user, get_current_user_optional, get_current_user_or_query
import asyncio
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
from config import settings
from typing import Optional
import re
import json
import math
import logging
from bson import ObjectId

# Import create_group function from groups module
from routes.groups import create_group


async def _log_group_activity(group_id: str, actor_id: str, event: str, meta: Optional[dict] = None):
    """Log group activity for auditing"""
    try:
        db = get_db()
        col = db.group_activity
        doc = {
            "_id": str(ObjectId()),
            "group_id": group_id,
            "actor_id": actor_id,
            "event": event,
            "meta": meta or {},
            "created_at": datetime.now(timezone.utc)
        }
        await col.insert_one(doc)
    except Exception:
        # Silently fail logging to avoid breaking main flow
        pass

# Set up detailed logging for profile operations
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

def _log(level: str, message: str, user_data: dict = None):
    """Helper method for consistent logging with PII protection"""
    if user_data:
        # Remove PII from logs in production
        safe_data = {
            "user_id": user_data.get("user_id", "unknown"),
            "operation": user_data.get("operation", "unknown"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        safe_message = f"{message} (user: {safe_data['user_id']})"
    else:
        safe_message = message
    
    if level.lower() == "error":
        logger.error(safe_message)
    elif level.lower() == "warning":
        logger.warning(safe_message)
    elif level.lower() == "info":
        logger.info(safe_message)
    else:
        logger.debug(safe_message)


router = APIRouter(prefix="/users", tags=["Users"])


class PermissionsUpdate(BaseModel):
    """Permissions update model"""
    location: bool = False
    camera: bool = False
    microphone: bool = False
    storage: bool = False


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: str = Depends(get_current_user)):
    """Get current user profile"""
    try:
        # Add a 5-second timeout to prevent hanging
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
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
            bio=user.get("bio"),
            avatar=user.get("avatar"),
            avatar_url=user.get("avatar_url"),
            quota_used=user.get("quota_used", 0),
            quota_limit=user.get("quota_limit", 42949672960),
            created_at=user["created_at"],
            updated_at=user.get("updated_at"),
            last_seen=user.get("last_seen"),
            is_online=user.get("is_online", False),
            status=user.get("status"),
            pinned_chats=user.get("pinned_chats", []),
            is_contact=False  # Current user can't be a contact of themselves
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


# ProfileUpdate model is imported from models


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
        
        # Log the received data
        logger.info(f"Received ProfileUpdate model:")
        logger.info(f"  - name: {profile_data.name} (type: {type(profile_data.name).__name__})")
        logger.info(f"  - username: {profile_data.username} (type: {type(profile_data.username).__name__})")
        logger.info(f"  - avatar: {profile_data.avatar} (type: {type(profile_data.avatar).__name__})")
        logger.info(f"  - bio: [REDACTED_FOR_PRIVACY] (type: {type(profile_data.bio).__name__})")
        logger.info(f"  - avatar_url: {profile_data.avatar_url} (type: {type(profile_data.avatar_url).__name__})")
        logger.debug(f"[EMAIL_PII] Email fields present but not logged for privacy")
        
        # Check if at least one field is being updated
        if all(v is None for v in [profile_data.name, profile_data.email, profile_data.username, profile_data.bio, profile_data.avatar_url, profile_data.avatar]):
            logger.warning(f"No fields provided for update - all are None")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one field must be provided to update"
            )
        
        # Get current user data from the database
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
        
        # Prepare the update data
        update_data = {}
        
        # Process the name
        if profile_data.name is not None and len(profile_data.name.strip()) > 0:
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
            logger.info(f"SUCCESS: Name validation passed: {name}")
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
            # Check if the username is already taken
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
            logger.info(f"SUCCESS: Username validation passed: {username}")
            update_data["username"] = username
        
# Process the bio and phone
        if profile_data.bio is not None:
            # Validate bio length and content
            if len(profile_data.bio) > 500:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Bio/Status is too long. Maximum 500 characters allowed."
                )
            # Basic content sanitization
            import re
            sanitized_bio = re.sub(r'[<>"\']', '', profile_data.bio.strip())
            if sanitized_bio != profile_data.bio.strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Bio/Status contains invalid characters. Please use plain text only."
                )
            logger.info(f"SUCCESS: Bio set: [REDACTED_FOR_PRIVACY]")
            update_data["bio"] = sanitized_bio
        

        
        # Process the avatar
        if profile_data.avatar_url is not None:
            logger.info(f"SUCCESS: Avatar URL set: {profile_data.avatar_url}")
            update_data["avatar_url"] = profile_data.avatar_url
        
        if profile_data.avatar is not None:
            logger.info(f"SUCCESS: Avatar initials set: {profile_data.avatar}")
            update_data["avatar"] = profile_data.avatar  # Store avatar initials in the avatar field
        
        # Process email (enforce uniqueness)
        if profile_data.email is not None and profile_data.email.strip():
            logger.info(f"Processing email field update")
            # Validate the email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, profile_data.email):
                logger.warning(f"Email validation failed: invalid format")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid email format. Use format: user@zaply.in.net"
                )
            
            # Normalize the email
            new_email = profile_data.email.lower().strip()
            logger.info(f"Email field normalized")
            
            # Ensure no other user already uses this email
            existing = await asyncio.wait_for(
                users_collection().find_one({"email": new_email}),
                timeout=5.0
            )
            if existing and existing.get("_id") != current_user:
                logger.warning(f"Email field is already in use")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already in use"
                )
            logger.info(f"SUCCESS: Email field validation passed")
            update_data["email"] = new_email
        
        # Add updated timestamp
        update_data["updated_at"] = datetime.now(timezone.utc)
        
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
        
        logger.info(f"SUCCESS: Profile update successful!")
        logger.info(f"Updated user profile:")
        logger.info(f"  - ID: {updated_user.get('_id')}")
        logger.info(f"  - Name: {updated_user.get('name')}")
        logger.info(f"  - Username: {updated_user.get('username')}")
        logger.info(f"  - Updated at: {updated_user.get('updated_at')}")
        logger.info(f"{'='*80}")
        
        # Ensure all required fields for UserResponse are present with defaults if necessary
        return UserResponse(
            id=updated_user["_id"],
            name=updated_user["name"],
            email=updated_user["email"],
            username=updated_user.get("username"),
            bio=updated_user.get("bio"),
            avatar=updated_user.get("avatar"),
            avatar_url=updated_user.get("avatar_url"),
            quota_used=int(updated_user.get("quota_used", 0)),
            quota_limit=int(updated_user.get("quota_limit", 42949672960)),
            created_at=updated_user.get("created_at"),  # Let it be None if missing
            updated_at=updated_user.get("updated_at"),
            last_seen=updated_user.get("last_seen"),
            is_online=updated_user.get("is_online", False),
            status=updated_user.get("status"),
            pinned_chats=updated_user.get("pinned_chats", []) or [],
            is_contact=False  # Current user can't be a contact of themselves
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
        
        # Count total messages sent by user
        message_count = await asyncio.wait_for(
            messages_collection().count_documents({"sender_id": current_user}),
            timeout=5.0
        )
        
        # Count files shared by user
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
            "last_active": user.get("last_active", datetime.now(timezone.utc))
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
async def search_users(q: str, search_type: str = None, current_user: str = Depends(get_current_user)):
    """Search users by name, email, or username with intelligent prioritization
    
    Args:
        q: Search query string
        search_type: Optional - 'email', 'username', or None for auto-detection
        current_user: Current authenticated user ID
    """
    
    if len(q) < 2:
        return {"users": []}
    
    try:
        # Sanitize input for regex search to prevent injection
        sanitized_q = re.escape(q)
        
        # Determine search type - use provided search_type or auto-detect
        if search_type and search_type in ["email", "username"]:
            actual_search_type = search_type
        else:
            actual_search_type = _determine_search_type(q)
        
        users = []
        
        # Build prioritized search query based on detected search type
        if actual_search_type == "email":
            # Email search - exact email matches first, then username/name
            search_query = {
                "$or": [
                    {"email": {"$regex": sanitized_q, "$options": "i"}},  # Email exact match
                    {"username": {"$regex": sanitized_q, "$options": "i"}},  # Username fallback
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name fallback
                ],
                "_id": {"$ne": current_user}
            }
        elif actual_search_type == "username":
            # Username search - prioritized exact username match
            search_query = {
                "$or": [
                    {"username": {"$regex": sanitized_q, "$options": "i"}},  # Username priority
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name fallback
                ],
                "_id": {"$ne": current_user}
            }
        else:
            # General name search
            search_query = {
                "$or": [
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name priority
                    {"username": {"$regex": sanitized_q, "$options": "i"}},  # Username fallback
                ],
                "_id": {"$ne": current_user}
            }
        
        cursor = users_collection().find(search_query).limit(20)
        
        # Fetch results with timeout and scoring
        async def fetch_results():
            results = []
            async for user in cursor:
                score = _calculate_search_score(user, q, actual_search_type)
                results.append({
                    "id": user.get("_id", ""),
                    "name": user.get("name", ""),
                    "email": user.get("email", ""),
                    "username": user.get("username", ""),
                    "relevance_score": score
                })
            
            # Sort by relevance score (highest first)
            results.sort(key=lambda x: x["relevance_score"], reverse=True)
            return results
        
        users = await asyncio.wait_for(fetch_results(), timeout=5.0)
        return {"users": users}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Search operation timed out. Please try again."
        )


def _determine_search_type(query: str) -> str:
    """Determine the type of search based on query characteristics"""
    
    # Email detection
    if '@' in query and '.' in query.split('@')[-1]:
        return "email"
    
    # Username detection - starts with @ or contains underscores/hyphens
    if query.startswith('@') or '_' in query or '-' in query:
        return "username"
    
    return "general"


def _calculate_search_score(user: dict, query: str, search_type: str) -> int:
    """Calculate relevance score for search results (higher = more relevant)"""
    try:
        score = 0
        
        query_lower = query.lower()
        name = str(user.get("name", "")).lower()
        email = str(user.get("email", "")).lower()
        username = str(user.get("username", "")).lower()
        
        # Exact matches get highest scores
        if search_type == "email" and email == query_lower:
            score += 100
        elif search_type == "username" and username == query_lower.lstrip('@'):
            score += 85
        
        # Prefix matches
        if name.startswith(query_lower):
            score += 50
        elif username.startswith(query_lower.lstrip('@')):
            score += 45
        
        # Contains matches
        if query_lower in name:
            score += 30
        if query_lower in username:
            score += 25
        if query_lower in email:
            score += 20
        
        return score
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )


@router.get("/nearby")
async def get_nearby_users(
    lat: float,
    lng: float,
    radius: float = 1000,  # Default 1km in meters
    current_user: str = Depends(get_current_user)
):
    """Find nearby users within specified radius (in meters).
    
    Args:
        lat: Latitude of current location
        lng: Longitude of current location
        radius: Search radius in meters (default 1000m = 1km)
    
    Returns:
        List of nearby users with distance information
    """
    try:
        # Earth's radius in meters
        EARTH_RADIUS = 6371000
        
        # Convert radius to radians
        radius_radians = radius / EARTH_RADIUS
        
        # Validate coordinates
        if not (-90 <= lat <= 90) or not (-180 <= lng <= 180):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid coordinates. Latitude must be -90 to 90, Longitude must be -180 to 180"
            )
        
        # MongoDB geospatial query using $geoWithin with $centerSphere
        # First, ensure location field exists and has index
        nearby_users = await asyncio.wait_for(
            users_collection().find(
                {
                    "location": {"$exists": True, "$ne": None},
                    "_id": {"$ne": current_user},  # Exclude self
                    "location.lat": {
                        "$gte": lat - (radius / 111320),  # Approximate: 1 degree ≈ 111.32 km
                        "$lte": lat + (radius / 111320)
                    },
                    "location.lng": {
                        "$gte": lng - (radius / (111320 * abs(math.cos(math.radians(lat))))),
                        "$lte": lng + (radius / (111320 * abs(math.cos(math.radians(lat)))))
                    }
                },
                {
                    "_id": 1,
                    "name": 1,
                    "username": 1,
                    "avatar_url": 1,
                    "is_online": 1,
                    "location": 1
                }
            ).limit(50),
            timeout=5.0
        )
        
        # Calculate distances for each user
        import math
        users_with_distance = []
        
        async for user in nearby_users:
            user_lat = user.get("location", {}).get("lat")
            user_lng = user.get("location", {}).get("lng")
            
            if user_lat is None or user_lng is None:
                continue
            
            # Haversine formula to calculate distance
            dlat = math.radians(user_lat - lat)
            dlng = math.radians(user_lng - lng)
            a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat)) * math.cos(math.radians(user_lat)) * math.sin(dlng / 2) ** 2
            c = 2 * math.asin(math.sqrt(a))
            distance = EARTH_RADIUS * c
            
            if distance <= radius:  # Double-check distance
                users_with_distance.append({
                    "id": str(user.get("_id", "")),
                    "name": user.get("name", ""),
                    "username": user.get("username", ""),
                    "avatar_url": user.get("avatar_url"),
                    "is_online": user.get("is_online", False),
                    "distance_meters": round(distance, 2)
                })
        
        # Sort by distance (closest first)
        users_with_distance.sort(key=lambda u: u["distance_meters"])
        
        return {
            "nearby_users": users_with_distance,
            "count": len(users_with_distance),
            "search_radius_meters": radius,
            "center": {"lat": lat, "lng": lng}
        }
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except (ValueError, TypeError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid parameters: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to find nearby users: {str(e)}"
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


# Group Chat Creation Endpoint

@router.post("/create-group")
async def create_group_endpoint(
    payload: GroupCreate,
    current_user: str = Depends(get_current_user)
):
    try:
        member_ids = list(dict.fromkeys([*(payload.member_ids or []), current_user]))
        if len(member_ids) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Group must have at least 2 members"
            )
        
        from routes.groups import create_group as create_group_helper
        group_result = await create_group_helper(payload, current_user)
        
        return {
            "group_id": group_result["group_id"],
            "chat_id": group_result["chat_id"], 
            "group": group_result["group"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create group: {str(e)}"
        )


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
        from auth.utils import verify_password, hash_password
        
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
                {"$set": {"password_hash": new_password_hash, "updated_at": datetime.now(timezone.utc)}}
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
        from auth.utils import verify_password
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
                {"$set": {"email": new_email, "updated_at": datetime.now(timezone.utc)}}
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


@router.delete("/account")
async def delete_account(
    current_user: str = Depends(get_current_user)
):
    """Delete user account permanently"""
    try:
        print(f"[ACCOUNT_DELETE] Delete request for user: {current_user}")
        logger.info(f"Account deletion request for user: {current_user}")
        
        # Get user to verify they exist
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Delete user avatar file if exists
        try:
            if user.get("avatar_url") and user["avatar_url"].startswith("/api/v1/users/avatar/"):
                avatar_filename = user["avatar_url"].split("/")[-1]
                avatar_path = settings.DATA_ROOT / "avatars" / avatar_filename
                if avatar_path.exists():
                    avatar_path.unlink()
                    logger.info(f"Deleted avatar file for user: {current_user}")
        except Exception as e:
            logger.warning(f"Failed to delete avatar file: {e}")
            # Continue anyway - user deletion is more important
        
        # Delete all user's chats (both 1-to-1 and groups)
        try:
            chats = await asyncio.wait_for(
                chats_collection().find({"members": {"$in": [current_user]}}).to_list(None),
                timeout=10.0
            )
            
            for chat in chats:
                chat_id = chat["_id"]
                members = chat.get("members", [])
                
                if len(members) == 2:
                    # 1-to-1 chat - delete it
                    await asyncio.wait_for(
                        chats_collection().delete_one({"_id": chat_id}),
                        timeout=5.0
                    )
                else:
                    # Group chat - just remove user from members
                    await asyncio.wait_for(
                        chats_collection().update_one(
                            {"_id": chat_id},
                            {"$pull": {"members": current_user}}
                        ),
                        timeout=5.0
                    )
            
            logger.info(f"Deleted/updated {len(chats)} chats for user: {current_user}")
        except Exception as e:
            logger.warning(f"Failed to delete chats: {e}")
        
        # Delete all user's messages
        try:
            result = await asyncio.wait_for(
                messages_collection().delete_many({"sender_id": current_user}),
                timeout=10.0
            )
            logger.info(f"Deleted {result.deleted_count} messages for user: {current_user}")
        except Exception as e:
            logger.warning(f"Failed to delete messages: {e}")
        
        # Delete all user's files
        try:
            result = await asyncio.wait_for(
                files_collection().delete_many({"owner_id": current_user}),
                timeout=10.0
            )
            logger.info(f"Deleted {result.deleted_count} files for user: {current_user}")
        except Exception as e:
            logger.warning(f"Failed to delete files: {e}")
        
        # Delete all refresh tokens
        try:
            await asyncio.wait_for(
                refresh_tokens_collection().delete_many({"user_id": current_user}),
                timeout=5.0
            )
            logger.info(f"Deleted refresh tokens for user: {current_user}")
        except Exception as e:
            logger.warning(f"Failed to delete refresh tokens: {e}")
        
        # Finally, delete the user document
        result = await asyncio.wait_for(
            users_collection().delete_one({"_id": current_user}),
            timeout=5.0
        )
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        print(f"[ACCOUNT_DELETE] SUCCESS: Successfully deleted account for user: {current_user}")
        logger.info(f"SUCCESS: Account deleted successfully for user: {current_user}")
        
        return {"message": "Account deleted successfully"}
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Account deletion error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete account: {str(e)}"
        )


@router.post("/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    request: Request = None,
    current_user: str = Depends(get_current_user_or_query)
):
    """Upload user avatar - POST endpoint (requires authentication, returns avatar_url)"""
    try:
        import aiofiles
        import os
        import uuid
        
        print(f"[AVATAR_UPLOAD] POST /avatar endpoint called for user: {current_user}")
        print(f"[AVATAR_UPLOAD] Request method: {request.method if request else 'No request'}")
        print(f"[AVATAR_UPLOAD] Request URL: {request.url if request else 'No request'}")
        logger.debug(f"Avatar upload POST request started for user: {current_user}")
        logger.debug(f"Request headers: {dict(request.headers) if request else 'No request object'}")
        logger.debug(f"File object: {file}")
        logger.debug(f"File filename: {file.filename}")
        logger.debug(f"File content type: {file.content_type}")
        
        # User must be authenticated
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required for avatar upload"
            )
        
        logger.debug(f"Using authenticated mode for user: {current_user}")
        
        logger.debug(f"File content-type: {file.content_type}")
        
        # Validate file type
        if not file.content_type or not file.content_type.startswith("image/"):
            logger.warning("Invalid content type for avatar upload")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an image"
            )
        
        # Create directory
        avatar_dir = settings.DATA_ROOT / "avatars"
        try:
            avatar_dir.mkdir(parents=True, exist_ok=True)
            logger.debug("Avatar storage directory created/verified")
        except Exception as dir_error:
            logger.error(f"Failed to create avatar directory: {dir_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create avatar storage directory"
            )
        
        # Generate unique filename to avoid conflicts
        file_ext = os.path.splitext(file.filename)[1].lower()
        if not file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported image format"
            )
        
        # Security: Generate secure filename
        unique_id = str(uuid.uuid4())
        # Sanitize user ID to prevent path issues
        safe_user_id = "".join(c for c in current_user if c.isalnum())[:16]
        if not safe_user_id:
            safe_user_id = "user"
        
        new_file_name = f"{safe_user_id}_{unique_id}{file_ext}"
        
        # Security: Validate complete filename - allow UUID patterns with underscores and hyphens
        import re
        if not re.match(r'^[a-zA-Z0-9_.-]+\.[a-zA-Z0-9]+$', new_file_name):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Filename generation failed"
            )
        
        new_file_path = avatar_dir / new_file_name
        
        # Save the new file FIRST before doing anything else (using async file operations)
        try:
            # Reset file position to start
            await file.seek(0)
            
            # Use async file operations
            async with aiofiles.open(new_file_path, "wb") as buffer:
                content = await file.read()
                logger.debug(f"Read {len(content)} bytes from file")
                await buffer.write(content)
            
            logger.debug("Avatar file saved successfully")
            if new_file_path.exists():
                file_size = new_file_path.stat().st_size
                logger.debug(f"File size verified: {file_size} bytes")
            else:
                logger.error("File was not created successfully")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to save file - file not created"
                )
        except Exception as save_error:
            logger.error(f"Failed to save avatar file: {save_error}")
            logger.error(f"File path attempted: {new_file_path}")
            logger.error(f"Directory exists: {avatar_dir.exists()}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save file"
            )
        
        # Generate URL AFTER file is saved
        avatar_url = f"/api/v1/users/avatar/{new_file_name}"
        logger.debug("Avatar URL generated")
        
        # Clean up old avatar files AFTER saving new file
        try:
            user = await asyncio.wait_for(
                users_collection().find_one({"_id": current_user}),
                timeout=5.0
            )
            if user and "avatar_url" in user:
                old_avatar_url = user["avatar_url"]
                if old_avatar_url and old_avatar_url.startswith("/api/v1/users/avatar/"):
                    old_filename = old_avatar_url.split("/")[-1]
                    old_file_path = avatar_dir / old_filename
                    if old_file_path.exists():
                        try:
                            old_file_path.unlink()
                            logger.debug("Cleaned up old avatar file")
                        except Exception as delete_error:
                            logger.warning(f"Could not delete old avatar: {delete_error}")
        except Exception as cleanup_error:
            logger.warning(f"Cleanup error while checking old avatar: {cleanup_error}")
            # Continue anyway - new file is already saved
        
        # Update the user in the database with timeout
        updated_user = None
        try:
            result = await asyncio.wait_for(
                users_collection().update_one(
                    {"_id": current_user},
                    {"$set": {"avatar_url": avatar_url, "updated_at": datetime.now(timezone.utc)}}
                ),
                timeout=5.0
            )
            
            # Fetch updated user to return complete data
            updated_user = await asyncio.wait_for(
                users_collection().find_one({"_id": current_user}),
                timeout=5.0
            )
            if not updated_user:
                logger.warning("User not found in database - file still saved")
                # Don't raise - file is already saved
            else:
                logger.debug("Database updated with avatar URL")
                
        except asyncio.TimeoutError:
            logger.warning("Database update timed out - file still saved")
            # Don't fail - file is already saved
        except Exception as db_error:
            logger.warning(f"Database update failed: {db_error} - file still saved")
            # Don't fail - file is already saved, user can still download via URL
        
        # Return response that matches frontend expectations
        # Frontend specifically looks for 'avatar_url' field in profile_service.dart:178-182
        current_avatar = updated_user.get("avatar") if updated_user else None
        response_data = {
            "avatar_url": avatar_url,  # REQUIRED: Frontend expects this field
            # Keep avatar field for frontend compatibility
            "avatar": current_avatar if current_avatar else "",
            "success": True,
            "message": "Avatar uploaded successfully"
        }
        logger.debug(f"Avatar upload completed successfully: avatar_url={avatar_url}, avatar={response_data['avatar']}")
        
        # Validate response data before sending
        if not isinstance(response_data, dict):
            logger.error(f"Response data is not a dict: {type(response_data)}")
            response_data = {"avatar_url": avatar_url, "avatar": "", "success": False, "message": "Internal error"}
        
        if "avatar_url" not in response_data:
            logger.error("avatar_url missing from response_data")
            response_data["avatar_url"] = avatar_url
            
        if "avatar" not in response_data:
            response_data["avatar"] = current_avatar if current_avatar else ""
            
        logger.debug(f"Final response data: {response_data}")
        return JSONResponse(status_code=200, content=response_data)
        
    except HTTPException as http_exc:
        logger.warning(f"HTTP error in avatar upload: {http_exc.status_code} - {http_exc.detail}")
        raise
    except Exception as e:
        import traceback
        logger.error(f"Unexpected error in avatar upload: {type(e).__name__}: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        _log("error", f"Unexpected avatar upload error: {str(e)}", {"user_id": current_user, "operation": "avatar_upload"})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload avatar: {str(e)}"
        )


@router.post("/avatar-upload")
@router.post("/avatar-upload/")
async def upload_avatar_alt(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user_or_query)
):
    """Alternative avatar upload endpoint - same as /avatar/ but with different name"""
    try:
        logger.debug("Alternative avatar upload endpoint called")
        
        import aiofiles
        import os
        import uuid
        
        # Validate file type
        if not file.content_type or not file.content_type.startswith("image/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an image"
            )
        
        # Create directory
        avatar_dir = settings.DATA_ROOT / "avatars"
        avatar_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename
        file_ext = os.path.splitext(file.filename)[1].lower()
        if not file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported image format"
            )
        
        unique_id = str(uuid.uuid4())[:8]
        new_file_name = f"{current_user}_{unique_id}{file_ext}"
        new_file_path = avatar_dir / new_file_name
        
        # Save file using async operations
        await file.seek(0)
        async with aiofiles.open(new_file_path, "wb") as buffer:
            content = await file.read()
            await buffer.write(content)
        
        # Generate URL
        avatar_url = f"/api/v1/users/avatar/{new_file_name}"
        
        # Update database and fetch updated user
        updated_user = None
        try:
            await asyncio.wait_for(
                users_collection().update_one(
                    {"_id": current_user},
                    {"$set": {"avatar_url": avatar_url, "updated_at": datetime.now(timezone.utc)}}
                ),
                timeout=5.0
            )
            
            # Fetch updated user to return complete data
            updated_user = await asyncio.wait_for(
                users_collection().find_one({"_id": current_user}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            logger.warning("Database update timed out")
        except Exception as db_error:
            logger.warning(f"Database update failed: {db_error}")
        
        # Return response with both avatar_url and avatar fields
        # Both fields are required for frontend validation to pass
        current_avatar = updated_user.get("avatar") if updated_user else None
        response_data = {
            "avatar_url": avatar_url,  # Image URL (REQUIRED)
            "avatar": current_avatar if current_avatar else "",  # Initials (REQUIRED - defaults to empty string)
            "success": True,
            "filename": new_file_name,
            "message": "Avatar uploaded successfully"
        }
        logger.debug(f"Alternative avatar upload completed: avatar_url={avatar_url}, avatar={response_data['avatar']}")
        
        # Validate response data before sending
        if not isinstance(response_data, dict):
            logger.error(f"Response data is not a dict: {type(response_data)}")
            response_data = {"avatar_url": avatar_url, "avatar": "", "success": False, "message": "Internal error"}
        
        if "avatar_url" not in response_data:
            logger.error("avatar_url missing from response_data in alternative endpoint")
            response_data["avatar_url"] = avatar_url
            
        if "avatar" not in response_data:
            response_data["avatar"] = current_avatar if current_avatar else ""
            
        logger.debug(f"Final alternative response data: {response_data}")
        return JSONResponse(status_code=200, content=response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Alternative avatar upload error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload avatar: {str(e)}"
        )

@router.get("/health")
async def users_health():
    """Health check for users module"""
    return {"status": "healthy", "module": "users", "timestamp": datetime.now(timezone.utc).isoformat(), "avatar_endpoint": "POST /api/v1/users/avatar/"}

@router.get("/avatar-test")
async def test_avatar_route():
    """Test route to verify API routing for avatar endpoint"""
    return {
        "message": "Avatar API is working",
        "status": "ok",
        "post_endpoint": "POST /api/v1/users/avatar/ - Use this to upload",
        "get_endpoint": "GET /api/v1/users/avatar/{filename} - Use this to retrieve"
    }

@router.post("/avatar/")
async def upload_avatar_with_slash(
    file: UploadFile = File(...),
    request: Request = None,
    current_user: str = Depends(get_current_user_optional)
):
    """Upload user avatar - POST endpoint with trailing slash (same logic as without slash)"""
    print(f"[AVATAR_UPLOAD_SLASH] POST /avatar/ endpoint called!")
    print(f"[AVATAR_UPLOAD_SLASH] Request method: {request.method if request else 'No request'}")
    return await upload_avatar(file, request, current_user)



@router.options("/avatar")
@router.options("/avatar-upload")
async def avatar_options():
    """Handle CORS preflight for avatar endpoint"""
    from fastapi.responses import Response
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400"
        }
    )

@router.get("/avatar/{filename}")
async def get_avatar(filename: str, current_user: str = Depends(get_current_user_optional)):
    """Get user avatar - authenticated access only"""
    from fastapi.responses import FileResponse
    import os
    
    logger.info(f"[AVATAR] Avatar requested: {filename}")
    
# Security: Validate filename to prevent directory traversal
    if not filename:
        logger.warning(f"[AVATAR] Empty filename")
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    # Security: Check for directory traversal attempts (both Unix and Windows)
    dangerous_patterns = ['..', '\\', '/', '\x00']
    for pattern in dangerous_patterns:
        if pattern in filename:
            logger.warning(f"[AVATAR] Dangerous filename detected: {filename}")
            raise HTTPException(status_code=400, detail="Invalid filename")
    
    # Security: Ensure filename is alphanumeric with safe characters only
    import re
    # Allow UUID-style patterns with underscores, hyphens, and periods
    if not re.match(r'^[a-zA-Z0-9_.-]+\.([a-zA-Z0-9]+)$', filename):
        logger.warning(f"[AVATAR] Invalid filename format: {filename}")
        raise HTTPException(status_code=400, detail="Invalid filename format")
    
    file_path = settings.DATA_ROOT / "avatars" / filename
    logger.debug(f"[AVATAR] File path: {file_path}")
    
    if not file_path.exists():
        logger.warning(f"[AVATAR] File not found: {filename}")
        
        # Fallback: Try to find avatar by user ID from filename
        import re
        from pathlib import Path
        import glob
        # Extract user ID from patterns like "69564dea8eac4df1_xyz.png" or "69564dea8eac4df1.png"
        user_id_match = re.match(r'^([a-f0-9]+)', filename)
        if user_id_match:
            user_id = user_id_match.group(1)
            logger.info(f"[AVATAR] Searching for avatar by user_id: {user_id}")
            
            # Search for any avatar file for this user
            avatar_pattern = f"{user_id}_*.*"
            avatar_dir = settings.DATA_ROOT / "avatars"
            matching_files = list(glob.glob(str(avatar_dir / avatar_pattern)))
            
            if matching_files:
                # Return the most recent avatar file
                latest_file = max(matching_files, key=os.path.getctime)
                file_path = Path(latest_file)
                logger.info(f"[AVATAR] Found fallback avatar: {file_path.name}")
            else:
                logger.warning(f"[AVATAR] No avatar files found for user: {user_id}")
                raise HTTPException(status_code=404, detail="Avatar not found")
        else:
            raise HTTPException(status_code=404, detail="Avatar not found")
    
    # Check if it's actually a file
    if not file_path.is_file():
        logger.warning(f"[AVATAR] Path is not a file: {file_path}")
        raise HTTPException(status_code=404, detail="Avatar not found")
    
    # Determine media type based on file extension
    media_type = None
    filename_lower = filename.lower()
    if filename_lower.endswith(('.jpg', '.jpeg')):
        media_type = 'image/jpeg'
    elif filename_lower.endswith('.png'):
        media_type = 'image/png'
    elif filename_lower.endswith('.gif'):
        media_type = 'image/gif'
    elif filename_lower.endswith('.webp'):
        media_type = 'image/webp'
    else:
        logger.warning(f"[AVATAR] Unsupported file type: {filename}")
        raise HTTPException(status_code=400, detail="Unsupported file type")
    
    try:
        file_size = os.path.getsize(file_path)
        logger.info(f"[AVATAR] Serving avatar: {filename} ({file_size} bytes, {media_type})")
        return FileResponse(
            file_path, 
            media_type=media_type, 
            filename=filename,
            headers={"Cache-Control": "public, max-age=3600"}
        )
    except Exception as e:
        logger.error(f"[AVATAR] Error serving avatar {filename}: {e}")
        raise HTTPException(status_code=500, detail="Failed to serve avatar")


@router.post("/location/update")
async def update_location(
    lat: float,
    lng: float,
    current_user: str = Depends(get_current_user)
):
    """Update user's current location for 'People Nearby' feature.
    
    Args:
        lat: Latitude of current location
        lng: Longitude of current location
    
    Returns:
        Success message with updated location
    """
    try:
        # Validate coordinates
        if not (-90 <= lat <= 90) or not (-180 <= lng <= 180):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid coordinates. Latitude must be -90 to 90, Longitude must be -180 to 180"
            )
        
        # Update user location
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {
                    "$set": {
                        "location": {
                            "lat": lat,
                            "lng": lng,
                            "updated_at": datetime.now(timezone.utc)
                        },
                        "updated_at": datetime.now(timezone.utc)
                    }
                }
            ),
            timeout=5.0
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {
            "message": "Location updated successfully",
            "location": {"lat": lat, "lng": lng},
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except (ValueError, TypeError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid parameters: {str(e)}"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update location: {str(e)}"
        )


@router.post("/location/clear")
async def clear_location(current_user: str = Depends(get_current_user)):
    """Clear user's location data (opt-out of People Nearby feature)."""
    try:
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {
                    "$unset": {"location": ""},
                    "$set": {"updated_at": datetime.now(timezone.utc)}
                }
            ),
            timeout=5.0
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {"message": "Location cleared successfully"}
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear location: {str(e)}"
        )


# Contact Management Endpoints


        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        contact_ids = user.get("contacts", [])
        
        if not contact_ids:
            return {"contacts": [], "total": 0}
        
        # Paginate contacts
        paginated_ids = contact_ids[offset:offset + limit]
        
        # Fetch contact details
        contacts = []
        if paginated_ids:
            cursor = users_collection().find(
                {"_id": {"$in": paginated_ids}},
                {
                    "_id": 1,
                    "name": 1,
                    "email": 1,
                    "username": 1,
                    "phone": 1,
                    "avatar_url": 1,
                    "is_online": 1,
                    "last_seen": 1,
                    "status": 1,
                    "created_at": 1
                }
            )
            
            async def fetch_contacts():
                results = []
                async for contact in cursor:
                    results.append(UserSearchResponse(
                        id=contact.get("_id", ""),
                        name=contact.get("name", ""),
                        email=contact.get("email", ""),
                        username=contact.get("username"),
                        phone=contact.get("phone"),
                        avatar_url=contact.get("avatar_url"),
                        is_online=contact.get("is_online", False),
                        last_seen=contact.get("last_seen"),
                        status=contact.get("status"),
                        is_contact=True,
                        is_blocked=False
                    ))
                return results
            
            contacts = await asyncio.wait_for(fetch_contacts(), timeout=5.0)
        
        return {
            "contacts": contacts,
            "total": len(contact_ids),
            "offset": offset,
            "limit": limit
        }
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch contacts: {str(e)}"
        )



        
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Don't allow adding self as contact
        if request.user_id == current_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot add yourself as a contact"
            )
        
        # Check if already in contacts
        current_user_data = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not current_user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Current user not found"
            )
        
        contacts = current_user_data.get("contacts", [])
        
        # Check if already in contacts (support both old format and new format)
        if isinstance(contacts, list):
            if any(isinstance(c, dict) and c.get("user_id") == request.user_id for c in contacts) or (request.user_id in contacts):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User is already in your contacts"
                )
        
        # Add to contacts in new format: {user_id, display_name}
        contact_entry = {
            "user_id": request.user_id,
            "display_name": request.display_name or target_user.get("name", target_user.get("username", ""))
        }
        contacts.append(contact_entry)
        
        await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": {"contacts": contacts, "updated_at": datetime.now(timezone.utc)}}
            ),
            timeout=5.0
        )
        
        return {
            "message": "Contact added successfully",
            "contact_id": request.user_id,
            "contact_name": contact_entry["display_name"]
        }
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add contact: {str(e)}"
        )









        
        existing_contacts = set(current_user_data.get("contacts", []))
        blocked_users = set(current_user_data.get("blocked_users", []))
        
        # Build prioritized search query based on detected search type
        if search_type == "phone":
            search_query = {
                "$or": [
                    {"phone": {"$regex": re.escape(clean_phone), "$options": "i"}},  # Phone priority
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name fallback
                ],
                "_id": {"$ne": current_user}
            }
        elif search_type == "email":
            search_query = {
                "$or": [
                    {"email": {"$regex": sanitized_q, "$options": "i"}},  # Email priority
                    {"username": {"$regex": sanitized_q, "$options": "i"}},  # Username fallback
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name fallback
                ],
                "_id": {"$ne": current_user}
            }
        elif search_type == "username":
            search_query = {
                "$or": [
                    {"username": {"$regex": sanitized_q, "$options": "i"}},  # Username priority
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name fallback
                ],
                "_id": {"$ne": current_user}
            }
        else:
            # General name search
            search_query = {
                "$or": [
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name priority
                    {"username": {"$regex": sanitized_q, "$options": "i"}},  # Username fallback
                ],
                "_id": {"$ne": current_user}
            }
        
        # Add phone search as fallback for general searches if numeric
        if search_type == "general" and clean_phone and len(clean_phone) >= 3 and any(c.isdigit() for c in clean_phone):
            search_query["$or"].append({
                "phone": {"$regex": re.escape(clean_phone), "$options": "i"}
            })
        
        # Search users with limit
        cursor = users_collection().find(
            search_query,
            {
                "_id": 1,
                "name": 1,
                "email": 1,
                "username": 1,
                "phone": 1,
                "avatar_url": 1,
                "is_online": 1,
                "last_seen": 1,
                "status": 1
            }
        ).limit(limit)
        
        async def fetch_results():
            results = []
            async for user in cursor:
                user_id = user.get("_id")
                score = _calculate_search_score(user, q, clean_phone, search_type)
                
                result = UserSearchResponse(
                    id=user_id,
                    name=user.get("name", ""),
                    email=user.get("email", ""),
                    username=user.get("username"),
                    phone=user.get("phone"),
                    avatar_url=user.get("avatar_url"),
                    is_online=user.get("is_online", False),
                    last_seen=user.get("last_seen"),
                    status=user.get("status"),
                    is_contact=user_id in existing_contacts,
                    is_blocked=user_id in blocked_users
                )
                
                # Add relevance score for sorting
                results.append({
                    "id": result.id,
                    "name": result.name,
                    "email": result.email,
                    "username": result.username,
                    "phone": result.phone,
                    "avatar_url": result.avatar_url,
                    "is_online": result.is_online,
                    "last_seen": result.last_seen,
                    "status": result.status,
                    "is_contact": result.is_contact,
                    "is_blocked": result.is_blocked,
                    "relevance_score": score
                })
            
            # Sort by relevance score (highest first)
            results.sort(key=lambda x: x["relevance_score"], reverse=True)
            return results
        
        users = await asyncio.wait_for(fetch_results(), timeout=5.0)
        return {"users": users}
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Search operation timed out. Please try again."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Search failed. Please try again."
        )



