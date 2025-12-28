from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File, Request
from fastapi.responses import JSONResponse
from models import (
    UserResponse, UserInDB, PasswordChangeRequest, EmailChangeRequest, ProfileUpdate,
    ContactAddRequest, ContactDeleteRequest, ContactSyncRequest, UserSearchResponse
)
from db_proxy import users_collection, chats_collection, messages_collection, files_collection
from auth.utils import get_current_user, get_current_user_optional
import asyncio
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
from config import settings
from typing import Optional
import re
import logging
import json
import math

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
    contacts: bool = False
    phone: bool = False
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
            phone=user.get("phone"),
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
            contacts_count=len(user.get("contacts", [])),
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
        logger.info(f"  - email: {current_user_data.get('email')}")
        
        # Prepare the update data
        update_data = {}
        
        # Process the name
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
            logger.info(f"✓ Username validation passed: {username}")
            update_data["username"] = username
        
        # Process the bio and phone
        if profile_data.bio is not None:
            logger.info(f"✓ Bio set: {profile_data.bio[:50]}..." if len(profile_data.bio) > 50 else f"✓ Bio set: {profile_data.bio}")
            update_data["bio"] = profile_data.bio
        
        if profile_data.phone is not None:
            logger.info(f"✓ Phone set: {profile_data.phone}")
            update_data["phone"] = profile_data.phone
        
        # Process the avatar
        if profile_data.avatar_url is not None:
            logger.info(f"✓ Avatar URL set: {profile_data.avatar_url}")
            update_data["avatar_url"] = profile_data.avatar_url
        
        if profile_data.avatar is not None:
            logger.info(f"✓ Avatar initials set: {profile_data.avatar}")
            update_data["avatar"] = profile_data.avatar  # Store avatar initials in the avatar field
        
        # Process email (enforce uniqueness)
        if profile_data.email is not None and profile_data.email.strip():
            logger.info(f"Processing email update: {profile_data.email}")
            # Validate the email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, profile_data.email):
                logger.warning(f"Email validation failed: invalid format for {profile_data.email}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid email format. Use format: user@example.com"
                )
            
            # Normalize the email
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
            phone=updated_user.get("phone"),
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
            contacts_count=len(updated_user.get("contacts", [])),
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
    """Search users by name, email, username, or phone number with intelligent prioritization
    
    Args:
        q: Search query string
        search_type: Optional - 'phone', 'email', 'username', or None for auto-detection
        current_user: Current authenticated user ID
    """
    
    if len(q) < 2:
        return {"users": []}
    
    try:
        # Sanitize input for regex search to prevent injection
        sanitized_q = re.escape(q)
        # Extract only digits and plus for phone search - fix digits_only bug
        clean_phone = '+' + re.sub(r'[^\d]', '', q[1:]) if q.startswith('+') else re.sub(r'[^\d]', '', q)
        
        # Determine search type - use provided search_type or auto-detect
        if search_type and search_type in ["phone", "email", "username"]:
            actual_search_type = search_type
        else:
            actual_search_type = _determine_search_type(q, clean_phone)
        
        users = []
        
        # Build prioritized search query based on detected search type
        if actual_search_type == "phone":
            # Phone number search - highest priority for exact phone matches
            search_query = {
                "$or": [
                    {"phone": {"$regex": re.escape(clean_phone), "$options": "i"}},  # Exact phone match
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Fallback to name
                ],
                "_id": {"$ne": current_user}
            }
        elif actual_search_type == "email":
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
        
        # Add phone search as fallback for general searches if numeric
        if actual_search_type == "general" and clean_phone and len(clean_phone) >= 3 and any(c.isdigit() for c in clean_phone):
            search_query["$or"].append({
                "phone": {"$regex": re.escape(clean_phone), "$options": "i"}
            })
        
        cursor = users_collection().find(search_query).limit(20)
        
        # Fetch results with timeout and scoring
        async def fetch_results():
            results = []
            async for user in cursor:
                score = _calculate_search_score(user, q, clean_phone, actual_search_type)
                results.append({
                    "id": user.get("_id", ""),
                    "name": user.get("name", ""),
                    "email": user.get("email", ""),
                    "phone": user.get("phone", ""),
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


def _determine_search_type(query: str, clean_phone: str) -> str:
    """Determine the type of search based on query characteristics"""
    
    # Email detection
    if '@' in query and '.' in query.split('@')[-1]:
        return "email"
    
    # Phone detection - starts with + or contains mostly digits
    if query.startswith('+') or (len(clean_phone) >= 7 and clean_phone.isdigit()):
        return "phone"
    
    # Username detection - starts with @ or contains underscores/hyphens
    if query.startswith('@') or '_' in query or '-' in query:
        return "username"
    
    return "general"


def _calculate_search_score(user: dict, query: str, clean_phone: str, search_type: str) -> int:
    """Calculate relevance score for search results (higher = more relevant)"""
    try:
        score = 0
        
        query_lower = query.lower()
        name = str(user.get("name", "")).lower()
        email = str(user.get("email", "")).lower()
        username = str(user.get("username", "")).lower()
        phone = str(user.get("phone", "")).lower()
        
        # Exact matches get highest scores
        if search_type == "email" and email == query_lower:
            score += 100
        elif search_type == "phone" and clean_phone in re.sub(r'[^\d]', '', phone):
            score += 90
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
        
        # Phone partial matches
        if clean_phone and len(clean_phone) >= 3:
            # Normalize phone for comparison
            normalized_phone = '+' + re.sub(r'[^\d]', '', phone[1:]) if phone.startswith('+') else re.sub(r'[^\d]', '', phone)
            if clean_phone in normalized_phone:
                score += 15
        
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


@router.options("/avatar/")
@router.options("/avatar-upload/")
async def avatar_options():
    """Handle CORS preflight for avatar endpoint"""
    print(f"[AVATAR-OPTIONS] OPTIONS preflight received for /avatar/")
    return JSONResponse(status_code=200, content={"status": "ok", "methods": ["GET", "POST", "OPTIONS"]})

@router.post("/avatar-debug/")
async def upload_avatar_debug(
    file: UploadFile = File(...),
):
    """DEBUG endpoint - Avatar upload WITHOUT authentication requirement"""
    try:
        import shutil
        import os
        import uuid
        
        print(f"[AVATAR-DEBUG] ===== AVATAR UPLOAD POST (NO AUTH) STARTED =====")
        print(f"[AVATAR-DEBUG] File name: {file.filename}")
        print(f"[AVATAR-DEBUG] Content type: {file.content_type}")
        
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
        
        # Use filename as user_id for debug mode
        user_id = "debug_user"
        unique_id = str(uuid.uuid4())[:8]
        new_file_name = f"{user_id}_{unique_id}{file_ext}"
        new_file_path = avatar_dir / new_file_name
        
        # Save file
        with open(new_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Generate URL
        avatar_url = f"/api/v1/users/avatar/{new_file_name}"
        
        response_data = {
            "avatar_url": avatar_url,
            "success": True,
            "filename": new_file_name,
            "message": "Avatar uploaded successfully (debug mode)"
        }
        print(f"[AVATAR-DEBUG] Success: {response_data}")
        return JSONResponse(status_code=200, content=response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"[AVATAR-DEBUG] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload avatar: {str(e)}"
        )

@router.post("/avatar/")
async def upload_avatar(
    file: UploadFile = File(...),
    request: Request = None,
    current_user: str = Depends(get_current_user_optional)
):
    """Upload user avatar - POST endpoint (tries auth, falls back to guest)"""
    try:
        import shutil
        import os
        import uuid
        
        # If no user, use guest ID
        if not current_user:
            current_user = "guest_upload"
            print(f"[AVATAR-POST] ===== AVATAR UPLOAD POST (GUEST MODE) =====")
        else:
            print(f"[AVATAR-POST] ===== AVATAR UPLOAD POST STARTED =====")
        
        print(f"[AVATAR-POST] User ID: {current_user}")
        print(f"[AVATAR-POST] File name: {file.filename}")
        print(f"[AVATAR-POST] Content type: {file.content_type}")
        print(f"[AVATAR-POST] ===== END HEADERS =====")

        
        # Validate file type
        if not file.content_type or not file.content_type.startswith("image/"):
            _log("warning", f"Invalid avatar file type", {"user_id": current_user, "operation": "avatar_validation"})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an image"
            )
        
        # Create directory
        avatar_dir = settings.DATA_ROOT / "avatars"
        try:
            avatar_dir.mkdir(parents=True, exist_ok=True)
            print(f"[AVATAR] Avatar directory ensured at: {avatar_dir}")
            print(f"[AVATAR] Directory exists: {avatar_dir.exists()}")
        except Exception as dir_error:
            print(f"[AVATAR] Failed to create avatar directory: {dir_error}")
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
        
        unique_id = str(uuid.uuid4())[:8]
        new_file_name = f"{current_user}_{unique_id}{file_ext}"
        new_file_path = avatar_dir / new_file_name
        
        # Clean up old avatar files to prevent storage leaks
        try:
            # Find the current user's old avatar files
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
                        old_file_path.unlink()
                        _log("info", f"Cleaned up old avatar: {old_filename}")
        except Exception as cleanup_error:
            _log("warning", f"Failed to cleanup old avatar", {"user_id": current_user, "operation": "avatar_cleanup"})
            # Continue with upload even if cleanup fails
        
        # Save the new file with proper error handling
        try:
            with open(new_file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            print(f"[AVATAR] File saved successfully: {new_file_path}")
            print(f"[AVATAR] File exists after save: {new_file_path.exists()}")
            if new_file_path.exists():
                file_size = os.path.getsize(new_file_path)
                print(f"[AVATAR] File size: {file_size} bytes")
        except Exception as save_error:
            _log("error", f"Failed to save avatar file: {save_error}", {"user_id": current_user, "operation": "avatar_save"})
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save file"
            )
        
        # Generate URL
        avatar_url = f"/api/v1/users/avatar/{new_file_name}"
        
        # Update the user in the database with timeout
        try:
            result = await asyncio.wait_for(
                users_collection().update_one(
                    {"_id": current_user},
                    {"$set": {"avatar_url": avatar_url, "updated_at": datetime.now(timezone.utc)}}
                ),
                timeout=5.0
            )
            
            # Check for actual failure versus idempotent update
            user_exists = await asyncio.wait_for(
                users_collection().find_one({"_id": current_user}),
                timeout=5.0
            )
            if not user_exists:
                raise Exception("User not found")
                
            _log("info", f"Avatar updated successfully", {"user_id": current_user, "operation": "avatar_update"})
        except asyncio.TimeoutError:
            # Clean up the uploaded file if the database update times out
            if new_file_path.exists():
                new_file_path.unlink()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database operation timed out"
            )
        except Exception as db_error:
            # Clean up the uploaded file if the database update fails
            if new_file_path.exists():
                new_file_path.unlink()
            _log("error", f"Failed to update database: {db_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update avatar in database"
            )
        
        # Return successful response with avatar_url
        response_data = {
            "avatar_url": avatar_url,
            "success": True,
            "filename": new_file_name,
            "message": "Avatar uploaded successfully",
            "status": "upload_complete"
        }
        print(f"[AVATAR-POST] ===== SUCCESS RESPONSE =====")
        print(f"[AVATAR-POST] Response data: {response_data}")
        print(f"[AVATAR-POST] ===== END RESPONSE =====")
        return JSONResponse(status_code=200, content=response_data)
        
    except HTTPException as http_exc:
        print(f"[AVATAR-POST] HTTPException: status={http_exc.status_code}, detail={http_exc.detail}")
        raise
    except Exception as e:
        print(f"[AVATAR-POST] ===== UNEXPECTED ERROR =====")
        print(f"[AVATAR-POST] Error type: {type(e).__name__}")
        print(f"[AVATAR-POST] Error message: {str(e)}")
        print(f"[AVATAR-POST] ===== END ERROR =====")
        _log("error", f"Unexpected avatar upload error: {str(e)}", {"user_id": current_user, "operation": "avatar_upload"})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload avatar: {str(e)}"
        )


@router.post("/avatar-upload/")
async def upload_avatar_alt(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    """Alternative avatar upload endpoint - same as /avatar/ but with different name"""
    try:
        print(f"[AVATAR-UPLOAD-ALT] Alternative upload endpoint called")
        print(f"[AVATAR-UPLOAD-ALT] User: {current_user}, File: {file.filename}")
        
        import shutil
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
        
        # Save file
        with open(new_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Generate URL
        avatar_url = f"/api/v1/users/avatar/{new_file_name}"
        
        # Update database
        await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": {"avatar_url": avatar_url, "updated_at": datetime.now(timezone.utc)}}
            ),
            timeout=5.0
        )
        
        response_data = {
            "avatar_url": avatar_url,
            "success": True,
            "filename": new_file_name,
            "message": "Avatar uploaded successfully"
        }
        print(f"[AVATAR-UPLOAD-ALT] Success: {response_data}")
        return JSONResponse(status_code=200, content=response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"[AVATAR-UPLOAD-ALT] Error: {str(e)}")
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

@router.get("/avatar/")
async def list_avatars():
    """Handle GET requests to avatar endpoint without filename - Returns usage documentation"""
    print(f"[AVATAR-GET] WARNING: GET /users/avatar/ endpoint called")
    print(f"[AVATAR-GET] This usually means:")
    print(f"[AVATAR-GET]   1. Frontend made GET request instead of POST")
    print(f"[AVATAR-GET]   2. POST request failed and browser fell back to GET")
    print(f"[AVATAR-GET]   3. OPTIONS preflight failed")
    return {
        "error": "Use POST /api/v1/users/avatar/ to upload avatar",
        "message": "Avatar upload endpoint",
        "usage": {
            "upload": "POST /api/v1/users/avatar/ with file data",
            "retrieve": "GET /api/v1/users/avatar/{filename}"
        }
    }

@router.get("/avatar/{filename}")
async def get_avatar(filename: str, current_user: str = Depends(get_current_user)):
    """Get user avatar - authenticated access only"""
    from fastapi.responses import FileResponse
    import os
    
    logger.info(f"[AVATAR] Avatar requested: {filename}")
    
    # Validate filename to prevent directory traversal
    if not filename or '..' in filename or '/' in filename:
        logger.warning(f"[AVATAR] Invalid filename: {filename}")
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    file_path = settings.DATA_ROOT / "avatars" / filename
    logger.debug(f"[AVATAR] File path: {file_path}")
    
    if not file_path.exists():
        logger.warning(f"[AVATAR] File not found: {filename}")
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

@router.get("/contacts/list")
async def get_contacts_list(
    current_user: str = Depends(get_current_user),
    limit: int = 100,
    offset: int = 0
):
    """Get current user's contacts list with details"""
    try:
        # Get current user to fetch contacts
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
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


@router.post("/contacts/add")
async def add_contact(
    request: ContactAddRequest,
    current_user: str = Depends(get_current_user)
):
    """Add a user to contacts"""
    try:
        # Validate target user exists
        target_user = await asyncio.wait_for(
            users_collection().find_one({"_id": request.user_id}),
            timeout=5.0
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


@router.delete("/contacts/{contact_id}")
async def delete_contact(
    contact_id: str,
    current_user: str = Depends(get_current_user)
):
    """Remove a user from contacts"""
    try:
        # Get current user
        current_user_data = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        if not current_user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        contacts = current_user_data.get("contacts", [])
        
        # Check if contact exists (handle both string and dict formats)
        contact_found = False
        if isinstance(contacts, list):
            for i, contact in enumerate(contacts):
                if isinstance(contact, dict) and contact.get("user_id") == contact_id:
                    contacts.pop(i)
                    contact_found = True
                    break
                elif contact == contact_id:
                    contacts.pop(i)
                    contact_found = True
                    break
        
        if not contact_found:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contact not found in your contacts list"
            )
        await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {"$set": {"contacts": contacts, "updated_at": datetime.now(timezone.utc)}}
            ),
            timeout=5.0
        )
        
        return {"message": "Contact removed successfully"}
        
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
            detail=f"Failed to remove contact: {str(e)}"
        )


@router.post("/contacts/sync")
async def sync_contacts(
    request: ContactSyncRequest,
    current_user: str = Depends(get_current_user)
):
    """Sync phone contacts with app users"""
    try:
        # Extract phone numbers from request
        phone_numbers = []
        for contact in request.contacts:
            phone = contact.get("phone", "").strip()
            if phone:
                # Normalize phone number (remove spaces, dashes, parentheses, keep +)
                if phone.startswith('+'):
                    clean_phone = '+' + re.sub(r'[^\d]', '', phone[1:])
                else:
                    clean_phone = re.sub(r'[^\d]', '', phone)
                if clean_phone:
                    phone_numbers.append(clean_phone)
        
        if not phone_numbers:
            return {"matched_contacts": []}
        
        # Find users with matching phone numbers
        matched_users = await asyncio.wait_for(
            users_collection().find(
                {"phone": {"$in": phone_numbers}},
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
            ).to_list(None),
            timeout=5.0
        )
        
        # Get current user's contacts to mark which users are already contacts
        current_user_data = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}, {"contacts": 1}),
            timeout=5.0
        )
        
        existing_contacts = set(current_user_data.get("contacts", []))
        
        # Format response
        matched_contacts = []
        for user in matched_users:
            user_id = user.get("_id")
            contact_info = {
                "id": user_id,
                "name": user.get("name", ""),
                "username": user.get("username"),
                "phone": user.get("phone"),
                "avatar_url": user.get("avatar_url"),
                "is_online": user.get("is_online", False),
                "last_seen": user.get("last_seen"),
                "status": user.get("status"),
                "is_already_contact": user_id in existing_contacts
            }
            
            # Find the matching contact from request to include the contact's name
            for contact in request.contacts:
                contact_phone_raw = contact.get("phone", "").strip()
                if contact_phone_raw:
                    # Normalize contact phone number
                    if contact_phone_raw.startswith('+'):
                        contact_phone = '+' + re.sub(r'[^\d]', '', contact_phone_raw[1:])
                    else:
                        contact_phone = re.sub(r'[^\d]', '', contact_phone_raw)
                    
                    # Normalize user phone number
                    user_phone = user.get("phone", "")
                    if user_phone:
                        if user_phone.startswith('+'):
                            clean_user_phone = '+' + re.sub(r'[^\d]', '', user_phone[1:])
                        else:
                            clean_user_phone = re.sub(r'[^\d]', '', user_phone)
                        
                        if contact_phone == clean_user_phone:
                            contact_info["contact_name"] = contact.get("name", "")
                            break
            
            matched_contacts.append(contact_info)
        
        return {
            "matched_contacts": matched_contacts,
            "total_matched": len(matched_contacts)
        }
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out. Please try again."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync contacts: {str(e)}"
        )


@router.get("/contacts/search")
async def search_contacts(
    q: str,
    current_user: str = Depends(get_current_user),
    limit: int = 20
):
    """Search users for adding to contacts with intelligent prioritization and enhanced info"""
    try:
        if len(q) < 2:
            return {"users": []}
        
        # Sanitize input for regex search
        sanitized_q = re.escape(q)
        # Extract only digits and plus for phone search - fix digits_only bug
        clean_phone = '+' + re.sub(r'[^\d]', '', q[1:]) if q.startswith('+') else re.sub(r'[^\d]', '', q)
        
        # Determine search type for better prioritization
        search_type = _determine_search_type(q, clean_phone)
        
        # Get current user's existing contacts and blocked users
        current_user_data = await asyncio.wait_for(
            users_collection().find_one(
                {"_id": current_user}, 
                {"contacts": 1, "blocked_users": 1}
            ),
            timeout=5.0
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


@router.post("/contacts/block/{user_id}")
async def block_user(
    user_id: str,
    current_user: str = Depends(get_current_user)
):
    """Block a user"""
    try:
        # Validate user exists
        target_user = await asyncio.wait_for(
            users_collection().find_one({"_id": user_id}),
            timeout=5.0
        )
        
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Don't allow blocking self
        if user_id == current_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot block yourself"
            )
        
        # Add to blocked users and remove from contacts if present
        await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {
                    "$addToSet": {"blocked_users": user_id},
                    "$pull": {"contacts": user_id},
                    "$set": {"updated_at": datetime.now(timezone.utc)}
                }
            ),
            timeout=5.0
        )
        
        return {"message": "User blocked successfully"}
        
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
            detail=f"Failed to block user: {str(e)}"
        )


@router.delete("/contacts/block/{user_id}")
async def unblock_user(
    user_id: str,
    current_user: str = Depends(get_current_user)
):
    """Unblock a user"""
    try:
        # Remove from blocked users
        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {
                    "$pull": {"blocked_users": user_id},
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
        
        return {"message": "User unblocked successfully"}
        
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
            detail=f"Failed to unblock user: {str(e)}"
        )
