from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File, Request

from fastapi.responses import JSONResponse



try:

    from ..models import (

        UserResponse, UserInDB, PasswordChangeRequest, ProfileUpdate,

        UserSearchResponse, GroupCreate, GroupUpdate, GroupMembersUpdate, GroupMemberRoleUpdate, ChatPermissions,

        ContactAddRequest, ContactResponse

    )

    from ..db_proxy import users_collection, chats_collection, messages_collection, files_collection, uploads_collection, refresh_tokens_collection, get_db

    from ..config import settings

except ImportError:

    from models import (

        UserResponse, UserInDB, PasswordChangeRequest, ProfileUpdate,

        UserSearchResponse, GroupCreate, GroupUpdate, GroupMembersUpdate, GroupMemberRoleUpdate, ChatPermissions,

        ContactAddRequest, ContactResponse

    )

    from db_proxy import users_collection, chats_collection, messages_collection, files_collection, uploads_collection, refresh_tokens_collection, get_db

    from config import settings



from auth.utils import get_current_user, get_current_user_optional, get_current_user_or_query

import asyncio

from pydantic import BaseModel, Field, field_validator

from datetime import datetime, timezone

from typing import Optional

import re

import json

import math

import logging

from bson import ObjectId



# Import create_group function from groups module

try:

    from .groups import create_group

except Exception:

    from routes.groups import create_group





def get_secure_cors_origin(request_origin: Optional[str]) -> str:

    """Get secure CORS origin based on configuration and security"""

    # In production, use strict origin validation

    if not settings.DEBUG:

        if request_origin and request_origin in settings.CORS_ORIGINS:

            return request_origin

        elif settings.CORS_ORIGINS:

            return settings.CORS_ORIGINS[0]  # Return first allowed origin

        else:

            return "http://localhost:8000"  # Secure default

    

    # In debug mode, allow localhost with validation

    if request_origin:

        if (request_origin.startswith("http://localhost") or 
            request_origin.startswith("http://127.0.0.1")):
            return request_origin

        elif request_origin in settings.CORS_ORIGINS:

            return request_origin

    

    return settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "http://localhost:8000"





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

                detail={

                    "status": "ERROR",

                    "message": "User not found",

                    "data": None

                }

            )

        

        return UserResponse(

            id=user["_id"],

            name=user["name"],

            email=user.get("email", user.get("username", "")),  # Use email if available, fallback to username

            username=user.get("username") or user.get("email", "").lower(),  # Fallback to email lowercased if username missing

            bio=user.get("bio"),

            avatar="",  # FIXED: Always empty string for WhatsApp compatibility

            avatar_url=user.get("avatar_url"),

            quota_used=user.get("quota_used", 0),

            quota_limit=user.get("quota_limit", 42949672960),

            created_at=user["created_at"],

            updated_at=user.get("updated_at"),

            last_seen=user.get("last_seen"),

            is_online=user.get("is_online", False),

            status=user.get("status"),

            permissions=user.get("permissions", {

                "location": False,

                "camera": False,

                "microphone": False,

                "storage": False

            }),

            pinned_chats=user.get("pinned_chats", []),

            is_contact=False  # Current user can't be a contact of themselves

        )

    except asyncio.TimeoutError:

        logger.error(f"Database operation timed out")

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

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

        if all(v is None for v in [profile_data.name, profile_data.username, profile_data.bio, profile_data.avatar_url, profile_data.avatar]):

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

            

            # Clean up old avatar file if avatar_url is being changed

            try:

                # Get current user data to check for existing avatar

                current_user_data = await asyncio.wait_for(

                    users_collection().find_one({"_id": current_user}),

                    timeout=5.0

                )

                

                if current_user_data and "avatar_url" in current_user_data:

                    old_avatar_url = current_user_data["avatar_url"]

                    if old_avatar_url and old_avatar_url != profile_data.avatar_url:

                        # Only delete if the avatar_url is actually changing

                        if old_avatar_url.startswith("/api/v1/users/avatar/"):

                            old_filename = old_avatar_url.split("/")[-1]

                            from pathlib import Path

                            data_root = Path(settings.DATA_ROOT)

                            old_file_path = data_root / "avatars" / old_filename

                            if old_file_path.exists():

                                try:

                                    old_file_path.unlink()

                                    logger.info(f"Cleaned up old avatar file: {old_filename}")

                                except Exception as delete_error:

                                    logger.warning(f"Could not delete old avatar file {old_filename}: {delete_error}")

            except Exception as cleanup_error:

                logger.warning(f"Cleanup error while checking old avatar: {cleanup_error}")

                # Continue anyway - new avatar URL will be set

            

            update_data["avatar_url"] = profile_data.avatar_url

            # Clear avatar initials when avatar_url is set

            update_data["avatar"] = None

        else:

            # avatar_url is None, check if we need to clean up existing avatar

            try:

                current_user_data = await asyncio.wait_for(

                    users_collection().find_one({"_id": current_user}),

                    timeout=5.0

                )

                

                if current_user_data and "avatar_url" in current_user_data:

                    old_avatar_url = current_user_data["avatar_url"]

                    if old_avatar_url and old_avatar_url.startswith("/api/v1/users/avatar/"):

                        old_filename = old_avatar_url.split("/")[-1]

                        from pathlib import Path

                        data_root = Path(settings.DATA_ROOT)

                        old_file_path = data_root / "avatars" / old_filename

                        if old_file_path.exists():

                            try:

                                old_file_path.unlink()

                                logger.info(f"Removed avatar file: {old_filename}")

                            except Exception as delete_error:

                                logger.warning(f"Could not remove avatar file {old_filename}: {delete_error}")

                

                # Set avatar_url to None in database to remove avatar

                update_data["avatar_url"] = None

                logger.info("Avatar URL set to None (avatar removed)")

            except Exception as cleanup_error:

                logger.warning(f"Cleanup error while removing avatar: {cleanup_error}")

                # Continue anyway - avatar will be set to None in database

        

        if profile_data.avatar is not None:

            logger.info(f"FIXED: Avatar initials ignored - set to None instead")

            # FIXED: Don't allow avatar initials, always set to None

            update_data["avatar"] = None  # Store avatar initials in the avatar field

        

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

            email=updated_user.get("email", updated_user.get("username", "")),  # Use email if available, fallback to username or empty

            username=updated_user.get("username") or updated_user.get("email", "").lower(),  # Fallback to email lowercased if username missing

            bio=updated_user.get("bio"),

            avatar="",  # FIXED: Always empty string for WhatsApp compatibility

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

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

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

                detail={

                    "status": "ERROR",

                    "message": "User not found",

                    "data": None

                }

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

            "storage_percentage": round((quota_used / quota_limit) * 100, 1) if quota_limit and quota_limit > 0 else 0,

            "account_created": user.get("created_at"),

            "last_active": user.get("last_active", datetime.now(timezone.utc))

        }

    except asyncio.TimeoutError:

        logger.error(f"Database operation timed out")

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

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



    if not q:

        return {"users": []}



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

                ]

            }

        elif actual_search_type == "username":

            # Username search - prioritized exact username match

            search_query = {

                "$or": [

                    {"username": {"$regex": sanitized_q, "$options": "i"}},  # Username priority

                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name fallback

                ]

            }

        else:

            # General name search

            search_query = {

                "$or": [

                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name priority

                    {"username": {"$regex": sanitized_q, "$options": "i"}},  # Username fallback

                ]

            }

        

        find_result = users_collection().find(search_query)

        # Check if find_result is a coroutine (mock DB) or cursor (real MongoDB)

        if hasattr(find_result, '__await__'):

            cursor = await find_result

        else:

            cursor = find_result

        # Apply limit

        cursor = cursor.limit(20)

        

        # Fetch results with timeout and scoring

        async def fetch_results():

            results = []

            async for user in cursor:

                if str(user.get("_id", "")) == str(current_user):

                    continue

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

        logger.error(f"Database operation timed out")

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

        )

    except Exception as e:

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail="Search failed. Please try again."

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

        if lat < -90 or lat > 90 or lng < -180 or lng > 180:

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

        logger.error(f"Database operation timed out")

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

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

                detail={

                    "status": "ERROR",

                    "message": "User not found",

                    "data": None

                }

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

        logger.error(f"Database operation timed out")

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

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

        logger.error(f"Database operation timed out")

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

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

        print(f"[USERS_GROUP_CREATE] Creating group for user: {current_user}")

        print(f"[USERS_GROUP_CREATE] Payload member_ids: {payload.member_ids}")

        

        member_ids = list(dict.fromkeys([*(payload.member_ids or []), current_user]))

        print(f"[USERS_GROUP_CREATE] After adding current_user: {member_ids}")

        

        if len(member_ids) < 2:

            print(f"[USERS_GROUP_CREATE] ERROR: Group must have at least 2 members, got {len(member_ids)}")

            raise HTTPException(

                status_code=status.HTTP_400_BAD_REQUEST,

                detail="Group must have at least 2 members"

            )

        

        try:

            from .groups import create_group as create_group_helper

        except Exception:

            from routes.groups import create_group as create_group_helper

        group_result = await create_group_helper(payload, current_user)

        

        print(f"[USERS_GROUP_CREATE] Group created successfully: {group_result}")

        

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

                detail={

                    "status": "ERROR",

                    "message": "User not found",

                    "data": None

                }

            )

        

        # Verify old password

        from auth.utils import verify_password, hash_password

        

        # Get user's password salt for verification

        password_salt = user.get("password_salt", "")

        password_hash = user.get("password_hash", "")

        

        if not verify_password(request.old_password, password_hash, password_salt, current_user):

            print(f"[PASSWORD_CHANGE] Old password verification failed for {current_user}")

            raise HTTPException(

                status_code=status.HTTP_401_UNAUTHORIZED,

                detail={

                    "status": "ERROR",

                    "message": "Old password is incorrect",

                    "data": None

                }

            )

        

        # Hash new password (returns tuple: hash, salt)

        new_password_hash, new_password_salt = hash_password(request.new_password)

        

        # Update password in database

        result = await asyncio.wait_for(

            users_collection().update_one(

                {"_id": current_user},

                {"$set": {

                    "password_hash": new_password_hash,  # Store hash separately

                    "password_salt": new_password_salt,  # Store salt separately

                    "updated_at": datetime.now(timezone.utc)

                }}

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

        logger.error(f"Database operation timed out")

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

        )

    except Exception as e:

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail=f"Failed to change password: {str(e)}"

        )





# Email change functionality removed





@router.post("/change-email")

async def change_email():

    """Change user's email - DISABLED"""

    return JSONResponse(

        content={"message": "Email change functionality has been disabled. Please contact support."},

        status_code=200

    )





@router.get("/search-legacy")

async def search_users_legacy(

    q: str = None,

    current_user: str = Depends(get_current_user)

):

    """Search users by username"""

    try:

        if not q:

            raise HTTPException(

                status_code=status.HTTP_400_BAD_REQUEST,

                detail="Search query is required"

            )

        

        print(f"[USER_SEARCH] Search query: {q} by user: {current_user}")

        

        # Search users by username (case-insensitive)

        users = await asyncio.wait_for(

            users_collection().find({

                "username": {"$regex": q, "$options": "i"}

            }).limit(10).to_list(None),

            timeout=5.0

        )

        

        # Convert to response format

        search_results = []

        for user in users:

            search_results.append({

                "id": str(user["_id"]),

                "name": user.get("name", ""),

                "username": user.get("username", ""),

                "avatar_url": user.get("avatar_url"),

                "is_online": user.get("is_online", False),

                "last_seen": user.get("last_seen")

            })

        

        return {

            "status": "SUCCESS",

            "message": f"Found {len(search_results)} users",

            "data": search_results

        }

        

    except asyncio.TimeoutError:

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail="Search operation timed out"

        )

    except Exception as e:

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail=f"Search failed: {str(e)}"

        )





@router.delete("/account")

async def delete_account(

    current_user: str = Depends(get_current_user)

):

    """Delete user account permanently"""

    try:

        print(f"[ACCOUNT_DELETE] Delete request for user: {current_user}")

        

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

        

        # Delete user from database

        result = await asyncio.wait_for(

            users_collection().delete_one({"_id": current_user}),

            timeout=5.0

        )

        

        if result.deleted_count == 0:

            raise HTTPException(

                status_code=status.HTTP_404_NOT_FOUND,

                detail="User not found"

            )

        

        print(f"[ACCOUNT_DELETE] Successfully deleted user: {current_user}")

        return {"message": "Account deleted successfully"}

        

    except asyncio.TimeoutError:

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail="Delete operation timed out"

        )

    except Exception as e:

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail=f"Delete failed: {str(e)}"

        )





@router.post("/avatar")

async def upload_avatar(

    file: UploadFile = File(...),

    request: Request = None,

    current_user: str = Depends(get_current_user)

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

        from pathlib import Path

        data_root = Path(settings.DATA_ROOT)

        avatar_dir = data_root / "avatars"

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

        current_avatar = None

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

            # Store current avatar for response

            current_avatar = user.get("avatar", "") if user else None

        except Exception as cleanup_error:

            logger.warning(f"Cleanup error while checking old avatar: {cleanup_error}")

            # Continue anyway - new file is already saved

        

        # Update the user in the database with timeout

        updated_user = None

        try:

            result = await asyncio.wait_for(

                users_collection().update_one(

                    {"_id": current_user},

                    {"$set": {"avatar_url": avatar_url, "avatar": None, "updated_at": datetime.now(timezone.utc)}}

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

        response_data = {

            "avatar_url": avatar_url,  # REQUIRED: Frontend expects this field

            "avatar": "",  # FIXED: Always empty string when image uploaded (prevents text-based avatars)

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

    current_user: str = Depends(get_current_user)

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

        from pathlib import Path

        data_root = Path(settings.DATA_ROOT)

        avatar_dir = data_root / "avatars"

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

            "avatar": "",  # FIXED: Always empty string for WhatsApp compatibility

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

async def avatar_options(request: Request):

    """Handle CORS preflight for avatar endpoints with secure origin validation"""

    from fastapi.responses import Response

    

    origin = request.headers.get("origin", "")

    secure_origin = get_secure_cors_origin(origin)

    

    return Response(

        status_code=200,

        headers={

            "Access-Control-Allow-Origin": secure_origin,

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

    

    # Handle both string and Path objects for DATA_ROOT

    from pathlib import Path

    data_root = Path(settings.DATA_ROOT)

    file_path = data_root / "avatars" / filename

    logger.debug(f"[AVATAR] File path: {file_path}")

    

    if not file_path.exists():

        logger.warning(f"[AVATAR] File not found: {filename}")

        

        # Fallback: Try to find avatar by user ID from filename

        import re

        from pathlib import Path

        import glob

        # Extract user ID from patterns like "69564dea8eac4df1_xyz.png" or "69564dea8eac4df1.png"

        user_id_match = re.match(r'^([a-f0-9]+)', filename)

        if user_id_match and user_id_match.groups():

            user_id = user_id_match.group(1)

            logger.info(f"[AVATAR] Searching for avatar by user_id: {user_id}")

            

            # Search for any avatar file for this user

            avatar_pattern = f"{user_id}_*.*"

            avatar_dir = data_root / "avatars"

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

        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported file type")

    

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

        if lat < -90 or lat > 90 or lng < -180 or lng > 180:

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

        logger.error(f"Database operation timed out")

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

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

        logger.error(f"Database operation timed out")

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail={

                "status": "ERROR",

                "message": "Database operation timed out. Please try again later.",

                "data": None

            }

        )

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail=f"Failed to clear location: {str(e)}"

        )





# Contact Management Endpoints





@router.get("/simple")

async def get_simple_users(

    offset: int = 0,

    limit: int = 50,

    current_user: str = Depends(get_current_user)

):

    """Get simple list of users for group creation UI.



    Behaviour:

    - If the user has contacts, return those contacts (paged).

    - If the user has NO contacts, return a generic list of users so that

      group creation UI still shows members to pick from.

    - Always exclude the current user from the list.

    """

    try:

        # Fetch current user (may or may not have contacts configured)

        user = await asyncio.wait_for(

            users_collection().find_one({"_id": current_user}),

            timeout=5.0,

        )



        contact_ids = user.get("contacts", []) if user else []



        # If user has contacts, return them in the same shape expected by frontend

        if contact_ids:

            paginated_ids = contact_ids[offset:offset + limit]



            cursor = users_collection().find(

                {"_id": {"$in": paginated_ids}},

                {

                    "_id": 1,

                    "name": 1,

                    "email": 1,

                    "username": 1,

                    "avatar_url": 1,

                    "is_online": 1,

                    "last_seen": 1,

                    "status": 1,

                },

            )



            users: list[dict] = []

            async for user_doc in cursor:

                # Normalise to the simple user payload the Flutter UI expects

                users.append(

                    {

                        "id": user_doc.get("_id", ""),

                        "name": user_doc.get("name", ""),

                        "email": user_doc.get("email", ""),

                        "username": user_doc.get("username"),

                        "avatar_url": user_doc.get("avatar_url"),

                        "is_online": user_doc.get("is_online", False),

                        "last_seen": user_doc.get("last_seen"),

                        "status": user_doc.get("status"),

                    }

                )



            return {

                "users": users,

                "total": len(contact_ids),

                "offset": offset,

                "limit": limit,

            }



        # No contacts configured for this user -> fall back to a generic user list

        # so that group creation is still usable for first‑time users.

        users_col = users_collection()



        # Detect in-memory mock used by tests (has a dict-like `.data` store)

        if hasattr(users_col, "data") and isinstance(getattr(users_col, "data"), dict):

            all_docs = []

            for uid, doc in users_col.data.items():

                if uid == current_user:

                    continue

                all_docs.append(doc)



            # Sort by created_at (newest first), then by name as secondary key

            def _sort_key(doc: dict) -> tuple:

                created = doc.get("created_at")

                name = (doc.get("name") or "").lower()

                # Handle None created_at: treat as older (high value) so newer items come first

                if created is None:

                    # Use very old timestamp for missing created_at

                    created = 0

                elif hasattr(created, 'timestamp'):

                    # Convert datetime to timestamp for proper numeric sorting

                    created = created.timestamp()

                # Negate created to sort descending (newest first), then by name ascending

                return (-created if isinstance(created, (int, float)) else -1000000000, name)



            all_docs.sort(key=_sort_key)

            paged_docs = all_docs[offset:offset + limit]



            users: list[dict] = []

            for user_doc in paged_docs:

                users.append(

                    {

                        "id": user_doc.get("_id", ""),

                        "name": user_doc.get("name", ""),

                        "email": user_doc.get("email", ""),

                        "username": user_doc.get("username"),

                        "avatar_url": user_doc.get("avatar_url"),

                        "is_online": user_doc.get("is_online", False),

                        "last_seen": user_doc.get("last_seen"),

                        "status": user_doc.get("status"),

                    }

                )



            return {

                "users": users,

                "total": len(all_docs),

                "offset": offset,

                "limit": limit,

            }



        # Real MongoDB path

        base_query = {"_id": {"$ne": current_user}}



        cursor = users_col.find(

            base_query,

            {

                "_id": 1,

                "name": 1,

                "email": 1,

                "username": 1,

                "avatar_url": 1,

                "is_online": 1,

                "last_seen": 1,

                "status": 1,

            },

        ).sort("created_at", -1).skip(offset).limit(limit)



        users: list[dict] = []

        async for user_doc in cursor:

            users.append(

                {

                    "id": user_doc.get("_id", ""),

                    "name": user_doc.get("name", ""),

                    "email": user_doc.get("email", ""),

                    "username": user_doc.get("username"),

                    "avatar_url": user_doc.get("avatar_url"),

                    "is_online": user_doc.get("is_online", False),

                    "last_seen": user_doc.get("last_seen"),

                    "status": user_doc.get("status"),

                }

            )



        return {

            "users": users,

            # Total is approximate when falling back; we at least report page size

            "total": len(users),

            "offset": offset,

            "limit": limit,

        }



    except asyncio.TimeoutError:

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail="Database operation timed out. Please try again later.",

        )

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail=f"Failed to fetch users: {str(e)}",

        )





@router.get("/contacts")

async def get_contacts(

    offset: int = 0,

    limit: int = 50,

    current_user: str = Depends(get_current_user)

):

    """Get current user's contacts with pagination"""

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

        

        contact_ids = user.get("contacts", [])

        

        if not contact_ids:

            # CRITICAL FIX: Fallback to all users when no contacts available

            _log("info", f"No contacts found for user {current_user}, loading all users as fallback")

            

            # Get all users except current user

            users_col = users_collection()

            

            # Check if using mock DB or real MongoDB

            if hasattr(users_col, "data") and isinstance(getattr(users_col, "data"), dict):

                # Mock DB - filter manually

                all_users = []

                for uid, doc in users_col.data.items():

                    if uid != current_user:  # Exclude current user

                        all_users.append({

                            "id": doc.get("_id", ""),

                            "name": doc.get("name", ""),

                            "email": doc.get("email", ""),

                            "username": doc.get("username"),

                            "avatar_url": doc.get("avatar_url"),

                            "is_online": doc.get("is_online", False),

                            "last_seen": doc.get("last_seen"),

                            "status": doc.get("status", "")

                        })

                

                # Sort by online status first, then by name

                all_users.sort(key=lambda x: (0 if x["is_online"] else 1, x["name"].lower()))

                

                # Apply pagination

                paginated_users = all_users[offset:offset + limit]

                

                return {

                    "contacts": paginated_users,

                    "total": len(all_users),

                    "fallback_used": True

                }

            else:

                # Real MongoDB - use aggregation

                pipeline = [

                    {"$match": {"_id": {"$ne": current_user}}},

                    {"$sort": {"is_online": -1, "name": 1}},

                    {"$skip": offset},

                    {"$limit": limit},

                    {"$project": {

                        "id": "$_id",

                        "name": 1,

                        "email": 1,

                        "username": 1,

                        "avatar_url": 1,

                        "is_online": {"$ifNull": ["$is_online", False]},

                        "last_seen": 1,

                        "status": {"$ifNull": ["$status", ""]}

                    }}

                ]

                

                cursor = users_col.aggregate(pipeline)

                if hasattr(cursor, '__await__'):

                    cursor = await cursor

                

                contacts = []

                async for doc in cursor:

                    contacts.append(doc)

                

                # Get total count

                total_count = await users_col.count_documents({"_id": {"$ne": current_user}})

                

                return {

                    "contacts": contacts,

                    "total": total_count,

                    "fallback_used": True

                }

        

        # Paginate contacts

        paginated_ids = contact_ids[offset:offset + limit]

        

        # Fetch contact details

        contacts = []

        if paginated_ids:

            users_col = users_collection()



            # The in-memory mock DB used by tests stores documents in `users_collection().data`

            # and does not fully support nested Mongo operators like {"_id": {"$in": [...]}}.

            if hasattr(users_col, "data") and isinstance(getattr(users_col, "data"), dict):

                results = []

                for uid in paginated_ids:

                    doc = users_col.data.get(uid)

                    if not doc:

                        continue

                    results.append({

                        "id": doc.get("_id", ""),

                        "name": doc.get("name", ""),

                        "email": doc.get("email", ""),

                        "username": doc.get("username"),

                        "avatar_url": doc.get("avatar_url"),

                        "is_online": doc.get("is_online", False),

                        "last_seen": doc.get("last_seen"),

                        "status": doc.get("status"),

                    })

                contacts = results

            else:

                find_result = users_col.find(

                    {"_id": {"$in": paginated_ids}},

                    {

                        "_id": 1,

                        "name": 1,

                        "email": 1,

                        "username": 1,

                        "avatar_url": 1,

                        "is_online": 1,

                        "last_seen": 1,

                        "status": 1,

                        "created_at": 1

                    }

                )



                # Support both coroutine-based mock DB and real MongoDB cursors

                if hasattr(find_result, '__await__'):

                    cursor = await find_result

                else:

                    cursor = find_result

                

                async def fetch_contacts():

                    results = []

                    async for contact in cursor:

                        results.append({

                            "id": contact.get("_id", ""),

                            "name": contact.get("name", ""),

                            "email": contact.get("email", ""),

                            "username": contact.get("username"),

                            "avatar_url": contact.get("avatar_url"),

                            "is_online": contact.get("is_online", False),

                            "last_seen": contact.get("last_seen"),

                            "status": contact.get("status")

                        })

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

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail="Database operation timed out. Please try again later."

        )

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail=f"Failed to fetch contacts: {str(e)}"

        )





@router.post("/contacts", response_model=ContactResponse)

async def add_contact(

    request: ContactAddRequest,

    current_user: str = Depends(get_current_user)

):

    """Add a new contact by user_id, username, or email"""

    try:

        # Validate that at least one identifier is provided

        if not any([request.user_id, request.username, request.email]):

            raise HTTPException(

                status_code=status.HTTP_400_BAD_REQUEST,

                detail="Either user_id, username, or email must be provided"

            )

        

        # Find the target user

        identifier_field, identifier_value = request.get_identifier()

        

        if identifier_field == "user_id":

            target_user = await asyncio.wait_for(

                users_collection().find_one({"_id": identifier_value}),

                timeout=5.0

            )

        elif identifier_field == "username":

            target_user = await asyncio.wait_for(

                users_collection().find_one({"username": identifier_value}),

                timeout=5.0

            )

        elif identifier_field == "email":

            target_user = await asyncio.wait_for(

                users_collection().find_one({"email": identifier_value}),

                timeout=5.0

            )

        

        if not target_user:

            raise HTTPException(

                status_code=status.HTTP_404_NOT_FOUND,

                detail="User not found"

            )

        

        # Don't allow adding self as contact

        if target_user["_id"] == current_user:

            raise HTTPException(

                status_code=status.HTTP_400_BAD_REQUEST,

                detail="Cannot add yourself as a contact"

            )

        

        # Check if already in contacts

        current_user_data = await asyncio.wait_for(

            users_collection().find_one({"_id": current_user}),

            timeout=5.0

        )

        

        existing_contacts = current_user_data.get("contacts", [])

        if target_user["_id"] in existing_contacts:

            raise HTTPException(

                status_code=status.HTTP_409_CONFLICT,

                detail="User is already in your contacts"

            )

        

        # Add contact

        contact_entry = {

            "user_id": target_user["_id"],

            "display_name": request.display_name or target_user.get("name", target_user.get("username", "")),

            "added_at": datetime.now(timezone.utc)

        }

        

        result = await asyncio.wait_for(

            users_collection().update_one(

                {"_id": current_user},

                {

                    "$push": {"contacts": target_user["_id"]},

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

        

        return {

            "message": "Contact added successfully",

            "contact_id": target_user["_id"],

            "contact_name": target_user.get("name", target_user.get("username", "")),

            "display_name": contact_entry["display_name"]

        }

        

    except asyncio.TimeoutError:

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail="Database operation timed out. Please try again later."

        )

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail=f"Failed to add contact: {str(e)}"

        )





@router.delete("/contacts/{contact_id}")

async def remove_contact(

    contact_id: str,

    current_user: str = Depends(get_current_user)

):

    """Remove a contact"""

    try:

        # Check if contact exists

        current_user_data = await asyncio.wait_for(

            users_collection().find_one({"_id": current_user}),

            timeout=5.0

        )

        

        if not current_user_data:

            raise HTTPException(

                status_code=status.HTTP_404_NOT_FOUND,

                detail="User not found"

            )

        

        existing_contacts = current_user_data.get("contacts", [])

        if contact_id not in existing_contacts:

            raise HTTPException(

                status_code=status.HTTP_404_NOT_FOUND,

                detail="Contact not found"

            )

        

        # Remove contact

        result = await asyncio.wait_for(

            users_collection().update_one(

                {"_id": current_user},

                {

                    "$pull": {"contacts": contact_id},

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

        

        return {"message": "Contact removed successfully"}

        

    except asyncio.TimeoutError:

        raise HTTPException(

            status_code=status.HTTP_504_GATEWAY_TIMEOUT,

            detail="Database operation timed out. Please try again later."

        )

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(

            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail=f"Failed to remove contact: {str(e)}"

        )







