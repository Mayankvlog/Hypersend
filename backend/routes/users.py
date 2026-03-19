from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    Request,
    UploadFile,
    File,
)
from fastapi.responses import JSONResponse, FileResponse
from typing import List, Optional
import logging
import asyncio
import sys

sys.modules.setdefault("routes.users", sys.modules[__name__])
sys.modules.setdefault("backend.routes.users", sys.modules[__name__])


try:
    from ..models import (
        UserResponse,
        UserInDB,
        PasswordChangeRequest,
        ProfileUpdate,
        UserSearchResponse,
        GroupCreate,
        GroupUpdate,
        GroupMembersUpdate,
        GroupMemberRoleUpdate,
        ChatPermissions,
        ContactAddRequest,
        ContactResponse,
    )

    from ..db_proxy import (
        users_collection,
        chats_collection,
        messages_collection,
        files_collection,
        uploads_collection,
        refresh_tokens_collection,
        get_database,
    )

    from ..config import settings

except ImportError:
    from models import (
        UserResponse,
        UserInDB,
        PasswordChangeRequest,
        ProfileUpdate,
        UserSearchResponse,
        GroupCreate,
        GroupUpdate,
        GroupMembersUpdate,
        GroupMemberRoleUpdate,
        ChatPermissions,
        ContactAddRequest,
        ContactResponse,
    )

    from db_proxy import (
        users_collection,
        chats_collection,
        messages_collection,
        files_collection,
        uploads_collection,
        refresh_tokens_collection,
        get_database,
    )

    from config import settings


# Auth utilities with fallback for different import paths
try:
    from backend.auth.utils import (
        get_current_user,
        get_current_user_optional,
        get_current_user_or_query,
    )
except ImportError:
    from auth.utils import (
        get_current_user,
        get_current_user_optional,
        get_current_user_or_query,
    )

import asyncio

from pydantic import BaseModel, Field, field_validator

from datetime import datetime, timezone, timedelta

from typing import Optional

import re

import json

import math

import logging

from bson import ObjectId

import asyncio
import aiofiles
import logging
import os
from pathlib import Path


# Helper function to check if URL is an avatar URL
def _is_avatar_url(url: str) -> bool:
    """Check if URL is an avatar URL (both old relative and new absolute formats)"""
    if not isinstance(url, str) or not url:
        return False
    return "/api/v1/users/avatar/" in url or "/users/avatar/" in url


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
            return "https://zaply.in.net/"  # Secure default

    # Only allow zaply.in.net in production

    if request_origin:
        if request_origin.startswith("https://zaply.in.net"):
            return request_origin

        elif request_origin in settings.CORS_ORIGINS:
            return request_origin

    return (
        settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "https://zaply.in.net/"
    )


def _maybe_object_id(value: str):
    if not value:
        return value

    try:
        if isinstance(value, ObjectId):
            return value

        if isinstance(value, str) and ObjectId.is_valid(value):
            return ObjectId(value)

    except Exception:
        return value

    return value


async def _log_group_activity(
    group_id: str, actor_id: str, event: str, meta: Optional[dict] = None
):
    """Log group activity for auditing"""

    try:
        db = get_database()

        col = db.group_activity

        doc = {
            "_id": str(ObjectId()),
            "group_id": group_id,
            "actor_id": actor_id,
            "event": event,
            "meta": meta or {},
            "created_at": datetime.now(timezone.utc),
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
        "[%(asctime)s] [PROFILE] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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

    camera: bool = False

    microphone: bool = False

    storage: bool = False


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: str = Depends(get_current_user)):
    """Get current user profile"""

    try:
        from bson import ObjectId

        # Add a 5-second timeout to prevent hanging
        user = None
        if ObjectId.is_valid(current_user):
            object_id = ObjectId(current_user)
            user = await asyncio.wait_for(
                users_collection().find_one({"_id": object_id}),
                timeout=5.0,
            )
        else:
            user = await asyncio.wait_for(
                users_collection().find_one({"_id": current_user}),
                timeout=5.0,
            )

        if not user:
            # CRITICAL FIX: User not found after successful authentication
            # This may indicate a race condition (user created but not inserted yet)
            # or a database synchronization issue. Log and retry once.
            logger.warning(
                f"Authenticated user {current_user} not found on first attempt"
            )

            # Brief retry to handle eventual consistency
            await asyncio.sleep(0.5)  # Wait 500ms for database synchronization
            if ObjectId.is_valid(current_user):
                object_id = ObjectId(current_user)
                user = await asyncio.wait_for(
                    users_collection().find_one({"_id": object_id}),
                    timeout=5.0,
                )
            else:
                user = await asyncio.wait_for(
                    users_collection().find_one({"_id": current_user}),
                    timeout=5.0,
                )

            if not user:
                logger.error(
                    f"User {current_user} not found in database after retry - returning 401"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "status": "ERROR",
                        "message": "User session invalid",
                        "data": None,
                    },
                )

        return UserResponse(
            id=str(user["_id"]),
            name=user["name"],
            email=user.get(
                "email", user.get("username", "")
            ),  # Use email if available, fallback to username
            username=user.get("username")
            or user.get(
                "email", ""
            ).lower(),  # Fallback to email lowercased if username missing
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
            permissions=user.get(
                "permissions", {"camera": False, "microphone": False, "storage": False}
            ),
            pinned_chats=user.get("pinned_chats", []),
            is_contact=False,  # Current user can't be a contact of themselves
        )

    except asyncio.TimeoutError:
        logger.error(f"Database operation timed out")

        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "status": "ERROR",
                "message": "Database operation timed out. Please try again later.",
                "data": None,
            },
        )

    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch user: {str(e)}",
        )

    except Exception as e:
        if "timeout" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail={
                    "status": "ERROR",
                    "message": "Database operation timed out. Please try again later.",
                    "data": None,
                },
            )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user",
        )


# ProfileUpdate model is imported from models


@router.put("/profile", response_model=UserResponse)
async def update_profile(
    profile_data: ProfileUpdate, current_user: str = Depends(get_current_user)
):
    """Update current user's profile with detailed logging"""

    try:
        logger.info(f"{'='*80}")

        logger.info(f"PROFILE UPDATE REQUEST STARTED")

        logger.info(f"{'='*80}")

        logger.info(f"User ID: {current_user}")

        # Log the received data

        logger.info(f"Received ProfileUpdate model:")

        logger.info(
            f"  - name: {profile_data.name} (type: {type(profile_data.name).__name__})"
        )

        logger.info(
            f"  - username: {profile_data.username} (type: {type(profile_data.username).__name__})"
        )

        logger.info(
            f"  - avatar: {profile_data.avatar} (type: {type(profile_data.avatar).__name__})"
        )

        logger.info(
            f"  - bio: [REDACTED_FOR_PRIVACY] (type: {type(profile_data.bio).__name__})"
        )

        logger.info(
            f"  - avatar_url: {profile_data.avatar_url} (type: {type(profile_data.avatar_url).__name__})"
        )

        logger.debug(f"[EMAIL_PII] Email fields present but not logged for privacy")

        # Check if at least one field is being updated

        if all(
            v is None
            for v in [
                profile_data.name,
                profile_data.username,
                profile_data.bio,
                profile_data.avatar_url,
                profile_data.avatar,
            ]
        ):
            logger.warning(f"No fields provided for update - all are None")

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one field must be provided to update",
            )

        # Get current user data from the database

        logger.info(f"Fetching current user data from database...")

        current_user_oid = _maybe_object_id(current_user)
        current_user_data = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user_oid}),
            timeout=5.0,
        )

        if not current_user_data:
            logger.error(f"Current user not found in database: {current_user}")

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Current user not found"
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
                    detail="Name cannot be empty",
                )

            if len(name) < 2:
                logger.warning(f"Name validation failed: length {len(name)} < 2")

                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Name must be at least 2 characters",
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
                    detail="Username cannot be empty",
                )

            # Check if username is already taken (excluding current user)
            if username != "":
                current_user_id = (
                    current_user_data.get("_id")
                    if current_user_data
                    else current_user_oid
                )

                existing_username = await asyncio.wait_for(
                    users_collection().find_one(
                        {"username": username, "_id": {"$ne": current_user_id}}
                    ),
                    timeout=5.0,
                )

                if existing_username:
                    logger.warning(
                        f"Username already taken: {username} by {existing_username.get('_id')}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Username already taken",
                    )

                logger.info(f"SUCCESS: Username validation passed: {username}")
                update_data["username"] = username

        # Process the bio and phone

        if profile_data.bio is not None:
            # Validate bio length and content

            if len(profile_data.bio) > 500:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Bio/Status is too long. Maximum 500 characters allowed.",
                )

            # Basic content sanitization

            import re

            sanitized_bio = re.sub(r'[<>"\']', "", profile_data.bio.strip())

            if sanitized_bio != profile_data.bio.strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Bio/Status contains invalid characters. Please use plain text only.",
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
                    users_collection().find_one({"_id": current_user_oid}),
                    timeout=5.0,
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

                                    logger.info(
                                        f"Cleaned up old avatar file: {old_filename}"
                                    )

                                except Exception as delete_error:
                                    logger.warning(
                                        f"Could not delete old avatar file {old_filename}: {delete_error}"
                                    )
            except Exception as cleanup_error:
                logger.warning(
                    f"Cleanup error while checking old avatar: {cleanup_error}"
                )

            update_data["avatar_url"] = profile_data.avatar_url

            # Clear avatar initials when avatar_url is set
            update_data["avatar"] = None

        else:
            # avatar_url is None, check if we need to clean up existing avatar

            try:
                current_user_id = (
                    current_user_data.get("_id")
                    if current_user_data
                    else current_user_oid
                )

                # Use the already-available current_user_data instead of redundant DB lookup
                user_doc = current_user_data

                if user_doc and "avatar_url" in user_doc:
                    if _is_avatar_url(user_doc["avatar_url"]):
                        # Extract filename from both relative and absolute URLs
                        old_filename = user_doc["avatar_url"].split("/")[-1]
                        # Get avatar_dir the same way upload_avatar does
                        data_root = Path(settings.DATA_ROOT)
                        avatar_dir = data_root / "avatars"
                        old_file_path = avatar_dir / old_filename
                        if old_file_path.exists():
                            try:
                                old_file_path.unlink()
                                logger.debug("Cleaned up old avatar file")
                            except Exception as delete_error:
                                logger.warning(
                                    f"Could not delete old avatar: {delete_error}"
                                )

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

        logger.info(
            f"Update data values: {json.dumps({k: str(v)[:100] if isinstance(v, str) else str(v) for k, v in update_data.items()}, default=str)}"
        )

        # Update user profile in database

        logger.info(f"Executing database update...")

        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user_oid}, {"$set": update_data}
            ),
            timeout=5.0,
        )

        logger.info(f"Database update result:")

        logger.info(f"  - Matched documents: {result.matched_count}")

        logger.info(f"  - Modified documents: {result.modified_count}")

        if result.matched_count == 0:
            logger.error(f"User not found during update: {current_user}")

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        if result.modified_count == 0:
            logger.warning(f"No documents were modified (may be identical data)")

        # Fetch and return updated user profile

        logger.info(f"Fetching updated user profile...")

        updated_user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user_oid}), timeout=5.0
        )

        if not updated_user:
            logger.error(f"User not found after update: {current_user}")

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found after update",
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
            id=str(updated_user["_id"]),
            name=updated_user["name"],
            email=updated_user.get(
                "email", updated_user.get("username", "")
            ),  # Use email if available, fallback to username or empty
            username=updated_user.get("username")
            or updated_user.get(
                "email", ""
            ).lower(),  # Fallback to email lowercased if username missing
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
            is_contact=False,  # Current user can't be a contact of themselves
        )

    except asyncio.TimeoutError:
        logger.error(f"Database operation timed out")

        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "status": "ERROR",
                "message": "Database operation timed out. Please try again later.",
                "data": None,
            },
        )

    except HTTPException:
        raise  # Re-raise HTTP exceptions

    except (ValueError, TypeError, KeyError, OSError) as e:
        logger.error(f"Error during profile update: {type(e).__name__}: {str(e)}")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update profile: {str(e)}",
        )

    except Exception as e:
        logger.error(
            f"Unexpected error during profile update: {type(e).__name__}: {str(e)}"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}",
        )


@router.get("/stats")
async def get_user_stats(current_user: str = Depends(get_current_user)):
    """Get current user's statistics"""

    try:
        # Get user data

        user_id = _maybe_object_id(current_user)

        user = await asyncio.wait_for(
            users_collection().find_one({"_id": user_id}), timeout=5.0
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"status": "ERROR", "message": "User not found", "data": None},
            )

        # Count total messages sent by user

        message_count = await asyncio.wait_for(
            messages_collection().count_documents({"sender_id": current_user}),
            timeout=5.0,
        )

        # Count files shared by user

        file_count = await asyncio.wait_for(
            files_collection().count_documents({"uploaded_by": current_user}),
            timeout=5.0,
        )

        # Calculate storage usage

        quota_used = user.get("quota_used", 0)

        quota_limit = user.get("quota_limit", 1024 * 1024 * 1024)  # 1GB default

        return {
            "messages_sent": message_count,
            "files_shared": file_count,
            "storage_used_mb": round(quota_used / (1024 * 1024), 2),
            "storage_limit_mb": round(quota_limit / (1024 * 1024), 2),
            "storage_percentage": round((quota_used / quota_limit) * 100, 1)
            if quota_limit and quota_limit > 0
            else 0,
            "account_created": user.get("created_at"),
            "last_active": user.get("last_active", datetime.now(timezone.utc)),
        }

    except asyncio.TimeoutError:
        logger.error(f"Database operation timed out")

        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "status": "ERROR",
                "message": "Database operation timed out. Please try again later.",
                "data": None,
            },
        )

    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch stats: {str(e)}",
        )


@router.get("/search")
async def search_users(
    q: str, search_type: str = None, current_user: str = Depends(get_current_user)
):
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
                    {
                        "email": {"$regex": sanitized_q, "$options": "i"}
                    },  # Email exact match
                    {
                        "username": {"$regex": sanitized_q, "$options": "i"}
                    },  # Username fallback
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name fallback
                ]
            }

        elif actual_search_type == "username":
            # Username search - prioritized exact username match

            search_query = {
                "$or": [
                    {
                        "username": {"$regex": sanitized_q, "$options": "i"}
                    },  # Username priority
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name fallback
                ]
            }

        else:
            # General name search

            search_query = {
                "$or": [
                    {"name": {"$regex": sanitized_q, "$options": "i"}},  # Name priority
                    {
                        "username": {"$regex": sanitized_q, "$options": "i"}
                    },  # Username fallback
                ]
            }

        find_result = users_collection().find(search_query)

        # Check if find_result is a coroutine (mock DB) or cursor (real MongoDB)

        if hasattr(find_result, "__await__"):
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

                results.append(
                    {
                        "id": user.get("_id", ""),
                        "name": user.get("name", ""),
                        "email": user.get("email", ""),
                        "username": user.get("username", ""),
                        "relevance_score": score,
                    }
                )

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
                "data": None,
            },
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Search failed. Please try again.",
        )


def _determine_search_type(query: str) -> str:
    """Determine the type of search based on query characteristics"""

    # Email detection

    if "@" in query and "." in query.split("@")[-1]:
        return "email"

    # Username detection - starts with @ or contains underscores/hyphens

    if query.startswith("@") or "_" in query or "-" in query:
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

        elif search_type == "username" and username == query_lower.lstrip("@"):
            score += 85

        # Prefix matches

        if name.startswith(query_lower):
            score += 50

        elif username.startswith(query_lower.lstrip("@")):
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
            detail=f"Search failed: {str(e)}",
        )


@router.get("/permissions")
async def get_permissions(current_user: str = Depends(get_current_user)):
    """Get current user's app permissions"""

    try:
        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}), timeout=5.0
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"status": "ERROR", "message": "User not found", "data": None},
            )

        # Get permissions or return default (all denied)

        permissions = user.get(
            "permissions", {"camera": False, "microphone": False, "storage": False}
        )

        return permissions

    except asyncio.TimeoutError:
        logger.error(f"Database operation timed out")

        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "status": "ERROR",
                "message": "Database operation timed out. Please try again later.",
                "data": None,
            },
        )

    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch permissions: {str(e)}",
        )


@router.put("/permissions")
async def update_permissions(
    permissions_data: PermissionsUpdate, current_user: str = Depends(get_current_user)
):
    """Update current user's app permissions"""

    try:
        # Prepare permissions dictionary

        permissions = {
            "camera": permissions_data.camera,
            "microphone": permissions_data.microphone,
            "storage": permissions_data.storage,
        }

        # Update user's permissions in database

        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user}, {"$set": {"permissions": permissions}}
            ),
            timeout=5.0,
        )

        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        return {
            "message": "Permissions updated successfully",
            "permissions": permissions,
        }

    except asyncio.TimeoutError:
        logger.error(f"Database operation timed out")

        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "status": "ERROR",
                "message": "Database operation timed out. Please try again later.",
                "data": None,
            },
        )

    except (ValueError, TypeError, KeyError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update permissions: {str(e)}",
        )


# Group Chat Creation Endpoint


@router.post("/create-group")
async def create_group_endpoint(
    payload: GroupCreate, current_user: str = Depends(get_current_user)
):
    try:
        print(f"[USERS_GROUP_CREATE] Creating group for user: {current_user}")

        print(f"[USERS_GROUP_CREATE] Payload member_ids: {payload.member_ids}")

        member_ids = list(dict.fromkeys([*(payload.member_ids or []), current_user]))

        print(f"[USERS_GROUP_CREATE] After adding current_user: {member_ids}")

        if len(member_ids) < 2:
            print(
                f"[USERS_GROUP_CREATE] ERROR: Group must have at least 2 members, got {len(member_ids)}"
            )

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Group must have at least 2 members",
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
            "group": group_result["group"],
        }

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create group: {str(e)}",
        )


@router.post("/change-password")
async def change_password(
    request: PasswordChangeRequest, current_user: str = Depends(get_current_user)
):
    """Change user's password"""

    try:
        print(f"[PASSWORD_CHANGE] Request for user: {current_user}")

        if not request.old_password or not request.new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Old password and new password are required",
            )

        if request.new_password.strip() == "":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password cannot be empty",
            )

        if len(request.new_password) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be at least 6 characters",
            )

        # Get user from database

        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}), timeout=5.0
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"status": "ERROR", "message": "User not found", "data": None},
            )

        # Verify old password

        from auth.utils import verify_password, hash_password

        # Get user's password salt for verification

        password_salt = user.get("password_salt", "")

        password_hash = user.get("password_hash", "")

        if not verify_password(
            request.old_password, password_hash, password_salt, current_user
        ):
            print(
                f"[PASSWORD_CHANGE] Old password verification failed for {current_user}"
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "status": "ERROR",
                    "message": "Old password is incorrect",
                    "data": None,
                },
            )

        # Hash new password (returns tuple: hash, salt)

        new_password_hash, new_password_salt = hash_password(request.new_password)

        # Update password in database

        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {
                    "$set": {
                        "password_hash": new_password_hash,  # Store hash separately
                        "password_salt": new_password_salt,  # Store salt separately
                        "updated_at": datetime.now(timezone.utc),
                    }
                },
            ),
            timeout=5.0,
        )

        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
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
                "data": None,
            },
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to change password: {str(e)}",
        )


# Email change functionality removed


@router.post("/change-email")
async def change_email():
    """Change user's email - DISABLED"""

    return JSONResponse(
        content={
            "message": "Email change functionality has been disabled. Please contact support."
        },
        status_code=200,
    )


@router.get("/search-legacy")
async def search_users_legacy(
    q: str = None, current_user: str = Depends(get_current_user)
):
    """Search users by username"""

    try:
        if not q:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Search query is required",
            )

        print(f"[USER_SEARCH] Search query: {q} by user: {current_user}")

        # Search users by username (case-insensitive)

        users = await asyncio.wait_for(
            users_collection()
            .find({"username": {"$regex": q, "$options": "i"}})
            .limit(10)
            .to_list(None),
            timeout=5.0,
        )

        # Convert to response format

        search_results = []

        for user in users:
            search_results.append(
                {
                    "id": str(user["_id"]),
                    "name": user.get("name", ""),
                    "username": user.get("username", ""),
                    "avatar_url": user.get("avatar_url"),
                    "is_online": user.get("is_online", False),
                    "last_seen": user.get("last_seen"),
                }
            )

        return {
            "status": "SUCCESS",
            "message": f"Found {len(search_results)} users",
            "data": search_results,
        }

    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Search operation timed out",
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}",
        )


@router.delete("/account")
async def delete_account(current_user: str = Depends(get_current_user)):
    """Delete user account permanently"""

    try:
        print(f"[ACCOUNT_DELETE] Delete request for user: {current_user}")

        # Get user to verify they exist

        user = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}), timeout=5.0
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        # Delete user from database

        result = await asyncio.wait_for(
            users_collection().delete_one({"_id": current_user}), timeout=5.0
        )

        if result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        print(f"[ACCOUNT_DELETE] Successfully deleted user: {current_user}")

        return {"message": "Account deleted successfully"}

    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Delete operation timed out",
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Delete failed: {str(e)}",
        )


@router.post("/avatar")
@router.post("/avatar/")
async def upload_avatar(
    file: UploadFile = File(...),
    request: Request = None,
    current_user: str = Depends(get_current_user),
):
    """Upload user avatar - POST endpoint (requires authentication, returns avatar_url)"""
    import aiofiles
    import os
    import uuid
    import traceback

    logger.info(f"[AVATAR_UPLOAD] === POST /avatar endpoint started ===")
    logger.info(f"[AVATAR_UPLOAD] User ID: {current_user}")

    try:
        logger.info(f"[AVATAR_UPLOAD] File object received: {file}")
        logger.info(f"[AVATAR_UPLOAD] File filename: {file.filename}")
        logger.info(f"[AVATAR_UPLOAD] File content_type: {file.content_type}")
        logger.info(f"[AVATAR_UPLOAD] File size (header): {file.size}")

        # User must be authenticated
        if not current_user:
            logger.warning("[AVATAR_UPLOAD] No authenticated user")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required for avatar upload",
            )

        logger.info(f"[AVATAR_UPLOAD] User authenticated: {current_user}")

        # Validate file object is not None
        if file is None:
            logger.error("[AVATAR_UPLOAD] File is None!")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file provided in request",
            )

        # Validate file type
        if not file.content_type or not file.content_type.startswith("image/"):
            logger.warning(f"[AVATAR_UPLOAD] Invalid content type: {file.content_type}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an image (image/jpeg, image/png, image/gif, or image/webp)",
            )

        logger.info(f"[AVATAR_UPLOAD] Content type validated: {file.content_type}")

        # CRITICAL: Validate file size BEFORE saving (5MB limit for avatars)
        MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB
        file_size = getattr(file, "size", None)

        # If file.size is None, try to read content length from headers
        if file_size is None:
            try:
                # Read file content to determine size
                await file.seek(0)
                content = await file.read()
                file_size = len(content)
                logger.info(
                    f"[AVATAR_UPLOAD] File size from content read: {file_size} bytes"
                )
                # Reset file pointer for later use
                await file.seek(0)
            except Exception as read_error:
                logger.error(
                    f"[AVATAR_UPLOAD] Failed to read file content: {read_error}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to read file content",
                )

        if file_size and file_size > MAX_AVATAR_SIZE:
            size_mb = file_size / (1024 * 1024)
            logger.warning(
                f"[AVATAR_UPLOAD] File too large: {size_mb:.2f}MB (max: 5MB)"
            )
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Image file too large: {size_mb:.2f}MB. Maximum size is 5MB. Please compress or scale down the image.",
            )

        logger.info(f"[AVATAR_UPLOAD] File size validated: {file_size} bytes")

        # Create directory
        from pathlib import Path

        data_root = Path(settings.DATA_ROOT)
        avatar_dir = data_root / "avatars"

        logger.info(f"[AVATAR_UPLOAD] Storage path: {avatar_dir}")

        try:
            avatar_dir.mkdir(parents=True, exist_ok=True)
            logger.info(
                f"[AVATAR_UPLOAD] Avatar directory ready: {avatar_dir.exists()}"
            )
        except Exception as dir_error:
            logger.error(
                f"[AVATAR_UPLOAD] Failed to create avatar directory: {dir_error}"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create avatar storage directory",
            )

        # Generate unique filename
        file_ext = (
            os.path.splitext(file.filename)[1].lower() if file.filename else ".jpg"
        )
        logger.info(f"[AVATAR_UPLOAD] File extension: {file_ext}")

        if file_ext not in [".jpg", ".jpeg", ".png", ".gif", ".webp"]:
            logger.warning(f"[AVATAR_UPLOAD] Unsupported extension: {file_ext}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported image format. Use: jpg, jpeg, png, gif, or webp",
            )

        # Security: Generate secure filename
        unique_id = str(uuid.uuid4())
        safe_user_id = "".join(c for c in current_user if c.isalnum())[:16]
        if not safe_user_id:
            safe_user_id = "user"

        new_file_name = f"{safe_user_id}_{unique_id}{file_ext}"
        logger.info(f"[AVATAR_UPLOAD] Generated filename: {new_file_name}")

        # Validate filename
        import re

        if not re.match(r"^[a-zA-Z0-9_.-]+\.[a-zA-Z0-9]+$", new_file_name):
            logger.error(f"[AVATAR_UPLOAD] Invalid filename generated: {new_file_name}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Filename generation failed",
            )

        new_file_path = avatar_dir / new_file_name
        logger.info(f"[AVATAR_UPLOAD] Full file path: {new_file_path}")

        # Save the file
        try:
            # Reset file position to start
            await file.seek(0)

            # Read content first to ensure we have data
            content = await file.read()
            content_length = len(content)
            logger.info(
                f"[AVATAR_UPLOAD] Read {content_length} bytes from uploaded file"
            )

            if content_length == 0:
                logger.error("[AVATAR_UPLOAD] Uploaded file is empty!")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Uploaded file is empty",
                )

            # Write to disk
            async with aiofiles.open(new_file_path, "wb") as buffer:
                await buffer.write(content)

            logger.info(f"[AVATAR_UPLOAD] File written to disk")

            # Verify file was created
            if new_file_path.exists():
                actual_size = new_file_path.stat().st_size
                logger.info(
                    f"[AVATAR_UPLOAD] File verified: exists={new_file_path.exists()}, size={actual_size} bytes"
                )
            else:
                logger.error("[AVATAR_UPLOAD] File was NOT created on disk!")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to save file - file not created",
                )

        except HTTPException:
            raise
        except Exception as save_error:
            logger.error(f"[AVATAR_UPLOAD] Failed to save avatar file: {save_error}")
            logger.error(f"[AVATAR_UPLOAD] File path: {new_file_path}")
            logger.error(f"[AVATAR_UPLOAD] Directory exists: {avatar_dir.exists()}")
            logger.error(
                f"[AVATAR_UPLOAD] Directory writable: {os.access(str(avatar_dir), os.W_OK)}"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to save file: {str(save_error)}",
            )

        # Generate absolute URL
        from backend.config import settings

        # FIXED: Use correct API_BASE_URL pattern for avatar URLs
        # Avatar endpoint is at /api/v1/users/avatar/{filename}
        avatar_url = f"{settings.API_BASE_URL}/users/avatar/{new_file_name}"
        logger.info(f"[AVATAR_UPLOAD] Generated avatar URL: {avatar_url}")

        # Update database
        try:
            user_id = _maybe_object_id(current_user)

            logger.info(
                f"[AVATAR_UPLOAD] Updating user {user_id} with avatar_url: {avatar_url}"
            )

            result = await asyncio.wait_for(
                users_collection().update_one(
                    {"_id": user_id},
                    {
                        "$set": {
                            "avatar_url": avatar_url,
                            "avatar": None,
                            "updated_at": datetime.now(timezone.utc),
                        }
                    },
                ),
                timeout=5.0,
            )

            logger.info(
                f"[AVATAR_UPLOAD] Database update result: matched={result.matched_count}, modified={result.modified_count}"
            )

        except asyncio.TimeoutError:
            logger.warning(
                "[AVATAR_UPLOAD] Database update timed out - file still saved"
            )
        except Exception as db_error:
            logger.warning(
                f"[AVATAR_UPLOAD] Database update failed: {db_error} - file still saved"
            )

        # Prepare response
        response_data = {
            "avatar_url": avatar_url,
            "avatar": "",
            "success": True,
            "message": "Avatar uploaded successfully",
            "filename": new_file_name,
        }

        logger.info(f"[AVATAR_UPLOAD] === SUCCESS === Returning: {response_data}")

        return JSONResponse(status_code=200, content=response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[AVATAR_UPLOAD] Unexpected error: {type(e).__name__}: {str(e)}")
        logger.error(f"[AVATAR_UPLOAD] Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload avatar: {str(e)}",
        )

        logger.debug(f"Using authenticated mode for user: {current_user}")

        logger.debug(f"File content-type: {file.content_type}")

        # Validate file type

        if not file.content_type or not file.content_type.startswith("image/"):
            logger.warning("Invalid content type for avatar upload")

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="File must be an image"
            )

        # CRITICAL: Validate file size BEFORE saving (5MB limit for avatars)
        # This prevents large uploads from consuming disk space and bandwidth
        MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB
        if file.size and file.size > MAX_AVATAR_SIZE:
            size_mb = file.size / (1024 * 1024)
            logger.warning(f"Avatar file too large: {size_mb:.2f}MB (max: 5MB)")
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Image file too large: {size_mb:.2f}MB. Maximum size is 5MB. Please compress or scale down the image.",
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
                detail="Failed to create avatar storage directory",
            )

        # Generate unique filename to avoid conflicts

        file_ext = os.path.splitext(file.filename)[1].lower()

        if not file_ext in [".jpg", ".jpeg", ".png", ".gif", ".webp"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported image format",
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

        if not re.match(r"^[a-zA-Z0-9_.-]+\.[a-zA-Z0-9]+$", new_file_name):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Filename generation failed",
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
                    detail="Failed to save file - file not created",
                )

        except Exception as save_error:
            logger.error(f"Failed to save avatar file: {save_error}")

            logger.error(f"File path attempted: {new_file_path}")

            logger.error(f"Directory exists: {avatar_dir.exists()}")

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save file",
            )

        # Generate absolute URL AFTER file is saved
        # CRITICAL FIX: Use base URL without /api/v1 for avatar URLs to work correctly
        from backend.config import settings

        base_url = settings.API_BASE_URL.replace("/api/v1", "")
        avatar_url = f"{base_url}/users/avatar/{new_file_name}"

        # Update the user in the database with timeout

        updated_user = None

        try:
            user_id = _maybe_object_id(current_user)

            result = await asyncio.wait_for(
                users_collection().update_one(
                    {"_id": user_id},
                    {
                        "$set": {
                            "avatar_url": avatar_url,
                            "avatar": None,
                            "updated_at": datetime.now(timezone.utc),
                        }
                    },
                ),
                timeout=5.0,
            )

            # Fetch updated user to return complete data

            updated_user = await asyncio.wait_for(
                users_collection().find_one({"_id": user_id}), timeout=5.0
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
            "message": "Avatar uploaded successfully",
        }

        logger.debug(
            f"Avatar upload completed successfully: avatar_url={avatar_url}, avatar={response_data['avatar']}"
        )

        # Validate response data before sending

        if not isinstance(response_data, dict):
            logger.error(f"Response data is not a dict: {type(response_data)}")

            response_data = {
                "avatar_url": avatar_url,
                "avatar": "",
                "success": False,
                "message": "Internal error",
            }

        if "avatar_url" not in response_data:
            logger.error("avatar_url missing from response_data")

            response_data["avatar_url"] = avatar_url

        if "avatar" not in response_data:
            response_data["avatar"] = ""  # Always empty string for image avatars

        logger.debug(f"Final response data: {response_data}")

        return JSONResponse(status_code=200, content=response_data)

    except HTTPException as http_exc:
        logger.warning(
            f"HTTP error in avatar upload: {http_exc.status_code} - {http_exc.detail}"
        )

        raise

    except Exception as e:
        import traceback

        logger.error(f"Unexpected error in avatar upload: {type(e).__name__}: {str(e)}")

        logger.error(f"Full traceback: {traceback.format_exc()}")

        _log(
            "error",
            f"Unexpected avatar upload error: {str(e)}",
            {"user_id": current_user, "operation": "avatar_upload"},
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload avatar: {str(e)}",
        )


@router.get("/avatar/{filename}")
@router.get("/avatar/{filename}/")
async def get_avatar(
    filename: str,
    current_user: Optional[str] = Depends(get_current_user_optional),
):
    logger.info(f"[GET_AVATAR] Requested filename: {filename}")

    # Sanitize filename
    file_name_only = (filename or "").split("/")[-1].split("\\")[-1]
    if not file_name_only or file_name_only != filename:
        logger.warning(f"[GET_AVATAR] Invalid filename format: {filename}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename"
        )
    if ".." in file_name_only or "\x00" in file_name_only:
        logger.warning(f"[GET_AVATAR] Path traversal attempt: {filename}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename"
        )

    from pathlib import Path
    import mimetypes

    avatar_dir = Path(settings.DATA_ROOT) / "avatars"
    file_path = avatar_dir / file_name_only

    logger.info(f"[GET_AVATAR] Looking for file at: {file_path}")
    logger.info(f"[GET_AVATAR] File exists: {file_path.exists()}")

    if not file_path.exists() or not file_path.is_file():
        logger.warning(f"[GET_AVATAR] File not found: {file_path}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Avatar not found"
        )

    # Determine MIME type
    mime_type, _ = mimetypes.guess_type(str(file_path))
    if not mime_type:
        mime_type = "application/octet-stream"

    logger.info(f"[GET_AVATAR] Serving file with MIME type: {mime_type}")

    return FileResponse(
        str(file_path),
        media_type=mime_type,
        headers={
            "Cache-Control": "public, max-age=86400",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/simple")
@router.get("/simple/")
async def get_users_simple(
    request: Request,
    offset: int = 0,
    limit: int = 50,
    current_user: str = Depends(get_current_user),
):
    """Get simple user list for group creation (excluding current user)"""
    try:
        if offset < 0:
            offset = 0
        if limit < 1:
            limit = 1
        if limit > 200:
            limit = 200

        # Get all users except current user
        users_col = users_collection()

        # Build query to exclude current user
        query = {"_id": {"$ne": current_user}}

        # Get total count
        total = await users_col.count_documents(query)

        # Get users with projection for simple response
        projection = {
            "_id": 1,
            "name": 1,
            "email": 1,
            "username": 1,
            "avatar_url": 1,
            "is_online": 1,
            "last_seen": 1,
            "status": 1,
        }

        cursor = (
            users_col.find(query, projection).sort("name", 1).skip(offset).limit(limit)
        )

        users = []
        async for doc in cursor:
            users.append(
                {
                    "id": str(doc.get("_id")),
                    "name": doc.get("name", ""),
                    "email": doc.get("email", ""),
                    "username": doc.get("username", ""),
                    "avatar_url": doc.get("avatar_url"),
                    "is_online": doc.get("is_online", False),
                    "last_seen": doc.get("last_seen"),
                    "status": doc.get("status", ""),
                }
            )

        return {
            "users": users,
            "total": total,
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
@router.get("/contacts/")
async def get_contacts_route(
    request: Request,
    offset: int = 0,
    limit: int = 50,
    current_user: str = Depends(get_current_user),
):
    return await get_contacts(
        request=request,
        offset=offset,
        limit=limit,
        current_user=current_user,
    )


async def get_contacts(
    request=None,
    offset: int = 0,
    limit: int = 50,
    current_user: str = None,
):
    """Get users excluding the current user (contacts directory) with pagination."""

    try:
        if offset < 0:
            offset = 0
        if limit < 1:
            limit = 1
        if limit > 200:
            limit = 200

        db = None
        if request is not None:
            state = getattr(request, "app", None)
            state = getattr(state, "state", None)
            db = getattr(state, "db", None)
        if db is None:
            from database import get_database

            db = get_database()
        if db is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not initialized",
            )

        users_col = db["users"]

        # Load current user's contacts and return only those.
        current_doc = None
        current_oid = _maybe_object_id(current_user)
        if current_oid is not None:
            current_doc = await users_col.find_one({"_id": current_oid})
        if current_doc is None:
            current_doc = await users_col.find_one({"_id": current_user})
        if current_doc is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        contacts_ids = current_doc.get("contacts") or []
        if not isinstance(contacts_ids, list):
            contacts_ids = []

        contact_oids = []
        contact_strs = []
        for cid in contacts_ids:
            if cid is None:
                continue
            if isinstance(cid, str) and ObjectId.is_valid(cid):
                contact_oids.append(ObjectId(cid))
                contact_strs.append(cid)
            else:
                contact_strs.append(str(cid))

        if not contact_oids and not contact_strs:
            return {"contacts": [], "total": 0, "offset": offset, "limit": limit}

        query = {"_id": {"$in": list(set(contact_oids + contact_strs))}}
        total = await users_col.count_documents(query)

        projection = {
            "_id": 1,
            "name": 1,
            "email": 1,
            "username": 1,
            "avatar_url": 1,
            "is_online": 1,
            "last_seen": 1,
            "status": 1,
        }

        contacts = []
        cursor = (
            users_col.find(query, projection).sort("name", 1).skip(offset).limit(limit)
        )
        async for doc in cursor:
            contacts.append(
                {
                    "id": str(doc.get("_id")),
                    "name": doc.get("name", ""),
                    "email": doc.get("email", ""),
                    "username": doc.get("username"),
                    "avatar_url": doc.get("avatar_url"),
                    "is_online": doc.get("is_online", False),
                    "last_seen": doc.get("last_seen"),
                    "status": doc.get("status", ""),
                }
            )

        return {
            "contacts": contacts,
            "total": total,
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
            detail=f"Failed to fetch contacts: {str(e)}",
        )


@router.post("/contacts", response_model=ContactResponse)
async def add_contact(
    request: ContactAddRequest, current_user: str = Depends(get_current_user)
):
    """Add a new contact by user_id, username, or email"""

    try:
        # Validate that at least one identifier is provided

        if not any([request.user_id, request.username, request.email]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either user_id, username, or email must be provided",
            )

        # Find the target user

        identifier_field, identifier_value = request.get_identifier()

        if identifier_field == "user_id":
            target_user = await asyncio.wait_for(
                users_collection().find_one({"_id": identifier_value}), timeout=5.0
            )

        elif identifier_field == "username":
            target_user = await asyncio.wait_for(
                users_collection().find_one({"username": identifier_value}), timeout=5.0
            )

        elif identifier_field == "email":
            target_user = await asyncio.wait_for(
                users_collection().find_one({"email": identifier_value}), timeout=5.0
            )

        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        # Don't allow adding self as contact

        if target_user["_id"] == current_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot add yourself as a contact",
            )

        # Check if already in contacts

        current_user_data = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}), timeout=5.0
        )

        existing_contacts = current_user_data.get("contacts", [])

        if target_user["_id"] in existing_contacts:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is already in your contacts",
            )

        # Add contact

        contact_entry = {
            "user_id": target_user["_id"],
            "display_name": request.display_name
            or target_user.get("name", target_user.get("username", "")),
            "added_at": datetime.now(timezone.utc),
        }

        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {
                    "$push": {"contacts": target_user["_id"]},
                    "$set": {"updated_at": datetime.now(timezone.utc)},
                },
            ),
            timeout=5.0,
        )

        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        return {
            "message": "Contact added successfully",
            "contact_id": target_user["_id"],
            "contact_name": target_user.get("name", target_user.get("username", "")),
            "display_name": contact_entry["display_name"],
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
            detail=f"Failed to add contact: {str(e)}",
        )


@router.post("/users/contacts", response_model=ContactResponse)
async def add_contact_alias(
    request: ContactAddRequest, current_user: str = Depends(get_current_user)
):
    return await add_contact(request=request, current_user=current_user)


@router.delete("/contacts/{contact_id}")
async def remove_contact(
    contact_id: str, current_user: str = Depends(get_current_user)
):
    """Remove a contact"""

    try:
        # Check if contact exists

        current_user_data = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}), timeout=5.0
        )

        if not current_user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        existing_contacts = current_user_data.get("contacts", [])

        if contact_id not in existing_contacts:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found"
            )

        # Remove contact

        result = await asyncio.wait_for(
            users_collection().update_one(
                {"_id": current_user},
                {
                    "$pull": {"contacts": contact_id},
                    "$set": {"updated_at": datetime.now(timezone.utc)},
                },
            ),
            timeout=5.0,
        )

        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        return {"message": "Contact removed successfully"}

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
            detail=f"Failed to remove contact: {str(e)}",
        )


@router.delete("/users/contacts/{contact_id}")
async def remove_contact_alias(
    contact_id: str, current_user: str = Depends(get_current_user)
):
    return await remove_contact(contact_id=contact_id, current_user=current_user)


# ========== BLOCK/UNBLOCK USER ENDPOINTS ==========


@router.post("/{user_id}/block")
async def block_user(user_id: str, current_user: str = Depends(get_current_user)):
    """Block a user - prevent them from contacting you"""
    try:
        from bson import ObjectId

        # Validation: Cannot block yourself
        if user_id == current_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot block yourself",
            )

        # Validate that target user exists
        target_user_oid = ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id
        target_user = await users_collection().find_one({"_id": target_user_oid})

        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        # Get current user data
        current_user_oid = (
            ObjectId(current_user) if ObjectId.is_valid(current_user) else current_user
        )
        current_user_data = await users_collection().find_one({"_id": current_user_oid})

        if not current_user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current user not found",
            )

        # Get blocked_users list (or empty list if it doesn't exist)
        blocked_users = current_user_data.get("blocked_users", [])

        # Validation: Check if already blocked
        if user_id in blocked_users:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="User is already blocked"
            )

        # Add user to blocked list
        blocked_users.append(user_id)

        # Update database
        result = await users_collection().update_one(
            {"_id": current_user_oid},
            {
                "$set": {
                    "blocked_users": blocked_users,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )

        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to block user",
            )

        logger.info(f"User {current_user} blocked user {user_id}")

        return {
            "status": "SUCCESS",
            "message": f"User {target_user.get('name', user_id)} blocked successfully",
            "data": {
                "blocked_user_id": user_id,
                "blocked_user_name": target_user.get("name"),
                "total_blocked": len(blocked_users),
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to block user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to block user: {str(e)}",
        )


@router.post("/{user_id}/unblock")
async def unblock_user(user_id: str, current_user: str = Depends(get_current_user)):
    """Unblock a user - allow them to contact you again"""
    try:
        from bson import ObjectId

        # Get current user data
        current_user_oid = (
            ObjectId(current_user) if ObjectId.is_valid(current_user) else current_user
        )
        current_user_data = await users_collection().find_one({"_id": current_user_oid})

        if not current_user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current user not found",
            )

        # Get blocked_users list
        blocked_users = current_user_data.get("blocked_users", [])

        # Validation: Check if user is actually blocked
        if user_id not in blocked_users:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User is not in your blocked list",
            )

        # Remove user from blocked list
        blocked_users.remove(user_id)

        # Update database
        result = await users_collection().update_one(
            {"_id": current_user_oid},
            {
                "$set": {
                    "blocked_users": blocked_users,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )

        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to unblock user",
            )

        logger.info(f"User {current_user} unblocked user {user_id}")

        # Get unblocked user's name for response
        target_user_oid = ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id
        target_user = await users_collection().find_one({"_id": target_user_oid})
        target_name = target_user.get("name") if target_user else user_id

        return {
            "status": "SUCCESS",
            "message": f"User {target_name} unblocked successfully",
            "data": {
                "unblocked_user_id": user_id,
                "unblocked_user_name": target_name,
                "total_blocked": len(blocked_users),
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unblock user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to unblock user: {str(e)}",
        )


@router.get("/blocked/list")
async def get_blocked_users(current_user: str = Depends(get_current_user)):
    """Get list of users blocked by current user"""
    try:
        from bson import ObjectId

        # Get current user data
        current_user_oid = (
            ObjectId(current_user) if ObjectId.is_valid(current_user) else current_user
        )
        current_user_data = await users_collection().find_one({"_id": current_user_oid})

        if not current_user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current user not found",
            )

        # Get blocked_users list
        blocked_user_ids = current_user_data.get("blocked_users", [])

        # If no blocked users, return empty list
        if not blocked_user_ids:
            return {
                "status": "SUCCESS",
                "message": "No blocked users",
                "data": {"blocked_users": [], "total_count": 0},
            }

        # Fetch actual user documents for blocked users with single batch query
        blocked_users_list = []

        # Convert valid string IDs to ObjectId objects
        valid_oids = []
        for blocked_id in blocked_user_ids:
            if ObjectId.is_valid(blocked_id):
                valid_oids.append(ObjectId(blocked_id))

        if valid_oids:
            # Single batch query to fetch all blocked users
            blocked_users_cursor = users_collection().find(
                {"_id": {"$in": valid_oids}},
                {
                    "name": 1,
                    "username": 1,
                    "email": 1,
                    "avatar_url": 1,
                    "status": 1,
                    "_id": 1,
                },
            )

            async for blocked_user in blocked_users_cursor:
                blocked_users_list.append(
                    {
                        "id": str(blocked_user["_id"]),
                        "name": blocked_user.get("name"),
                        "username": blocked_user.get("username"),
                        "email": blocked_user.get("email"),
                        "avatar_url": blocked_user.get("avatar_url"),
                        "status": blocked_user.get("status"),
                    }
                )

        return {
            "status": "SUCCESS",
            "message": f"Retrieved {len(blocked_users_list)} blocked users",
            "data": {
                "blocked_users": blocked_users_list,
                "total_count": len(blocked_users_list),
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get blocked users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get blocked users: {str(e)}",
        )


@router.get("/{user_id}/is-blocked")
async def check_if_blocked(user_id: str, current_user: str = Depends(get_current_user)):
    """Check if a specific user is blocked by current user"""
    try:
        from bson import ObjectId

        # Get current user data
        current_user_oid = (
            ObjectId(current_user) if ObjectId.is_valid(current_user) else current_user
        )
        current_user_data = await users_collection().find_one({"_id": current_user_oid})

        if not current_user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current user not found",
            )

        # Get blocked_users list
        blocked_user_ids = current_user_data.get("blocked_users", [])

        # Check if user is blocked
        is_blocked = user_id in blocked_user_ids

        return {
            "status": "SUCCESS",
            "data": {"user_id": user_id, "is_blocked": is_blocked},
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check if user is blocked: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check if user is blocked: {str(e)}",
        )
