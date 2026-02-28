from fastapi import APIRouter, Depends, HTTPException, status, Body, Query, UploadFile, File
from fastapi.encoders import jsonable_encoder
from typing import List, Optional, Any, Dict
from datetime import datetime, timezone, timedelta
from bson import ObjectId
import asyncio
import json
import logging
import os
import uuid
import re
import base64
from pathlib import Path

from auth.utils import get_current_user, get_current_user_optional
from pydantic import BaseModel, Field

try:
    from ..db_proxy import chats_collection, users_collection, messages_collection, get_database
    from ..models import GroupCreate, GroupUpdate, GroupMembersUpdate, GroupMemberRoleUpdate, ChatPermissions, UserPublic
    from ..redis_cache import GroupCacheService, UserCacheService, SearchCacheService
    from ..config import settings
except ImportError:
    from db_proxy import chats_collection, users_collection, messages_collection, get_database
    from models import GroupCreate, GroupUpdate, GroupMembersUpdate, GroupMemberRoleUpdate, ChatPermissions, UserPublic
    from redis_cache import GroupCacheService, UserCacheService, SearchCacheService
    from config import settings

logger = logging.getLogger(__name__)


# WhatsApp-style Group Management Models
class GroupVisibility:
    EVERYONE = "everyone"
    PARTICIPANTS = "participants"
    ADMINS = "admins"
    CUSTOM = "custom"


class SenderKeyDistribution(BaseModel):
    group_id: str
    sender_key_id: str
    sender_key_b64: str  # Encrypted for each member
    chain_key_b64: str
    member_devices: List[str]
    created_at: datetime
    expires_at: datetime
    signature: str


class GroupStateChange(BaseModel):
    group_id: str
    change_type: str  # add_member, remove_member, promote_member, demote_member, change_visibility
    initiator_id: str
    target_user_id: Optional[str] = None
    old_state: Optional[Dict] = None
    new_state: Dict
    timestamp: datetime
    signature: str  # Signed by admin's device key
    sequence_number: int


def _log(level: str, message: str, meta: Optional[dict] = None) -> None:
    """Lightweight structured logging helper used throughout this module.

    The function is intentionally defensive so that logging can never break
    the main request handling logic.
    """
    meta = meta or {}
    try:
        log_level = getattr(logging, level.upper(), logging.INFO)
        logger.log(log_level, message, extra={"meta": meta})
    except Exception:
        # Fallback that never raises in case logging configuration is broken
        logger.error(f"[GROUPS_LOG_FAIL] {level}: {message} | meta={meta}")


router = APIRouter(prefix="/groups", tags=["Groups"])

import sys


def _id_query(id_value: str) -> dict:
    try:
        if ObjectId.is_valid(id_value):
            return {"$or": [{"_id": ObjectId(id_value)}, {"_id": id_value}]}
    except Exception:
        pass
    return {"_id": id_value}


def _encode_doc(doc: Any) -> Any:
    return jsonable_encoder(doc, custom_encoder={ObjectId: str})

sys.modules.setdefault("routes.groups", sys.modules[__name__])
sys.modules.setdefault("backend.routes.groups", sys.modules[__name__])


class _ToggleMemberAddPermissionBody(BaseModel):
    enabled: bool


class _AddMembersBody(BaseModel):
    participant_ids: List[str] = []


# OPTIONS handlers for CORS preflight requests
@router.options("")
@router.options("/{group_id}")
@router.options("/{group_id}/members")
@router.options("/{group_id}/members/{member_id}")
@router.options("/{group_id}/members/{member_id}/role")
@router.options("/{group_id}/members/{member_id}/restrict")
async def groups_options(request):
    """Handle CORS preflight for groups endpoints"""
    from fastapi.responses import Response
    # SECURITY: Restrict CORS origins in production for authenticated endpoints
    try:
        from .auth import get_safe_cors_origin
    except Exception:
        from routes.auth import get_safe_cors_origin
    
    cors_origin = get_safe_cors_origin(request.headers.get("origin", ""))
    
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": cors_origin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400"
        }
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _collect_cursor(cursor, limit: Optional[int] = None) -> List[dict]:
    if cursor is None:
        return []

    raw_aiter = None
    try:
        raw_aiter = getattr(cursor, "__dict__", {}).get("__aiter__")
    except Exception:
        raw_aiter = None

    if raw_aiter is None:
        try:
            raw_aiter = getattr(getattr(cursor, "_mock_children", None) or {}, "get", lambda _k, _d=None: None)("__aiter__")
        except Exception:
            raw_aiter = None

    if raw_aiter is None:
        try:
            raw_aiter = getattr(cursor, "__aiter__", None)
        except Exception:
            raw_aiter = None

    if callable(raw_aiter):
        items: List[dict] = []

        aiter_callable = raw_aiter
        try:
            from unittest.mock import Mock as _MockBase
        except Exception:
            _MockBase = None

        if _MockBase is not None and isinstance(raw_aiter, _MockBase):
            try:
                wrapped = getattr(raw_aiter, "_mock_wraps", None)
                if callable(wrapped):
                    aiter_callable = wrapped
            except Exception:
                pass

            if aiter_callable is raw_aiter:
                try:
                    side_effect = getattr(raw_aiter, "side_effect", None)
                    if callable(side_effect):
                        aiter_callable = side_effect
                except Exception:
                    pass

        try:
            it = aiter_callable()
        except TypeError:
            # unittest.mock may wrap a user-provided zero-arg lambda as:
            #   lambda *args, **kw: original(self, *args, **kw)
            # which breaks when original expects 0 args.
            orig = None
            try:
                closure = getattr(aiter_callable, "__closure__", None)
                freevars = getattr(getattr(aiter_callable, "__code__", None), "co_freevars", ())
                if closure and freevars and len(closure) == len(freevars):
                    mapping = {name: cell.cell_contents for name, cell in zip(freevars, closure)}
                    candidate = mapping.get("original")
                    if callable(candidate):
                        orig = candidate
                    else:
                        for cell in mapping.values():
                            if callable(cell):
                                orig = cell
                                break
            except Exception:
                orig = None

            if callable(orig):
                it = orig()
                # If orig() returns a coroutine, await it
                if hasattr(it, "__await__"):
                    result = await it
                    # Check if result is iterable but not async iterable
                    if hasattr(result, "__iter__") and not hasattr(result, "__anext__"):
                        # It's a regular iterable (like a list), extend items directly
                        items.extend(result)
                        if limit is not None:
                            items = items[:limit]
                        return items
                    else:
                        it = result
            else:
                raise
        if hasattr(it, "__anext__"):
            while True:
                try:
                    item = await it.__anext__()
                except StopAsyncIteration:
                    break
                items.append(item)
                if limit is not None and len(items) >= limit:
                    break
        else:
            # Handle case where it is still a coroutine
            if hasattr(it, "__await__"):
                result = await it
                if hasattr(result, "__iter__") and not hasattr(result, "__anext__"):
                    items.extend(result)
                    if limit is not None:
                        items = items[:limit]
                    return items
            else:
                for item in it:
                    items.append(item)
                    if limit is not None and len(items) >= limit:
                        break
        return items

    if hasattr(cursor, "to_list"):
        try:
            return await cursor.to_list(limit)
        except TypeError:
            return await cursor.to_list(None)

    items: List[dict] = []
    try:
        async for item in cursor:
            items.append(item)
            if limit is not None and len(items) >= limit:
                break
        return items
    except TypeError:
        pass

    try:
        aiter = object.__getattribute__(cursor, "__aiter__")
    except Exception:
        return items

    if callable(aiter):
        it = aiter()
        if hasattr(it, "__anext__"):
            while True:
                try:
                    item = await it.__anext__()
                except StopAsyncIteration:
                    break
                items.append(item)
                if limit is not None and len(items) >= limit:
                    break
        else:
            for item in it:
                items.append(item)
                if limit is not None and len(items) >= limit:
                    break

    return items


def _safe_image_extension(filename: str) -> str:
    name = (filename or "").strip().lower()
    if name.endswith(".jpg") or name.endswith(".jpeg"):
        return ".jpg"
    if name.endswith(".png"):
        return ".png"
    if name.endswith(".webp"):
        return ".webp"
    if name.endswith(".gif"):
        return ".gif"
    raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported image type")


@router.post("/{group_id}/avatar")
async def upload_group_avatar(
    group_id: str,
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user),
):
    group = await _require_group(group_id, current_user)
    if not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can update group")

    ext = _safe_image_extension(file.filename or "")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file")
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Image too large")

    data_root = Path(settings.DATA_ROOT)
    avatars_dir = data_root / "group_avatars"
    avatars_dir.mkdir(parents=True, exist_ok=True)

    safe_name = f"{group_id}_{uuid.uuid4().hex}{ext}"
    out_path = avatars_dir / safe_name

    try:
        with open(out_path, "wb") as f:
            f.write(content)
    except OSError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to save avatar")

    avatar_url = f"/api/v1/groups/avatar/{safe_name}"
    return {"avatar_url": avatar_url, "filename": safe_name}


@router.get("/avatar/{filename}")
async def get_group_avatar(filename: str, current_user: Optional[str] = Depends(get_current_user_optional)):
    from fastapi.responses import FileResponse

    if not filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")

    dangerous_patterns = ['..', '\\', '/', '\x00']
    for pattern in dangerous_patterns:
        if pattern in filename:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")

    if not re.match(r'^[a-zA-Z0-9_.-]+\.([a-zA-Z0-9]+)$', filename):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename format")

    data_root = Path(settings.DATA_ROOT)
    file_path = data_root / "group_avatars" / filename
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Avatar not found")

    filename_lower = filename.lower()
    if filename_lower.endswith((".jpg", ".jpeg")):
        media_type = "image/jpeg"
    elif filename_lower.endswith(".png"):
        media_type = "image/png"
    elif filename_lower.endswith(".gif"):
        media_type = "image/gif"
    elif filename_lower.endswith(".webp"):
        media_type = "image/webp"
    else:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported file type")

    _ = current_user
    return FileResponse(file_path, media_type=media_type, filename=filename, headers={"Cache-Control": "public, max-age=3600"})


async def _require_group(group_id: str, current_user: str) -> dict:
    # Backward compatibility: older data stored chats._id as a string.
    query = {"_id": group_id, "type": "group", "members": {"$in": [current_user]}}
    try:
        if ObjectId.is_valid(group_id):
            query = {
                "$or": [{"_id": ObjectId(group_id)}, {"_id": group_id}],
                "type": "group",
                "members": {"$in": [current_user]},
            }
    except Exception:
        pass

    group = await chats_collection().find_one(query)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return group


def _is_admin(group: dict, user_id: str) -> bool:
    admins = group.get("admins", [])
    return user_id in admins


async def _log_activity(group_id: str, actor_id: str, event: str, meta: Optional[dict] = None) -> None:
    db = get_database()
    col = db.group_activity
    doc = {
        "_id": str(ObjectId()),
        "group_id": group_id,
        "actor_id": actor_id,
        "event": event,
        "meta": meta or {},
        "created_at": _now(),
    }
    await col.insert_one(doc)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_group(payload: GroupCreate, current_user: str = Depends(get_current_user)):
    """Create a new group chat (stored in chats collection with type=group)."""
    print(f"[GROUP_CREATE] Creating group for user: {current_user}")
    print(f"[GROUP_CREATE] Payload member_ids: {payload.member_ids}")
    
    if not payload.name or not payload.name.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group name is required")

    member_ids = list(dict.fromkeys([*(payload.member_ids or []), current_user]))
    print(f"[GROUP_CREATE] After adding current_user: {member_ids}")
    
    if len(member_ids) < 2:
        print(f"[GROUP_CREATE] ERROR: Group must have at least 2 members, got {len(member_ids)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group must have at least 2 members")

    group_oid = ObjectId()
    group_id = str(group_oid)
    chat_doc = {
        "_id": group_oid,
        "type": "group",
        "name": payload.name.strip(),
        "description": (payload.description or "").strip(),
        "avatar_url": (payload.avatar_url or "").strip() or None,
        "members": member_ids,  # Ensure all members including current_user are included
        "admins": [current_user],
        "created_by": current_user,
        "created_at": _now(),
        "muted_by": [],
        "permissions": {
            "allow_member_add": False
        },
    }
    
    print(f"[GROUP_CREATE] Final chat_doc members: {chat_doc['members']}")

    await chats_collection().insert_one(chat_doc)
    print(f"[GROUP_CREATE] Group {group_id} created successfully")
    await _log_activity(group_id, current_user, "group_created", {"name": chat_doc["name"]})

    # Activity for added members (excluding creator)
    for uid in member_ids:
        if uid != current_user:
            await _log_activity(group_id, current_user, "member_added", {"user_id": uid})

    # Fetch member details for frontend
    members_detail = []
    async def fetch_member(uid: str) -> Optional[dict]:
        user_profile = await UserCacheService.get_user_profile(uid)
        if user_profile:
            return user_profile
        return await users_collection().find_one({"_id": uid})

    tasks = [fetch_member(uid) for uid in member_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for uid, user in zip(member_ids, results):
        if isinstance(user, Exception) or not user:
            members_detail.append({"user_id": uid, "role": "admin" if uid in chat_doc["admins"] else "member"})
        else:
            members_detail.append({
                "user_id": uid,
                "name": user.get("name"),
                "email": user.get("email"),
                "username": user.get("username"),
                "role": "admin" if uid in chat_doc["admins"] else "member",
            })

    # Return group with member details for frontend
    chat_doc["member_count"] = len(member_ids)
    chat_doc["members"] = member_ids
    chat_doc["members_detail"] = members_detail
    chat_doc["is_admin"] = True  # Creator is always admin
    
    print(f"[GROUP_CREATE] Returning group with {len(member_ids)} members and {len(members_detail)} member details")
    
    return {"group_id": group_id, "chat_id": group_id, "group": chat_doc}


@router.get("")
async def list_groups(current_user: str = Depends(get_current_user)):
    """List groups for current user."""
    groups = []
    cursor = chats_collection().find({"type": "group", "members": {"$in": [current_user]}})

    # Some test mocks make sort() async, returning a coroutine.
    try:
        cursor_sorted = cursor.sort("created_at", -1)
        if hasattr(cursor_sorted, "__await__") and not hasattr(cursor_sorted, "__aiter__"):
            cursor = await cursor_sorted
        else:
            cursor = cursor_sorted
    except Exception:
        # If sort is not supported, continue without sorting.
        pass

    # Convert cursor to list with broad compatibility across Motor + mocks.
    chats = []
    try:
        if hasattr(cursor, "__await__") and not hasattr(cursor, "__aiter__"):
            cursor = await cursor

        if hasattr(cursor, "__aiter__"):
            async for doc in cursor:
                chats.append(doc)
        elif hasattr(cursor, "to_list"):
            chats = await cursor.to_list(length=None)
        else:
            chats = list(cursor)
    except Exception:
        chats = []
    
    for chat in chats:
        # Attach the last message
        last_message = await messages_collection().find_one(
            {"chat_id": chat["_id"], "is_deleted": {"$ne": True}},
            sort=[("created_at", -1)],
        )
        chat["last_message"] = last_message
        
        # Add member count for frontend
        members = chat.get("members", [])
        chat["member_count"] = len(members)
        chat["members"] = members  # Ensure members array is included
        
        print(f"[LIST_GROUPS] Group {chat['_id']}: {len(members)} members")
        
        groups.append(chat)
    return {"groups": groups}


@router.get("/{group_id}/member-suggestions", response_model=List[UserPublic])
async def get_member_suggestions(
    group_id: str, 
    q: Optional[str] = None,
    limit: int = 20,
    current_user: str = Depends(get_current_user)
):
    """Get contact suggestions for adding to group (excluding current members)"""
    
    # Require user to be member of the group (not necessarily admin)
    group = await _require_group(group_id, current_user)
    
    # Get current members
    current_members = set(group.get("members", []))
    
    # Try to get suggestions from cache
    cache_key = f"group:{group_id}:member_suggestions:{current_user}"
    cached_suggestions = SearchCacheService.get_user_search(cache_key)
    if hasattr(cached_suggestions, '__await__'):
        cached_suggestions = await cached_suggestions
    
    if cached_suggestions is not None:
        # Return cached suggestions
        suggestions = json.loads(cached_suggestions) if isinstance(cached_suggestions, str) else cached_suggestions
    else:
        # Build suggestions from database
        # Get user's contacts
        contacts = await UserCacheService.get_user_contacts(current_user)
        if not contacts:
            # Fallback to database
            user_data = await users_collection().find_one({"_id": current_user})
            contacts = user_data.get("contacts", []) if user_data else []
            await UserCacheService.set_user_contacts(current_user, contacts)
        
        # Filter out current members and get contact details
        available_contacts = [uid for uid in contacts if uid not in current_members]
        
        suggestions = []
        if available_contacts:
            # Get contact details
            cursor = users_collection().find(
                {"_id": {"$in": available_contacts}},
                {
                    "_id": 1,
                    "name": 1,
                    "email": 1,
                    "username": 1,
                    "avatar_url": 1,
                    "is_online": 1,
                    "last_seen": 1,
                    "status": 1
                }
            )
            
            # Check if cursor is a coroutine (mock DB) or cursor (real MongoDB)
            if hasattr(cursor, '__await__') and not hasattr(cursor, '__aiter__'):
                cursor = await cursor

            for contact in await _collect_cursor(cursor, limit=limit):
                # Create UserPublic object from contact data
                user_public = UserPublic(
                    id=contact.get("_id"),
                    name=contact.get("name"),
                    email=contact.get("email"),
                    username=contact.get("username"),
                    avatar_url=contact.get("avatar_url"),
                    is_online=contact.get("is_online", False),
                    last_seen=contact.get("last_seen"),
                    status=contact.get("status")
                )
                
                contact_data = user_public.model_dump()
                
                # Apply search filter if provided
                if q:
                    q_lower = q.lower()
                    if (q_lower in contact_data["name"].lower() or 
                        q_lower in (contact_data["username"] or "").lower() or
                        q_lower in contact_data.get("email", "").lower()):
                        suggestions.append(contact_data)
                else:
                    suggestions.append(contact_data)
            
            # Limit results
            suggestions = suggestions[:limit]
        else:
            # CRITICAL FIX: Fallback to all users when no contacts available
            _log("info", f"No contacts found for user {current_user}, loading all users as fallback")
            
            # Get all users except current user and current members
            exclude_ids = set(current_members)
            exclude_ids.add(current_user)  # Exclude current user
            
            cursor = await users_collection().find(
                {"_id": {"$nin": list(exclude_ids)}},
                {
                    "_id": 1,
                    "name": 1,
                    "email": 1,
                    "username": 1,
                    "avatar_url": 1,
                    "is_online": 1,
                    "last_seen": 1,
                    "status": 1
                }
            )
            cursor = cursor.limit(limit * 2)  # Get more to account for filtering
            
            # Check if cursor is a coroutine (mock DB) or cursor (real MongoDB)
            if hasattr(cursor, '__await__') and not hasattr(cursor, '__aiter__'):
                cursor = await cursor
            
            for user in await _collect_cursor(cursor, limit=limit * 2):
                # Create UserPublic object from user data
                user_public = UserPublic(
                    id=user.get("_id"),
                    name=user.get("name"),
                    email=user.get("email"),
                    username=user.get("username"),
                    avatar_url=user.get("avatar_url"),
                    is_online=user.get("is_online", False),
                    last_seen=user.get("last_seen"),
                    status=user.get("status")
                )
                
                user_data = user_public.model_dump()
                
                # Apply search filter if provided
                if q:
                    q_lower = q.lower()
                    if (q_lower in user_data["name"].lower() or 
                        q_lower in (user_data["username"] or "").lower() or
                        q_lower in user_data["email"].lower()):
                        suggestions.append(user_data)
                else:
                    suggestions.append(user_data)
            
            # Limit results and sort by online status and name
            suggestions = suggestions[:limit]
            suggestions.sort(key=lambda x: (0 if x.get("is_online", False) else 1, x["name"].lower()))
        
        # Cache the results (even if empty)
        cache_write = SearchCacheService.set_user_search(cache_key, suggestions)
        if hasattr(cache_write, '__await__'):
            await cache_write
    
    return suggestions


@router.get("/{group_id}")
async def get_group(group_id: str, current_user: str = Depends(get_current_user)):
    """Get group details + basic member info."""
    
    # Try to get group info from cache first
    group = await GroupCacheService.get_group_info(group_id)
    if not group:
        group = await _require_group(group_id, current_user)
        # Cache the group info
        await GroupCacheService.set_group_info(group_id, group)
    
    member_ids: List[str] = group.get("members", [])
    admins: List[str] = group.get("admins", [])

    # Fetch member records (best-effort)
    members: List[Dict[str, Any]] = []

    async def fetch_member(uid: str) -> Optional[dict]:
        # Try to get user profile from cache first
        user_profile = await UserCacheService.get_user_profile(uid)
        if user_profile:
            return user_profile
        # Fallback to database
        return await users_collection().find_one({"_id": uid})

    # Avoid slow sequential queries for large groups (using basic parallelism with gather)
    tasks = [fetch_member(uid) for uid in member_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for uid, user in zip(member_ids, results):
        if isinstance(user, Exception) or not user:
            members.append({"user_id": uid, "role": "admin" if uid in admins else "member"})
        else:
            members.append({
                "user_id": uid,
                "name": user.get("name"),
                "email": user.get("email"),
                "username": user.get("username"),
                "role": "admin" if uid in admins else "member",
            })

    group_out = dict(group)
    group_out["members_detail"] = members
    group_out["is_admin"] = _is_admin(group, current_user)
    
    # Add member count for frontend compatibility
    group_out["member_count"] = len(member_ids)
    group_out["members"] = member_ids  # Ensure members array is included
    
    # CRITICAL FIX: Include muted_by field for notification mute functionality
    group_out["muted_by"] = group.get("muted_by", [])
    
    print(f"[GET_GROUP] Group {group_id}: {len(member_ids)} members, {len(members)} member details")
    
    return {"group": group_out}


@router.put("/{group_id}")
async def update_group(group_id: str, payload: GroupUpdate, current_user: str = Depends(get_current_user)):
    group = await _require_group(group_id, current_user)
    if not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can update group")

    update: Dict[str, Any] = {}
    if payload.name is not None:
        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group name cannot be empty")
        update["name"] = name
    if payload.description is not None:
        update["description"] = payload.description.strip()
    if payload.avatar_url is not None:
        update["avatar_url"] = payload.avatar_url.strip() or None

    if update:
        update["updated_at"] = _now()
        await chats_collection().update_one(_id_query(group_id), {"$set": update})
    if update:
        await _log_activity(group_id, current_user, "group_updated", {"fields": list(update.keys())})

    group_new = await chats_collection().find_one(_id_query(group_id))
    return {"group": _encode_doc(group_new)}


@router.post("/{group_id}/members")
async def add_members(group_id: str, payload: GroupMembersUpdate, current_user: str = Depends(get_current_user)):
    """Add members to a group.

    Behaviour required by tests:
    - Only admins can add members (403 otherwise).
    - Returns JSON with keys: added, member_count, members, message.
    - Empty list -> 200 with added=0.
    - user_ids is None -> 400.
    """
    print(f"[ADD_MEMBERS] ===== ADD MEMBERS REQUEST START =====")
    print(f"[ADD_MEMBERS] Group ID: {group_id}")
    print(f"[ADD_MEMBERS] Current User: {current_user}")
    print(f"[ADD_MEMBERS] Payload: {payload}")

    # Load group and ensure current_user is member
    group = await _require_group(group_id, current_user)

    # Only admins can add members
    if not _is_admin(group, current_user):
        print(f"[ADD_MEMBERS] User {current_user} is NOT admin. Admins: {group.get('admins', [])}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can add members",
        )

    user_ids = payload.user_ids

    # Explicitly treat null as validation error (tests expect 400)
    if user_ids is None:
        print("[ADD_MEMBERS] user_ids is None -> returning 400")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="user_ids must not be null",
        )

    # Normalise to list and clean values
    if isinstance(user_ids, str):
        if "," in user_ids:
            user_ids = [u.strip() for u in user_ids.split(",") if u.strip()]
        else:
            user_ids = [user_ids.strip()] if user_ids.strip() else []

    if not isinstance(user_ids, list):
        print(f"[ADD_MEMBERS] Invalid user_ids format: {type(user_ids)}")
        return {"added": 0, "member_count": len(group.get("members", [])), "members": group.get("members", []), "message": "Invalid user_ids format"}

    # Determine current members, preferring cache if available for large operations
    cached_members = GroupCacheService.get_group_members(group_id)
    if hasattr(cached_members, "__await__"):
        cached_members = await cached_members

    if cached_members is not None:
        current_members: list = list(cached_members)
    else:
        current_members: list = list(group.get("members", []))

    # Filter / dedupe IDs, skip empty and self
    current_set = set(current_members)
    new_ids: list[str] = []
    for raw in user_ids:
        if not raw:
            continue
        uid = str(raw).strip()
        if not uid or uid == current_user:
            continue
        if uid in current_set or uid in new_ids:
            continue
        new_ids.append(uid)

    print(f"[ADD_MEMBERS] Filtered new_ids: {new_ids}")

    if not new_ids:
        print("[ADD_MEMBERS] No valid new members to add")
        return {
            "added": 0,
            "member_count": len(current_members),
            "members": current_members,
            "message": "No valid user IDs to add",
        }

    # Persist to database (add to members set)
    await chats_collection().update_one(
        _id_query(group_id),
        {"$addToSet": {"members": {"$each": new_ids}}},
    )

    # Compute updated member list
    updated_members = current_members + new_ids

    # Update cached group members if cache layer is active
    try:
        cache_write = GroupCacheService.set_group_members(group_id, updated_members)
        if hasattr(cache_write, "__await__"):
            await cache_write
    except Exception:
        # Cache failures should not break core functionality
        pass

    print(f"[ADD_MEMBERS] Successfully added {len(new_ids)} members -> total {len(updated_members)}")
    print(f"[ADD_MEMBERS] ===== ADD MEMBERS REQUEST END =====")

    return {
        "added": len(new_ids),
        "member_count": len(updated_members),
        "members": updated_members,
        "message": f"Successfully added {len(new_ids)} members",
    }


@router.put("/{group_id}/members/{member_id}/role")
async def update_member_role(
    group_id: str,
    member_id: str,
    payload: GroupMemberRoleUpdate,
    current_user: str = Depends(get_current_user),
):
    group = await _require_group(group_id, current_user)
    if not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can update roles")

    role = payload.role
    if member_id not in group.get("members", []):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

    if role == "admin":
        await chats_collection().update_one(_id_query(group_id), {"$addToSet": {"admins": member_id}})
        await _log_activity(group_id, current_user, "member_promoted", {"user_id": member_id})
    else:
        # Prevent removing the last admin
        admins = group.get("admins", [])
        if member_id in admins and len(admins) <= 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group must have at least 1 admin")
        await chats_collection().update_one(_id_query(group_id), {"$pull": {"admins": member_id}})
        await _log_activity(group_id, current_user, "member_demoted", {"user_id": member_id})

    new_group = await chats_collection().find_one(_id_query(group_id))
    return {"group": _encode_doc(new_group)}




@router.post("/{group_id}/mute")
async def mute_group(group_id: str, mute: bool = True, current_user: str = Depends(get_current_user)):
    group = await _require_group(group_id, current_user)
    if mute:
        await chats_collection().update_one(_id_query(group_id), {"$addToSet": {"muted_by": current_user}})
        await _log_activity(group_id, current_user, "notifications_muted", {})
    else:
        await chats_collection().update_one(_id_query(group_id), {"$pull": {"muted_by": current_user}})
        await _log_activity(group_id, current_user, "notifications_unmuted", {})
    new_group = await chats_collection().find_one(_id_query(group_id))
    return {"group": _encode_doc(new_group)}


@router.get("/{group_id}/activity")
async def get_activity(group_id: str, limit: int = 50, current_user: str = Depends(get_current_user)):
    await _require_group(group_id, current_user)
    db = get_database()
    col = db.group_activity
    events = await col.find({"group_id": group_id}).sort("created_at", -1).limit(limit).to_list(limit)
    return {"events": list(reversed(events))}


@router.get("/{group_id}/pinned")
async def get_pinned_messages(group_id: str, limit: int = 20, current_user: str = Depends(get_current_user)):
    await _require_group(group_id, current_user)
    msgs = await messages_collection().find(
        {"chat_id": group_id, "is_pinned": True, "is_deleted": {"$ne": True}}
    ).sort("pinned_at", -1).limit(limit).to_list(limit)
    return {"messages": msgs}



@router.put("/{group_id}/permissions")
async def update_group_permissions(
    group_id: str, 
    permissions: ChatPermissions, 
    current_user: str = Depends(get_current_user)
):
    """Update global permissions for the group (what members can do)"""
    group = await _require_group(group_id, current_user)
    if not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can change permissions")

    # Preserve non-ChatPermissions fields stored under permissions (e.g. allow_member_add)
    existing_permissions = group.get("permissions", {}) or {}
    merged_permissions = dict(existing_permissions)
    merged_permissions.update(permissions.model_dump())

    await chats_collection().update_one(
        {"_id": group_id},
        {"$set": {"permissions": merged_permissions}}
    )
    
    await _log_activity(group_id, current_user, "permissions_updated", {})
    return {"status": "updated", "permissions": permissions}


@router.put("/{group_id}/members/{member_id}/restrict")
async def restrict_member(
    group_id: str,
    member_id: str,
    permissions: ChatPermissions,
    until_date: Optional[datetime] = None,
    current_user: str = Depends(get_current_user)
):
    """Restrict a user's permissions in the group"""
    group = await _require_group(group_id, current_user)
    if not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can restrict members")
        
    # Cannot restrict other admins
    if member_id in group.get("admins", []):
        raise HTTPException(status_code=403, detail="Cannot restrict an admin")

    # Store restrictions in a separate connection or embedded field
    # For now, store it in a 'restrictions' dict in the chat document or separate collection
    # A cleaner way is to use ChatMember model logic, but for now patch the chat document
    # Example: "restrictions": { "user_id": { permissions... } }
    
    restriction_data = permissions.model_dump()
    if until_date:
        restriction_data["until_date"] = until_date
        
    await chats_collection().update_one(
        {"_id": group_id},
        {"$set": {f"restrictions.{member_id}": restriction_data}}
    )
    
    await _log_activity(group_id, current_user, "member_restricted", {"user_id": member_id})
    return {"status": "restricted", "permissions": permissions}


# ============================================================================
# WHATSAPP-STYLE GROUP ADMIN FUNCTIONS
# ============================================================================

@router.put("/{group_id}/permissions/member-add")
async def toggle_member_add_permission(
    group_id: str,
    body: Optional[_ToggleMemberAddPermissionBody] = Body(None),
    enabled: Optional[bool] = None,
    current_user: str = Depends(get_current_user)
):
    """Enable/disable member add permission for non-admin members"""
    group = await _require_group(group_id, current_user)
    if not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can change permissions")

    effective_enabled = body.enabled if body is not None else (enabled if enabled is not None else True)
    
    # Update group permissions
    await chats_collection().update_one(
        {"_id": group_id},
        {"$set": {"permissions.allow_member_add": effective_enabled}}
    )
    
    await _log_activity(group_id, current_user, "member_add_permission_toggled", {"enabled": effective_enabled})
    
    return {
        "success": True,
        "message": f"Member add permission {'enabled' if effective_enabled else 'disabled'}",
        "permissions": {
            "allow_member_add": effective_enabled
        }
    }


@router.post("/{group_id}/is-admin")
async def is_admin_endpoint(group_id: str, current_user: str = Depends(get_current_user)):
    group = await _require_group(group_id, current_user)
    return {
        "group_id": group_id,
        "user_id": current_user,
        "is_admin": _is_admin(group, current_user),
        "allow_member_add": group.get("permissions", {}).get("allow_member_add", False),
    }


@router.get("/{group_id}/participants")
async def get_group_participants(
    group_id: str,
    current_user: str = Depends(get_current_user)
):
    """View all group participants with roles and permissions"""
    group = await _require_group(group_id, current_user)
    
    member_ids = group.get("members", [])
    admins = group.get("admins", [])
    
    # Fetch member details
    participants = []
    
    async def fetch_participant(uid: str) -> Optional[dict]:
        # Try cache first
        user_profile = await UserCacheService.get_user_profile(uid)
        if user_profile:
            return user_profile
        # Fallback to database
        return await users_collection().find_one({"_id": uid})
    
    # Use gather for parallel fetching
    tasks = [fetch_participant(uid) for uid in member_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for uid, user in zip(member_ids, results):
        if isinstance(user, Exception) or not user:
            # Create basic participant info if user not found
            participant = {
                "user_id": uid,
                "name": "Unknown User",
                "email": uid,
                "role": "admin" if uid in admins else "member",
                "is_admin": uid in admins,
                "added_at": group.get("created_at"),
                "status": "unknown"
            }
        else:
            participant = {
                "user_id": uid,
                "name": user.get("name", "Unknown User"),
                "email": user.get("email", uid),
                "username": user.get("username"),
                "avatar_url": user.get("avatar_url"),
                "role": "admin" if uid in admins else "member",
                "is_admin": uid in admins,
                "is_online": user.get("is_online", False),
                "last_seen": user.get("last_seen"),
                "status": user.get("status", "available"),
                "added_at": group.get("created_at")
            }
        
        participants.append(participant)
    
    # Sort by role (admins first) then by name
    participants.sort(key=lambda x: (0 if x["is_admin"] else 1, x["name"].lower()))
    
    return {
        "group_id": group_id,
        "participants": participants,
        "total_count": len(participants),
        "admin_count": len(admins),
        "member_count": len(member_ids) - len(admins),
        "permissions": {
            "allow_member_add": group.get("permissions", {}).get("allow_member_add", False),
            "current_user_is_admin": _is_admin(group, current_user)
        }
    }


@router.get("/{group_id}/contacts/search")
async def search_contacts_for_group(
    group_id: str,
    q: str = "",
    limit: int = 50,
    current_user: str = Depends(get_current_user)
):
    """Search contacts from phonebook for adding to group"""
    group = await _require_group(group_id, current_user)
    
    # Get current members to exclude them from suggestions
    current_members = set(group.get("members", []))
    
    # Get user's contacts
    contacts = await UserCacheService.get_user_contacts(current_user)
    if not contacts:
        # Fallback to database
        user_data = await users_collection().find_one({"_id": current_user})
        contacts = user_data.get("contacts", []) if user_data else []
        await UserCacheService.set_user_contacts(current_user, contacts)
    
    # Filter out current members
    available_contacts = [uid for uid in contacts if uid not in current_members]
    
    if not available_contacts:
        # CRITICAL FIX: Fallback to all users when no contacts available
        _log("info", f"No contacts found for user {current_user}, loading all users as fallback")
        
        # Get all users except current user and current members
        exclude_ids = set(current_members)
        exclude_ids.add(current_user)  # Exclude current user
        
        cursor = users_collection().find(
            {"_id": {"$nin": list(exclude_ids)}},
            {
                "_id": 1,
                "name": 1,
                "email": 1,
                "username": 1,
                "avatar_url": 1,
                "is_online": 1,
                "last_seen": 1,
                "status": 1
            }
        ).limit(limit * 2)  # Get more to account for filtering
        
        # Check if cursor is a coroutine (mock DB) or cursor (real MongoDB)
        if hasattr(cursor, '__await__') and not hasattr(cursor, '__aiter__'):
            cursor = await cursor
        
        contacts_list = []
        for user in await _collect_cursor(cursor, limit=limit * 2):
            # Create UserPublic object from user data
            user_public = UserPublic(
                id=user.get("_id"),
                name=user.get("name"),
                email=user.get("email"),
                username=user.get("username"),
                avatar_url=user.get("avatar_url"),
                is_online=user.get("is_online", False),
                last_seen=user.get("last_seen"),
                status=user.get("status")
            )
            
            user_data = user_public.model_dump()
            
            # Apply search filter if provided
            if q:
                q_lower = q.lower()
                search_fields = [
                    user_data.get("name", ""),
                    user_data.get("username", ""),
                    user_data.get("email", "")
                ]
                
                if any(q_lower in field.lower() for field in search_fields if field):
                    contacts_list.append(user_data)
            else:
                contacts_list.append(user_data)
        
        # Sort by online status first, then by name
        contacts_list.sort(key=lambda x: (0 if x["is_online"] else 1, x["name"].lower()))
        
        # Apply limit
        contacts_list = contacts_list[:limit]
        
        return {
            "contacts": contacts_list,
            "total_count": len(contacts_list),
            "query": q,
            "limit": limit,
            "group_id": group_id,
            "fallback_used": True
        }
    
    # Get contact details
    cursor = users_collection().find(
        {"_id": {"$in": available_contacts}},
        {
            "_id": 1,
            "name": 1,
            "email": 1,
            "username": 1,
            "avatar_url": 1,
            "is_online": 1,
            "last_seen": 1,
            "status": 1,
            "phone": 1  # Include phone for WhatsApp-like experience
        }
    )
    
    # Handle cursor (mock vs real DB)
    if hasattr(cursor, '__await__'):
        cursor = await cursor
    
    contacts_list = []
    for contact in await _collect_cursor(cursor, limit=limit):
        contact_data = {
            "id": contact.get("_id"),
            "name": contact.get("name", "Unknown"),
            "email": contact.get("email", ""),
            "username": contact.get("username", ""),
            "avatar_url": contact.get("avatar_url"),
            "phone": contact.get("phone", ""),
            "is_online": contact.get("is_online", False),
            "last_seen": contact.get("last_seen"),
            "status": contact.get("status", "available")
        }
        
        # Apply search filter if provided
        if q:
            q_lower = q.lower()
            search_fields = [
                contact_data["name"].lower(),
                contact_data["username"].lower() if contact_data["username"] else "",
                contact_data["email"].lower(),
                contact_data["phone"].lower() if contact_data["phone"] else ""
            ]
            
            if any(q_lower in field for field in search_fields if field):
                contacts_list.append(contact_data)
        else:
            contacts_list.append(contact_data)
    
    # Sort by online status first, then by name
    contacts_list.sort(key=lambda x: (0 if x["is_online"] else 1, x["name"].lower()))
    
    # Apply limit
    contacts_list = contacts_list[:limit]
    
    return {
        "contacts": contacts_list,
        "total_count": len(contacts_list),
        "query": q,
        "limit": limit,
        "group_id": group_id
    }


@router.post("/{group_id}/participants/add-multiple")
async def add_multiple_participants(
    group_id: str,
    payload: Any = Body(...),
    current_user: str = Depends(get_current_user)
):
    """Add multiple participants to group at once (WhatsApp-style)"""
    group = await _require_group(group_id, current_user)

    if isinstance(payload, dict):
        participant_ids = payload.get("participant_ids")
    else:
        participant_ids = payload

    if participant_ids is None:
        participant_ids = []
    
    # Check if current user is admin or if member add is allowed
    is_admin = _is_admin(group, current_user)
    allow_member_add = group.get("permissions", {}).get("allow_member_add", False)
    
    if not is_admin and not allow_member_add:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can add members (or member add permission required)"
        )
    
    if not participant_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No participant IDs provided"
    )
    
    # Validate and filter participant IDs
    valid_participants = []
    for pid in participant_ids:
        if pid and pid.strip() and pid != current_user:
            pid = pid.strip()
            if pid not in group.get("members", []) and pid not in valid_participants:
                valid_participants.append(pid)
    
    if not valid_participants:
        return {
            "success": True,
            "message": "No new participants to add",
            "added_count": 0,
            "participants": []
        }
    
    # Verify participants exist in database
    existing_users = []
    cursor = users_collection().find({"_id": {"$in": valid_participants}})
    
    if hasattr(cursor, '__await__'):
        cursor = await cursor
    
    async for user in cursor:
        existing_users.append(user["_id"])
    
    # Filter to only existing users
    final_participants = [pid for pid in valid_participants if pid in existing_users]
    
    if not final_participants:
        return {
            "success": True,
            "message": "No valid participants found",
            "added_count": 0,
            "participants": []
        }
    
    try:
        # Add participants to group
        update_result = await chats_collection().update_one(
            {"_id": group_id},
            {"$addToSet": {"members": {"$each": final_participants}}}
        )
        
        # Update cache
        current_members = group.get("members", []) + final_participants
        await GroupCacheService.set_group_members(group_id, current_members)
        
        # Invalidate group info cache
        try:
            await GroupCacheService.invalidate_group_cache(group_id)
        except AttributeError:
            pass  # Method doesn't exist, continue
        
        # Log activity for each added participant
        for pid in final_participants:
            await _log_activity(group_id, current_user, "member_added", {"user_id": pid})
        
        # Get details of added participants
        added_participants_details = []
        cursor = users_collection().find({"_id": {"$in": final_participants}})
        
        if hasattr(cursor, '__await__'):
            cursor = await cursor
        
        async for user in cursor:
            added_participants_details.append({
                "user_id": user["_id"],
                "name": user.get("name", "Unknown User"),
                "email": user.get("email", ""),
                "username": user.get("username", ""),
                "avatar_url": user.get("avatar_url"),
                "phone": user.get("phone", "")
            })
        
        return {
            "success": True,
            "message": f"Successfully added {len(final_participants)} participants",
            "added_count": len(final_participants),
            "participants": added_participants_details,
            "total_members": len(current_members)
        }
        
    except Exception as e:
        logger.error(f"Error adding multiple participants: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add participants"
        )


@router.post("/{group_id}/add-members")
async def add_members_alias(group_id: str, body: _AddMembersBody, current_user: str = Depends(get_current_user)):
    return await add_multiple_participants(group_id=group_id, payload={"participant_ids": body.participant_ids}, current_user=current_user)


@router.get("/{group_id}/info/add-participants")
async def get_add_participants_info(
    group_id: str,
    toggle_member_add: Optional[bool] = Query(None, alias="toggle_member_add"),
    current_user: str = Depends(get_current_user)
):
    """Get group info with add participants option (WhatsApp-style)"""
    group = await _require_group(group_id, current_user)
    
    is_admin = _is_admin(group, current_user)
    allow_member_add = group.get("permissions", {}).get("allow_member_add", False)
    can_add_members = is_admin or allow_member_add
    
    member_count = len(group.get("members", []))
    max_group_size = 256  # WhatsApp-like limit
    
    return {
        "group_id": group_id,
        "group_name": group.get("name", ""),
        "group_description": group.get("description", ""),
        "member_count": member_count,
        "max_group_size": max_group_size,
        "can_add_more": member_count < max_group_size,
        "can_add_members": can_add_members,
        "current_user_is_admin": is_admin,
        "permissions": {
            "allow_member_add": allow_member_add
        },
        "add_participants_button": {
            "visible": can_add_members and member_count < max_group_size,
            "text": f"+ Add Participants ({max_group_size - member_count} remaining)",
            "enabled": can_add_members
        }
    }
