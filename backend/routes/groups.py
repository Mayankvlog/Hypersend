from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional, Any, Dict
from datetime import datetime, timezone
from bson import ObjectId
import asyncio
import json

from auth.utils import get_current_user
from db_proxy import chats_collection, users_collection, messages_collection, get_db
from models import GroupCreate, GroupUpdate, GroupMembersUpdate, GroupMemberRoleUpdate, ChatPermissions, UserPublic
from redis_cache import GroupCacheService, UserCacheService, SearchCacheService


router = APIRouter(prefix="/groups", tags=["Groups"])

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
    from config import settings
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


async def _require_group(group_id: str, current_user: str) -> dict:
    group = await chats_collection().find_one({"_id": group_id, "type": "group", "members": {"$in": [current_user]}})
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return group


def _is_admin(group: dict, user_id: str) -> bool:
    admins = group.get("admins", [])
    return user_id in admins


async def _log_activity(group_id: str, actor_id: str, event: str, meta: Optional[dict] = None) -> None:
    db = get_db()
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

    group_id = str(ObjectId())
    chat_doc = {
        "_id": group_id,
        "type": "group",
        "name": payload.name.strip(),
        "description": (payload.description or "").strip(),
        "avatar_url": (payload.avatar_url or "").strip() or None,
        "members": member_ids,  # Ensure all members including current_user are included
        "admins": [current_user],
        "created_by": current_user,
        "created_at": _now(),
        "muted_by": [],
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
    cursor = chats_collection().find({"type": "group", "members": {"$in": [current_user]}}).sort("created_at", -1)
    
    # Handle both coroutine (mock DB) and cursor (real MongoDB)
    if hasattr(cursor, '__await__'):
        cursor = await cursor
    
    async for chat in cursor:
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
    cached_suggestions = await SearchCacheService.get_user_search(cache_key)
    
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
            if hasattr(cursor, '__await__'):
                cursor = await cursor
            
            async for contact in cursor:
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
                        q_lower in contact_data["email"].lower()):
                        suggestions.append(contact_data)
                else:
                    suggestions.append(contact_data)
            
            # Limit results
            suggestions = suggestions[:limit]
        
        # Cache the results (even if empty)
        await SearchCacheService.set_user_search(cache_key, suggestions)
    
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
        await chats_collection().update_one({"_id": group_id}, {"$set": update})
        await _log_activity(group_id, current_user, "group_updated", {"fields": list(update.keys())})

    group_new = await chats_collection().find_one({"_id": group_id})
    return {"group": group_new}


@router.post("/{group_id}/members")
async def add_members(group_id: str, payload: GroupMembersUpdate, current_user: str = Depends(get_current_user)):
    """Add members to a group - Only admins can add members"""
    
    print(f"[ADD_MEMBERS] ===== ADD MEMBERS REQUEST START =====")
    print(f"[ADD_MEMBERS] Group ID: {group_id}")
    print(f"[ADD_MEMBERS] Current User: {current_user}")
    print(f"[ADD_MEMBERS] Payload: {payload}")
    print(f"[ADD_MEMBERS] Payload Type: {type(payload)}")
    
    # Extract user_ids from payload with better error handling and support for different field names
    try:
        # Try multiple possible field names that frontend might send
        user_ids = None
        if hasattr(payload, 'user_ids'):
            user_ids = payload.user_ids
        elif hasattr(payload, 'user_ids'):
            user_ids = payload.user_ids
        elif hasattr(payload, 'member_ids'):
            user_ids = payload.member_ids
        elif hasattr(payload, 'member_ids'):
            user_ids = payload.member_ids
        elif hasattr(payload, 'user_ids'):
            user_ids = payload.user_ids
        else:
            print(f"[ADD_MEMBERS] Warning: No user_ids field found in payload. Available fields: {list(payload.keys())}")
            user_ids = []
        
        # Convert string to list if needed
        if user_ids and isinstance(user_ids, str):
            # Handle comma-separated user IDs: "user1@example.com,user2@example.com"
            user_ids = [uid.strip() for uid in user_ids.split(',') if uid.strip()]
        elif user_ids and not isinstance(user_ids, list):
            # Convert single string to list
            user_ids = [user_ids]
        
        print(f"[ADD_MEMBERS] Extracted user_ids: {user_ids}")
    except AttributeError as e:
        print(f"[ADD_MEMBERS] Error accessing user_ids field: {e}")
        user_ids = []
    except Exception as e:
        print(f"[ADD_MEMBERS] Unexpected error with payload: {e}")
        user_ids = []
    
    print(f"[ADD_MEMBERS] Final user_ids: {user_ids}")
    print(f"[ADD_MEMBERS] User IDs Type: {type(user_ids)}")
    
    # Validate group exists and user is member
    try:
        group = await _require_group(group_id, current_user)
        print(f"[ADD_MEMBERS] Group found: {group.get('_id')}")
        print(f"[ADD_MEMBERS] Group members: {group.get('members', [])}")
        print(f"[ADD_MEMBERS] Group admins: {group.get('admins', [])}")
    except HTTPException:
        raise
    except Exception as e:
        print(f"[ADD_MEMBERS] Error fetching group: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to fetch group")
    
    # Check admin permissions with detailed logging
    if not _is_admin(group, current_user):
        print(f"[ADD_MEMBERS] User {current_user} is NOT admin!")
        print(f"[ADD_MEMBERS] Admins list: {group.get('admins', [])}")
        print(f"[ADD_MEMBERS] User ID type: {type(current_user)}")
        print(f"[ADD_MEMBERS] Admin IDs types: {[type(admin) for admin in group.get('admins', [])]}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Only admins can add members"
        )
    
    print(f"[ADD_MEMBERS] User {current_user} IS admin - proceeding...")

    # Validate and filter user_ids - improved logic
    if not user_ids:
        print(f"[ADD_MEMBERS] No user_ids provided in payload")
        return {"added": 0, "message": "No user IDs provided"}
    
    # Convert to list if string and handle different formats
    if isinstance(user_ids, str):
        # Handle comma-separated user IDs: "user1@example.com,user2@example.com"
        if ',' in user_ids:
            user_ids = [uid.strip() for uid in user_ids.split(',') if uid.strip()]
        else:
            # Handle single user ID string
            user_ids = [user_ids.strip()] if user_ids.strip() else []
    elif not isinstance(user_ids, list):
        print(f"[ADD_MEMBERS] Invalid user_ids format: {type(user_ids)}. Expected list or string.")
        return {"added": 0, "message": "Invalid user_ids format"}
    
    # Remove empty strings and whitespace
    filtered_ids = []
    for uid in user_ids:
        if uid and uid.strip() and uid.strip() != current_user:
            if uid not in filtered_ids:  # Remove duplicates
                filtered_ids.append(uid.strip())
    
    print(f"[ADD_MEMBERS] Original user_ids: {user_ids}")
    print(f"[ADD_MEMBERS] Filtered user_ids: {filtered_ids}")
    
    if not filtered_ids:
        print(f"[ADD_MEMBERS] No valid user_ids after filtering")
        return {"added": 0, "message": "No valid user IDs to add"}
    
    print(f"[ADD_MEMBERS] Processing {len(filtered_ids)} valid user_ids: {filtered_ids}")

    try:
        # Get current members from cache or database
        current_members = await GroupCacheService.get_group_members(group_id)
        if not current_members:
            current_members = group.get("members", [])
            await GroupCacheService.set_group_members(group_id, current_members)
            print(f"[ADD_MEMBERS] Set initial group members: {current_members}")

        print(f"[ADD_MEMBERS] Current group members: {current_members}")

        # Filter out already added members
        new_members = [uid for uid in filtered_ids if uid not in current_members]
        if not new_members:
            print(f"[ADD_MEMBERS] No new members to add. All users already in group.")
            return {"added": 0, "message": "All users are already group members"}

        print(f"[ADD_MEMBERS] New members to add: {new_members}")

        # Atomic operation: add members not already present
        update_result = await chats_collection().update_one(
            {"_id": group_id}, 
            {"$addToSet": {"members": {"$each": new_members}}}
        )
        print(f"[ADD_MEMBERS] Database update result: {update_result}")

        # Update cache with new members
        updated_members = current_members + new_members
        await GroupCacheService.set_group_members(group_id, updated_members)
        print(f"[ADD_MEMBERS] Updated group members: {updated_members}")
        
        # Invalidate group info cache if method exists
        try:
            await GroupCacheService.invalidate_group_info(group_id)
        except AttributeError:
            # Method doesn't exist, continue without cache invalidation
            print(f"[ADD_MEMBERS] Group info cache invalidation method not found, continuing...")
        
        # Log activity for each new member
        for uid in new_members:
            await _log_activity(group_id, current_user, "member_added", {"user_id": uid})

        print(f"[ADD_MEMBERS] Successfully added {len(new_members)} members to group {group_id}")
        print(f"[ADD_MEMBERS] ===== ADD MEMBERS REQUEST END =====")
        
        # Return updated member count for frontend
        return {
            "added": len(new_members),
            "member_count": len(updated_members),
            "members": updated_members,
            "message": f"Successfully added {len(new_members)} members"
        }
        
    except Exception as e:
        print(f"[ADD_MEMBERS] Database error: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add members to group"
        )


@router.delete("/{group_id}/members/{member_id}")
async def remove_member(group_id: str, member_id: str, current_user: str = Depends(get_current_user)):
    group = await _require_group(group_id, current_user)
    if not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can remove members")
    if member_id == group.get("created_by"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot remove group creator")

    await chats_collection().update_one({"_id": group_id}, {"$pull": {"members": member_id, "admins": member_id}})
    
    # Update cache
    await GroupCacheService.remove_member_from_cache(group_id, member_id)
    
    # Invalidate group info cache
    await GroupCacheService.invalidate_group_cache(group_id)
    
    await _log_activity(group_id, current_user, "member_removed", {"user_id": member_id})
    return {"removed": member_id}


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
        await chats_collection().update_one({"_id": group_id}, {"$addToSet": {"admins": member_id}})
        await _log_activity(group_id, current_user, "member_promoted", {"user_id": member_id})
    else:
        # Prevent removing the last admin
        admins = group.get("admins", [])
        if member_id in admins and len(admins) <= 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group must have at least 1 admin")
        await chats_collection().update_one({"_id": group_id}, {"$pull": {"admins": member_id}})
        await _log_activity(group_id, current_user, "member_demoted", {"user_id": member_id})

    new_group = await chats_collection().find_one({"_id": group_id})
    return {"group": new_group}


@router.post("/{group_id}/leave")
async def leave_group(group_id: str, current_user: str = Depends(get_current_user)):
    group = await _require_group(group_id, current_user)
    if current_user == group.get("created_by"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Creator must delete the group or transfer ownership")

    # If admin leaving, ensure at least 1 admin remains
    admins = group.get("admins", [])
    if current_user in admins and len(admins) <= 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Assign another admin before leaving")

    await chats_collection().update_one({"_id": group_id}, {"$pull": {"members": current_user, "admins": current_user}})
    await _log_activity(group_id, current_user, "member_left", {"user_id": current_user})
    return {"status": "left"}


@router.delete("/{group_id}")
async def delete_group(group_id: str, current_user: str = Depends(get_current_user)):
    group = await _require_group(group_id, current_user)
    if current_user != group.get("created_by") and not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can delete group")

    await chats_collection().delete_one({"_id": group_id})
    await messages_collection().delete_many({"chat_id": group_id})
    await _log_activity(group_id, current_user, "group_deleted", {})
    return {"status": "deleted"}


@router.post("/{group_id}/mute")
async def mute_group(group_id: str, mute: bool = True, current_user: str = Depends(get_current_user)):
    group = await _require_group(group_id, current_user)
    if mute:
        await chats_collection().update_one({"_id": group_id}, {"$addToSet": {"muted_by": current_user}})
        await _log_activity(group_id, current_user, "notifications_muted", {})
    else:
        await chats_collection().update_one({"_id": group_id}, {"$pull": {"muted_by": current_user}})
        await _log_activity(group_id, current_user, "notifications_unmuted", {})
    new_group = await chats_collection().find_one({"_id": group_id})
    return {"group": new_group}


@router.get("/{group_id}/activity")
async def get_activity(group_id: str, limit: int = 50, current_user: str = Depends(get_current_user)):
    await _require_group(group_id, current_user)
    db = get_db()
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
        
    await chats_collection().update_one(
        {"_id": group_id},
        {"$set": {"permissions": permissions.model_dump()}}
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
