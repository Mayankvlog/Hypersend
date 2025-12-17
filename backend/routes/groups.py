import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional, Literal, Any, Dict
from datetime import datetime
from bson import ObjectId
import asyncio

from auth.utils import get_current_user
from database import chats_collection, users_collection, messages_collection, get_db
from models import GroupCreate, GroupUpdate, GroupMembersUpdate, GroupMemberRoleUpdate, ChatPermissions


router = APIRouter(prefix="/groups", tags=["Groups"])


def _now() -> datetime:
    return datetime.utcnow()


async def _require_group(group_id: str, current_user: str) -> dict:
    group = await chats_collection().find_one({"_id": group_id, "type": "group"})
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    if current_user not in group.get("members", []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this group")
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
    if not payload.name or not payload.name.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group name is required")

    member_ids = list(dict.fromkeys([*(payload.member_ids or []), current_user]))
    if len(member_ids) < 2:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group must have at least 2 members")

    group_id = str(ObjectId())
    chat_doc = {
        "_id": group_id,
        "type": "group",
        "name": payload.name.strip(),
        "description": (payload.description or "").strip(),
        "avatar_url": (payload.avatar_url or "").strip() or None,
        "members": member_ids,
        "admins": [current_user],
        "created_by": current_user,
        "created_at": _now(),
        "muted_by": [],
    }

    await chats_collection().insert_one(chat_doc)
    await _log_activity(group_id, current_user, "group_created", {"name": chat_doc["name"]})

    # Activity for added members (excluding creator)
    for uid in member_ids:
        if uid != current_user:
            await _log_activity(group_id, current_user, "member_added", {"user_id": uid})

    return {"group_id": group_id, "group": chat_doc}


@router.get("")
async def list_groups(current_user: str = Depends(get_current_user)):
    """List groups for current user."""
    groups = []
    async for chat in chats_collection().find({"type": "group", "members": current_user}).sort("created_at", -1):
        # attach last message
        last_message = await messages_collection().find_one(
            {"chat_id": chat["_id"], "is_deleted": {"$ne": True}},
            sort=[("created_at", -1)],
        )
        chat["last_message"] = last_message
        groups.append(chat)
    return {"groups": groups}


@router.get("/{group_id}")
async def get_group(group_id: str, current_user: str = Depends(get_current_user)):
    """Get group details + basic member info."""
    group = await _require_group(group_id, current_user)
    member_ids: List[str] = group.get("members", [])
    admins: List[str] = group.get("admins", [])

    # Fetch member records (best-effort)
    members: List[Dict[str, Any]] = []

    async def fetch_member(uid: str) -> Optional[dict]:
        return await users_collection().find_one({"_id": uid})

    # Avoid slow sequential queries for big groups (basic parallelism with gather)
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
                "role": "admin" if uid in admins else "member",
            })

    group_out = dict(group)
    group_out["members_detail"] = members
    group_out["is_admin"] = _is_admin(group, current_user)
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
    group = await _require_group(group_id, current_user)
    if not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can add members")

    add_ids = [uid for uid in (payload.user_ids or []) if uid and uid not in group.get("members", [])]
    if not add_ids:
        return {"added": 0}

    await chats_collection().update_one({"_id": group_id}, {"$addToSet": {"members": {"$each": add_ids}}})
    for uid in add_ids:
        await _log_activity(group_id, current_user, "member_added", {"user_id": uid})

    return {"added": len(add_ids)}


@router.delete("/{group_id}/members/{member_id}")
async def remove_member(group_id: str, member_id: str, current_user: str = Depends(get_current_user)):
    group = await _require_group(group_id, current_user)
    if not _is_admin(group, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can remove members")
    if member_id == group.get("created_by"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot remove group creator")

    await chats_collection().update_one({"_id": group_id}, {"$pull": {"members": member_id, "admins": member_id}})
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
    # For now, we'll assume we store it in a 'restrictions' dict in the chat doc or separate collection
    # A cleaner way is to use the ChatMember model logic, but for now we'll patch the chat document
    # "restrictions": { "user_id": { permissions... } }
    
    restriction_data = permissions.model_dump()
    if until_date:
        restriction_data["until_date"] = until_date
        
    await chats_collection().update_one(
        {"_id": group_id},
        {"$set": {f"restrictions.{member_id}": restriction_data}}
    )
    
    await _log_activity(group_id, current_user, "member_restricted", {"user_id": member_id})
    return {"status": "restricted", "permissions": permissions}
