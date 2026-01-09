from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional, Dict
from datetime import datetime, timedelta, timezone

from auth.utils import get_current_user
from db_proxy import chats_collection, messages_collection
from models import MessageEditRequest, MessageReactionRequest


router = APIRouter(prefix="/messages", tags=["Messages"])

# OPTIONS handlers for CORS preflight requests
@router.options("/{message_id}")
@router.options("/{message_id}/versions")
@router.options("/{message_id}/reactions")
@router.options("/{message_id}/versions")
@router.options("/{message_id}/reactions")
@router.options("/{message_id}/pin")
@router.options("/{message_id}/unpin")
@router.options("/{message_id}/read")
@router.options("/search")
@router.options("/{message_id}/react")
@router.options("/{message_id}/pin")
async def messages_options():
    """Handle CORS preflight for messages endpoints"""
    from fastapi.responses import Response
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400"
        }
    )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def _get_message_or_404(message_id: str) -> dict:
    msg = await messages_collection().find_one({"_id": message_id})
    if not msg:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
    return msg


async def _get_chat_for_message_or_403(message: dict, current_user: str) -> dict:
    chat_id = message.get("chat_id")
    chat = await chats_collection().find_one({"_id": chat_id})
    if not chat or current_user not in chat.get("members", []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this message")
    return chat


def _is_group_admin(chat: dict, user_id: str) -> bool:
    return user_id in chat.get("admins", [])


@router.put("/{message_id}")
async def edit_message(
    message_id: str,
    payload: MessageEditRequest,
    current_user: str = Depends(get_current_user),
):
    """Edit a message (sender only, within 24 hours) + keep edit history."""
    msg = await _get_message_or_404(message_id)
    chat = await _get_chat_for_message_or_403(msg, current_user)

    if msg.get("is_deleted"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot edit a deleted message")

    if msg.get("sender_id") != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Can only edit your own messages")

    created_at: datetime = msg.get("created_at") or _utcnow()
    if _utcnow() - created_at > timedelta(hours=24):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot edit messages older than 24 hours")

    new_text = (payload.text or "").strip()
    if not new_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message text cannot be empty")

    history = msg.get("edit_history") or []
    history.append({
        "text": msg.get("text"),
        "edited_at": _utcnow(),
        "edited_by": current_user,
    })

    await messages_collection().update_one(
        {"_id": message_id},
        {"$set": {
            "text": new_text,
            "is_edited": True,
            "edited_at": _utcnow(),
            "edit_history": history,
        }},
    )

    return {"status": "edited", "message_id": message_id}


@router.delete("/{message_id}")
async def delete_message(
    message_id: str,
    hard_delete: bool = False,
    current_user: str = Depends(get_current_user),
):
    """Delete a message. Default is soft-delete; sender only."""
    msg = await _get_message_or_404(message_id)
    await _get_chat_for_message_or_403(msg, current_user)

    if msg.get("sender_id") != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Can only delete your own messages")

    if hard_delete:
        await messages_collection().delete_one({"_id": message_id})
        return {"status": "deleted", "hard_delete": True}

    if msg.get("is_deleted"):
        return {"status": "deleted", "hard_delete": False}

    await messages_collection().update_one(
        {"_id": message_id},
        {"$set": {
            "is_deleted": True,
            "deleted_at": _utcnow(),
            "deleted_by": current_user,
            "text": None,
            "file_id": None,
        }},
    )
    return {"status": "deleted", "hard_delete": False}


@router.get("/{message_id}/versions")
async def get_message_versions(message_id: str, current_user: str = Depends(get_current_user)):
    msg = await _get_message_or_404(message_id)
    await _get_chat_for_message_or_403(msg, current_user)
    return {"message_id": message_id, "versions": msg.get("edit_history") or []}


@router.post("/{message_id}/reactions")
async def toggle_reaction(
    message_id: str,
    payload: MessageReactionRequest,
    current_user: str = Depends(get_current_user),
):
    """Toggle an emoji reaction for current user."""
    emoji = (payload.emoji or "").strip()
    if not emoji:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Emoji required")

    msg = await _get_message_or_404(message_id)
    await _get_chat_for_message_or_403(msg, current_user)

    # Use atomic operations to prevent race condition with concurrent reactions
    # First, check if user already has this reaction
    reactions: Dict[str, list] = msg.get("reactions") or {}
    users = reactions.get(emoji) or []
    
    if current_user in users:
        # Remove the reaction atomically
        await messages_collection().update_one(
            {"_id": message_id},
            {
                "$pull": {f"reactions.{emoji}": current_user},
                "$set": {"updated_at": _utcnow()}
            }
        )
        # Clean up empty emoji entries
        await messages_collection().update_one(
            {"_id": message_id, f"reactions.{emoji}": {"$size": 0}},
            {"$unset": {f"reactions.{emoji}": ""}}
        )
        action = "removed"
    else:
        # Add the reaction atomically
        await messages_collection().update_one(
            {"_id": message_id},
            {
                "$addToSet": {f"reactions.{emoji}": current_user},
                "$set": {"updated_at": _utcnow()}
            }
        )
        action = "added"

    # Fetch updated message for response
    updated_msg = await messages_collection().find_one({"_id": message_id})
    return {"status": "success", "action": action, "message_id": message_id, "reactions": updated_msg.get("reactions") or {}}


@router.get("/{message_id}/reactions")
async def get_reactions(message_id: str, current_user: str = Depends(get_current_user)):
    msg = await _get_message_or_404(message_id)
    await _get_chat_for_message_or_403(msg, current_user)
    return {"message_id": message_id, "reactions": msg.get("reactions") or {}}


@router.post("/{message_id}/pin")
async def pin_message(message_id: str, current_user: str = Depends(get_current_user)):
    """Pin a message. For group chats, only admins can pin."""
    msg = await _get_message_or_404(message_id)
    chat = await _get_chat_for_message_or_403(msg, current_user)

    if chat.get("type") == "group" and not _is_group_admin(chat, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can pin messages")

    await messages_collection().update_one(
        {"_id": message_id},
        {"$set": {"is_pinned": True, "pinned_at": _utcnow(), "pinned_by": current_user}},
    )
    return {"status": "pinned", "message_id": message_id}


@router.post("/{message_id}/unpin")
async def unpin_message(message_id: str, current_user: str = Depends(get_current_user)):
    msg = await _get_message_or_404(message_id)
    chat = await _get_chat_for_message_or_403(msg, current_user)

    if chat.get("type") == "group" and not _is_group_admin(chat, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can unpin messages")

    await messages_collection().update_one(
        {"_id": message_id},
        {"$set": {"is_pinned": False}, "$unset": {"pinned_at": "", "pinned_by": ""}},
    )
    return {"status": "unpinned", "message_id": message_id}


@router.post("/{message_id}/read")
async def mark_read(message_id: str, current_user: str = Depends(get_current_user)):
    """Mark message read for current user (read receipts)."""
    msg = await _get_message_or_404(message_id)
    await _get_chat_for_message_or_403(msg, current_user)

    # Use atomic operation to prevent race condition with concurrent read receipts
    # Only add read receipt if user hasn't already marked it as read
    result = await messages_collection().update_one(
        {
            "_id": message_id,
            "read_by": {"$not": {"$elemMatch": {"user_id": current_user}}}  # Only if not already there
        },
        {
            "$push": {"read_by": {"user_id": current_user, "read_at": _utcnow()}},
            "$set": {"updated_at": _utcnow()}
        }
    )
    
    # If user already marked as read, just return success
    if result.matched_count == 0:
        return {"status": "read", "message_id": message_id}
    
    return {"status": "read", "message_id": message_id}



@router.get("/search")
async def search_messages(
    q: str, 
    chat_id: Optional[str] = None, 
    limit: int = 50,
    has_media: bool = False,
    has_link: bool = False,
    current_user: str = Depends(get_current_user)
):
    """
    Search messages globally or within a chat.
    Filters: text query (q), has_media, has_link.
    """
    if not q and not has_media and not has_link:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Search query or filter required")
    
    # CRITICAL SECURITY: Enhanced search query validation
    if q:
        # Limit search query length to prevent DoS
        if len(q) > 100:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Search query too long (max 100 characters)")
        
        # CRITICAL SECURITY: Remove dangerous characters that could cause injection
        import re
        # Remove characters that could break MongoDB queries or cause injection
        dangerous_chars = r'[$\\]'
        cleaned_query = re.sub(dangerous_chars, '', q)
        if cleaned_query != q:
            _log("warning", f"Potentially dangerous characters in search query", {
                "user_id": current_user,
                "operation": "message_search",
                "query_length": len(q)
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid search query format"
            )
        
        # Prevent regex injection by escaping special characters
        q_escaped = re.escape(q)
    
    # Base filter
    filter_doc = {"is_deleted": {"$ne": True}}
    
    # Text search
    if q:
        filter_doc["text"] = {"$regex": q_escaped, "$options": "i"}
        
    # Media/Link filters
    if has_media:
        filter_doc["file_id"] = {"$ne": None}
    
    # To filter by links we would need regex on text, but for now let's assume client handles or simple regex
    if has_link:
        # Simple regex for http/https
        if "text" in filter_doc:
             # Merge regex? simpler to just add another condition using $and if needed, but regex can be combined
             pass 
        else:
             filter_doc["text"] = {"$regex": r"https?://", "$options": "i"}

    # Scope
    if chat_id:
        # Verify access
        chat = await chats_collection().find_one({"_id": chat_id, "members": current_user})
        if not chat:
            raise HTTPException(status_code=403, detail="Chat not found or access denied")
        filter_doc["chat_id"] = chat_id
    else:
        # Global search: get all chat IDs user is member of
        user_chats = await chats_collection().find({"members": current_user}, {"_id": 1}).to_list(1000)
        user_chat_ids = [c["_id"] for c in user_chats]
        filter_doc["chat_id"] = {"$in": user_chat_ids}
        
    messages = await messages_collection().find(filter_doc).sort("created_at", -1).limit(limit).to_list(limit)
    return {"messages": messages, "count": len(messages)}
