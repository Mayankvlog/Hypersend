from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional, Dict
from datetime import datetime, timedelta, timezone
import uuid
import logging
from pydantic import BaseModel, Field

from auth.utils import get_current_user

try:
    from ..db_proxy import chats_collection, messages_collection
    from ..models import MessageEditRequest, MessageReactionRequest
except ImportError:
    from db_proxy import chats_collection, messages_collection
    from models import MessageEditRequest, MessageReactionRequest

logger = logging.getLogger(__name__)


class MessageSendRequest(BaseModel):
    chat_id: str
    message: str = Field(..., min_length=1, max_length=10000)
    message_type: str = "text"


router = APIRouter(prefix="/messages", tags=["Messages"])

# OPTIONS handlers for CORS preflight requests
@router.options("/send")
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


@router.post("/send")
async def send_message(
    request: MessageSendRequest,
    current_user: str = Depends(get_current_user)
):
    """Send a message to a chat - WhatsApp-style ephemeral storage"""
    # Verify chat exists and user has access
    chat = await chats_collection().find_one({"_id": request.chat_id})
    if not chat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat not found")
    
    # Check if user is member of the chat
    participants = chat.get("participants", chat.get("members", chat.get("member_ids", [])))
    logger.debug(f"Checking chat membership for user authorization")
    
    if current_user not in participants and str(current_user) not in [str(p) for p in participants]:
        logger.debug(f"User authorization check failed")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this chat")
    
    logger.debug(f"User authorized to send message")
    
    # Generate message ID
    message_id = str(uuid.uuid4())
    
    # WhatsApp-style: Store ONLY metadata in Redis with TTL
    # Message content lives in RAM only, delivered immediately, then deleted
    message_metadata = {
        "message_id": message_id,
        "chat_id": request.chat_id,
        "sender_id": current_user,
        "message_type": request.message_type,
        "created_at": _utcnow().isoformat(),
        "delivery_status": "pending",  # pending -> delivered -> acknowledged -> deleted
        "receiver_ids": [p for p in participants if p != current_user],
        "ttl_seconds": 3600  # 1 hour TTL for message metadata
    }
    
    # Store in Redis with TTL (NOT MongoDB)
    try:
        from ..redis_cache import redis_client
        await redis_client.setex(
            f"message:{message_id}",
            message_metadata["ttl_seconds"],
            json.dumps(message_metadata)
        )
        
        # Add to chat's pending messages list
        await redis_client.lpush(
            f"chat_messages:{request.chat_id}",
            message_id
        )
        await redis_client.expire(
            f"chat_messages:{request.chat_id}",
            message_metadata["ttl_seconds"]
        )
        
    except Exception as e:
        logger.error(f"Failed to store message in Redis: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Message storage temporarily unavailable"
        )
    
    # Update chat's last message metadata only (NOT the message content)
    await chats_collection().update_one(
        {"_id": request.chat_id},
        {"$set": {
            "last_message_id": message_id,
            "last_activity": _utcnow(),
            "last_message_type": request.message_type
        }}
    )
    
    return {
        "status": "sent",
        "message_id": message_id,
        "chat_id": request.chat_id,
        "message_type": request.message_type,
        "created_at": message_metadata["created_at"],
        "delivery_status": message_metadata["delivery_status"],
        "ttl_seconds": message_metadata["ttl_seconds"]
    }


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def _get_message_or_404(message_id: str) -> dict:
    """Get message from Redis (WhatsApp-style ephemeral storage)"""
    try:
        from ..redis_cache import redis_client
        message_data = await redis_client.get(f"message:{message_id}")
        if not message_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found or expired")
        return json.loads(message_data)
    except Exception as e:
        logger.error(f"Failed to get message from Redis: {e}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found or expired")


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
    """Edit a message (sender only, within 15 minutes) - WhatsApp-style limited edit window."""
    msg = await _get_message_or_404(message_id)
    chat = await _get_chat_for_message_or_403(msg, current_user)

    delivery_status = msg.get("delivery_status", "pending")
    if delivery_status in ["delivered", "acknowledged"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot edit message after delivery")

    if msg.get("sender_id") != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Can only edit your own messages")

    created_at_str = msg.get("created_at")
    if created_at_str:
        created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
        if _utcnow() - created_at > timedelta(minutes=15):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot edit messages older than 15 minutes")

    new_text = (payload.text or "").strip()
    if not new_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message text cannot be empty")

    # Update message in Redis with edit flag
    try:
        from ..redis_cache import redis_client
        msg["text"] = new_text
        msg["is_edited"] = True
        msg["edited_at"] = _utcnow().isoformat()
        msg["edited_by"] = current_user
        
        # Update TTL to remaining time or minimum 5 minutes
        ttl = int(msg.get("ttl_seconds", 3600))
        elapsed = (_utcnow() - created_at).total_seconds() if created_at else 0
        remaining_ttl = max(300, int(ttl - elapsed))  # Minimum 5 minutes
        
        await redis_client.setex(
            f"message:{message_id}",
            remaining_ttl,
            json.dumps(msg)
        )
    except Exception as e:
        logger.error(f"Failed to update message in Redis: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Message update failed")

    return {"status": "edited", "message_id": message_id}


@router.delete("/{message_id}")
async def delete_message(
    message_id: str,
    hard_delete: bool = False,
    current_user: str = Depends(get_current_user),
):
    """Delete a message - WhatsApp-style immediate deletion from Redis."""
    msg = await _get_message_or_404(message_id)
    await _get_chat_for_message_or_403(msg, current_user)

    if msg.get("sender_id") != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Can only delete your own messages")

    # WhatsApp-style: Delete immediately from Redis (no soft delete)
    try:
        from ..redis_cache import redis_client
        
        # Remove message from Redis
        await redis_client.delete(f"message:{message_id}")
        
        # Remove from chat's message list
        await redis_client.lrem(f"chat_messages:{msg['chat_id']}", 0, message_id)
        
    except Exception as e:
        logger.error(f"Failed to delete message from Redis: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Message deletion failed")

    return {"status": "deleted", "hard_delete": True}


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
    """Mark message read for current user - WhatsApp-style delivery tracking."""
    msg = await _get_message_or_404(message_id)
    await _get_chat_for_message_or_403(msg, current_user)

    # Update delivery status in Redis
    try:
        from ..redis_cache import redis_client
        
        # Add read receipt to message
        msg["read_by"] = msg.get("read_by", [])
        
        # Check if already read by this user
        already_read = any(read.get("user_id") == current_user for read in msg["read_by"])
        if not already_read:
            msg["read_by"].append({
                "user_id": current_user,
                "read_at": _utcnow().isoformat()
            })
            
            # Update delivery status based on receivers
            receiver_ids = msg.get("receiver_ids", [])
            if len(msg["read_by"]) >= len(receiver_ids):
                msg["delivery_status"] = "acknowledged"
            else:
                msg["delivery_status"] = "delivered"
            
            # Update message in Redis with remaining TTL
            ttl = int(msg.get("ttl_seconds", 3600))
            await redis_client.setex(
                f"message:{message_id}",
                ttl,
                json.dumps(msg)
            )
    except Exception as e:
        logger.error(f"Failed to update message read status in Redis: {e}")
        # Continue without failing - read receipt is non-critical
    
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
    Search messages in Redis - WhatsApp-style limited search.
    Only searches recent messages due to ephemeral storage.
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
        # Remove characters that could break Redis queries or cause injection
        dangerous_chars = r'[$\]'
        cleaned_query = re.sub(dangerous_chars, '', q)
        if cleaned_query != q:
            logger.warning(f"Potentially dangerous characters in search query", extra={
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
    
    # WhatsApp-style: Search only in Redis (no MongoDB persistence)
    try:
        from ..redis_cache import redis_client
        
        # Get user's accessible chats
        user_chats = await chats_collection().find({"members": current_user}, {"_id": 1}).to_list(1000)
        user_chat_ids = [c["_id"] for c in user_chats]
        
        # Search in Redis for each chat
        all_messages = []
        search_chats = [chat_id] if chat_id else user_chat_ids
        
        for chat_id_to_search in search_chats:
            # Get message IDs from chat's message list
            message_ids = await redis_client.lrange(f"chat_messages:{chat_id_to_search}", 0, -1)
            
            for message_id in message_ids:
                # Get message data from Redis
                message_data = await redis_client.get(f"message:{message_id.decode('utf-8')}")
                if message_data:
                    msg = json.loads(message_data)
                    
                    # Apply filters
                    if q and msg.get("text") and q_escaped.lower() in msg["text"].lower():
                        all_messages.append(msg)
                    elif has_media and msg.get("file_id"):
                        all_messages.append(msg)
                    elif has_link and msg.get("text") and "http" in msg["text"]:
                        all_messages.append(msg)
        
        # Sort by created_at and limit
        all_messages.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        all_messages = all_messages[:limit]
        
        return {"messages": all_messages, "count": len(all_messages)}
        
    except Exception as e:
        logger.error(f"Failed to search messages in Redis: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Message search temporarily unavailable"
        )
