from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional, Dict, List
from datetime import datetime, timedelta, timezone
import uuid
import logging
import json
from pydantic import BaseModel, Field

from auth.utils import get_current_user

try:
    from ..db_proxy import chats_collection, messages_collection
    from ..models import MessageEditRequest, MessageReactionRequest
    from ..redis_cache import cache
except ImportError:
    from db_proxy import chats_collection, messages_collection
    from models import MessageEditRequest, MessageReactionRequest
    from redis_cache import cache

logger = logging.getLogger(__name__)


# WhatsApp-style message state constants
class MessageState:
    PENDING = "pending"           # Message created, not yet sent
    SENT = "sent"                # Message sent to server
    SERVER_ACK = "server_ack"     # Server acknowledges receipt
    DELIVERED = "delivered"       # Delivered to at least one device
    READ = "read"                # Read by recipient
    FAILED = "failed"            # Delivery failed


class WhatsAppDeliveryService:
    """
    WhatsApp-style delivery receipts and message state tracking.
    
    WHATSAPP DELIVERY BEHAVIOR:
    1. ✓ Single gray: Message sent to server
    2. ✓✓ Double gray: Delivered to recipient's device
    3. ✓✓✓ Blue: Read by recipient
    4. Per-device tracking for multi-device
    5. Strict sequence number ordering
    """
    
    @staticmethod
    async def get_next_sequence_number(chat_id: str) -> int:
        """Get next sequence number for chat (WhatsApp ordering)"""
        seq_key = f"chat_sequence:{chat_id}"
        current_seq = await cache.get(seq_key) or 0
        next_seq = int(current_seq) + 1
        await cache.set(seq_key, next_seq, expire_seconds=7*24*60*60)  # 7 days TTL
        return next_seq
    
    @staticmethod
    async def create_message_with_sequence(
        chat_id: str,
        sender_id: str,
        sender_device_id: str,
        message_content: str,
        message_type: str = "text"
    ) -> Dict[str, Any]:
        """Create message with sequence number and initial state"""
        sequence_number = await WhatsAppDeliveryService.get_next_sequence_number(chat_id)
        message_id = f"msg_{chat_id}_{sequence_number}_{uuid.uuid4().hex[:8]}"
        
        message_data = {
            "message_id": message_id,
            "chat_id": chat_id,
            "sender_id": sender_id,
            "sender_device_id": sender_device_id,
            "content": message_content,
            "message_type": message_type,
            "sequence_number": sequence_number,
            "state": MessageState.SENT,
            "created_at": datetime.utcnow().isoformat(),
            "delivery_receipts": {},  # Per-device tracking
            "read_receipts": {}       # Per-device tracking
        }
        
        # Store in Redis for real-time tracking
        message_key = f"message:{message_id}"
        await cache.set(message_key, message_data, expire_seconds=24*60*60)  # 24h TTL
        
        return message_data
    
    @staticmethod
    async def track_delivery(
        message_id: str,
        recipient_device_id: str,
        delivery_type: str,  # "delivered", "read"
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Track per-device delivery/read receipt"""
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        message_key = f"message:{message_id}"
        message_data = await cache.get(message_key)
        
        if not message_data:
            raise HTTPException(
                status_code=404,
                detail="Message not found or expired"
            )
        
        # Update delivery receipts
        if delivery_type == "delivered":
            message_data["delivery_receipts"][recipient_device_id] = timestamp.isoformat()
            # Update state to delivered if at least one device received it
            if message_data["state"] != MessageState.READ:
                message_data["state"] = MessageState.DELIVERED
                
        elif delivery_type == "read":
            message_data["read_receipts"][recipient_device_id] = timestamp.isoformat()
            # Update state to read if any device read it
            message_data["state"] = MessageState.READ
        
        # Save updated message data
        await cache.set(message_key, message_data, expire_seconds=24*60*60)
        
        # Publish real-time update
        await cache.publish(f"message_updates:{message_data['chat_id']}", {
            "message_id": message_id,
            "state": message_data["state"],
            "delivery_type": delivery_type,
            "device_id": recipient_device_id,
            "timestamp": timestamp.isoformat()
        })
        
        return {
            "message_id": message_id,
            "state": message_data["state"],
            "delivery_type": delivery_type,
            "timestamp": timestamp.isoformat()
        }
    
    @staticmethod
    async def get_message_state(message_id: str) -> Optional[Dict[str, Any]]:
        """Get current message state and delivery info"""
        message_key = f"message:{message_id}"
        return await cache.get(message_key)
    
    @staticmethod
    async def get_chat_delivery_status(chat_id: str, user_id: str) -> List[Dict[str, Any]]:
        """Get delivery status for all messages in chat for user"""
        # Get all message keys for this chat
        pattern = f"message:*"
        all_messages = []
        
        # In production, this would use Redis SCAN for efficiency
        # For now, we'll simulate getting chat messages
        chat_messages_key = f"chat_messages:{chat_id}"
        message_ids = await cache.get(chat_messages_key) or []
        
        for message_id in message_ids:
            message_data = await WhatsAppDeliveryService.get_message_state(message_id)
            if message_data:
                all_messages.append(message_data)
        
        # Sort by sequence number
        all_messages.sort(key=lambda x: x.get("sequence_number", 0))
        
        return all_messages
    
    @staticmethod
    async def deduplicate_message(message_id: str, sender_device_id: str) -> bool:
        """
        Check for duplicate messages (WhatsApp idempotency).
        Returns True if message is duplicate, False if new.
        """
        dedup_key = f"dedup:{message_id}:{sender_device_id}"
        exists = await cache.get(dedup_key)
        
        if exists:
            return True  # Duplicate
        
        # Mark as seen for 24 hours
        await cache.set(dedup_key, True, expire_seconds=24*60*60)
        return False


class MessageSendRequest(BaseModel):
    chat_id: str
    message: str = Field(..., min_length=1, max_length=10000)
    message_type: str = "text"
    device_id: Optional[str] = None  # Sending device ID


class DeliveryReceipt(BaseModel):
    message_id: str
    chat_id: str
    recipient_id: str
    device_id: str
    status: str  # delivered, read
    timestamp: datetime


class MessageStateUpdate(BaseModel):
    message_id: str
    chat_id: str
    sender_id: str
    state: str
    device_states: Dict[str, str]  # device_id -> state
    sequence_number: int
    created_at: datetime


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
    """Send a message - WhatsApp-style state machine with device tracking"""
    # Verify chat exists and user has access
    chat = await chats_collection().find_one({"_id": request.chat_id})
    if not chat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat not found")
    
    # Check if user is member of the chat
    participants = chat.get("participants", chat.get("members", chat.get("member_ids", [])))
    if current_user not in participants and str(current_user) not in [str(p) for p in participants]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this chat")
    
    # Generate WhatsApp-style message ID (UUIDv7 + sender device id)
    import uuid
    message_id = str(uuid.uuid7())
    sender_device_id = request.device_id or "primary"
    
    # Get recipient devices for fanout
    from ..redis_cache import redis_client, MessageQueueService
    recipient_devices = []
    for participant in participants:
        if participant != current_user:
            # Get all active devices for this participant
            device_key = f"user_devices:{participant}"
            devices = await redis_client.smembers(device_key)
            recipient_devices.extend(devices or ["default"])
    
    # Create message data for WhatsApp-style fanout
    message_data = {
        "id": message_id,
        "chat_id": request.chat_id,
        "sender_id": current_user,
        "sender_device_id": sender_device_id,
        "message": request.message,
        "message_type": request.message_type,
        "created_at": datetime.utcnow().isoformat()
    }
    
    # WhatsApp-style fanout to all recipient devices
    await MessageQueueService.fanout_message_to_devices(
        message_data, 
        recipient_devices,
        ttl_minutes=60  # 1 hour TTL
    )
    
    # Store minimal metadata in MongoDB (no message content)
    message_metadata = {
        "_id": message_id,
        "chat_id": request.chat_id,
        "sender_id": current_user,
        "sender_device_id": sender_device_id,
        "message_type": request.message_type,
        "delivery_state": "sent",
        "sequence_number": await MessageQueueService.get_chat_sequence_number(request.chat_id),
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(hours=24)  # 24h TTL
    }
    
    await messages_collection().insert_one(message_metadata)
    
    return {
        "message_id": message_id,
        "state": "sent",
        "sequence_number": message_metadata["sequence_number"],
        "recipient_devices": len(recipient_devices),
        "timestamp": message_metadata["created_at"].isoformat()
    }


@router.post("/{message_id}/delivery")
async def update_delivery_status(
    message_id: str,
    receipt: DeliveryReceipt,
    current_user: str = Depends(get_current_user)
):
    """Update message delivery status - WhatsApp-style per-device tracking"""
    from ..redis_cache import MessageQueueService
    
    # Update message state for this device
    success = await MessageQueueService.update_message_state(
        message_id, 
        receipt.device_id, 
        receipt.status
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Invalid state transition")
    
    # Check if message is read by all devices (for blue tick)
    # Get all recipient devices for this message
    message_metadata = await messages_collection().find_one({"_id": message_id})
    if message_metadata:
        chat_id = message_metadata.get("chat_id")
        if chat_id:
            # Get all participants and their devices
            chat = await chats_collection().find_one({"_id": chat_id})
            participants = chat.get("participants", [])
            recipient_devices = []
            
            for participant in participants:
                if participant != message_metadata.get("sender_id"):
                    device_key = f"user_devices:{participant}"
                    devices = await redis_client.smembers(device_key)
                    recipient_devices.extend(devices or ["default"])
            
            # Check if all devices have read the message
            all_read = await MessageQueueService.is_message_read_by_all(
                message_id, 
                recipient_devices
            )
            
            return {
                "message_id": message_id,
                "device_id": receipt.device_id,
                "status": receipt.status,
                "all_devices_read": all_read,
                "timestamp": receipt.timestamp.isoformat()
            }
    
    return {"message_id": message_id, "status": "updated"}


@router.post("/delivery-receipt")
async def delivery_receipt(
    receipt: DeliveryReceipt,
    current_user: str = Depends(get_current_user)
):
    """Process delivery receipts - WhatsApp-style per-device tracking"""
    from ..redis_cache import redis_client
    
    # Verify recipient matches current user
    if receipt.recipient_id != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
    
    # Get current message state
    state_key = f"message_state:{receipt.message_id}"
    state_data = await redis_client.get(state_key)
    
    if not state_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
    
    message_state = MessageStateUpdate(**json.loads(state_data))
    
    # Update device state
    message_state.device_states[receipt.device_id] = receipt.status
    
    # Determine overall message state
    if receipt.status == MessageState.READ:
        message_state.state = MessageState.READ
    elif receipt.status == MessageState.DELIVERED and message_state.state != MessageState.READ:
        message_state.state = MessageState.DELIVERED
    
    # Save updated state
    await redis_client.setex(state_key, 3600, message_state.model_dump_json())
    
    # Remove from device queue (ACK-based deletion)
    queue_key = f"device_queue:{current_user}:{receipt.device_id}"
    await redis_client.zrem(queue_key, receipt.message_id)
    
    # Notify sender about delivery status
    sender_notification = {
        "type": "delivery_receipt",
        "message_id": receipt.message_id,
        "chat_id": receipt.chat_id,
        "recipient_id": current_user,
        "device_id": receipt.device_id,
        "status": receipt.status,
        "timestamp": receipt.timestamp.isoformat()
    }
    
    await redis_client.publish(f"user_channel:{message_state.sender_id}", json.dumps(sender_notification))
    
    return {"status": "acknowledged", "message_state": message_state.state}


@router.get("/queue/{device_id}")
async def get_device_messages(
    device_id: str,
    current_user: str = Depends(get_current_user),
    limit: int = 50
):
    """Get pending messages for a device - WhatsApp-style queue processing"""
    from ..redis_cache import redis_client
    
    queue_key = f"device_queue:{current_user}:{device_id}"
    
    # Get messages with lowest sequence numbers (ordered delivery)
    messages = await redis_client.zrange(queue_key, 0, limit - 1, withscores=True)
    
    result = []
    for message_json, sequence in messages:
        message_data = json.loads(message_json)
        result.append(message_data)
    
    return {
        "messages": result,
        "queue_size": await redis_client.zcard(queue_key),
        "device_id": device_id
    }


@router.delete("/queue/{device_id}/{message_id}")
async def acknowledge_message(
    device_id: str,
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Acknowledge message delivery and remove from queue"""
    from ..redis_cache import redis_client
    
    queue_key = f"device_queue:{current_user}:{device_id}"
    removed = await redis_client.zrem(queue_key, message_id)
    
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not in queue")
    
    # Update message state to delivered
    await delivery_receipt(
        DeliveryReceipt(
            message_id=message_id,
            chat_id="",  # Will be validated in the function
            recipient_id=current_user,
            device_id=device_id,
            status=MessageState.DELIVERED,
            timestamp=_utcnow()
        ),
        current_user
    )
    
    return {"status": "acknowledged", "message_id": message_id}


def _utcnow():
    """Helper function to get current UTC time"""
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
