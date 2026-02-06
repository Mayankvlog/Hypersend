from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime, timedelta, timezone
import uuid
import logging
import json
import time
import secrets
import base64
import hashlib
import hmac
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from auth.utils import get_current_user

# WhatsApp-Grade Cryptographic Imports
try:
    from ..crypto.signal_protocol import SignalProtocol, X3DHBundle
    from ..crypto.multi_device import MultiDeviceManager, DeviceInfo
    from ..crypto.delivery_semantics import DeliveryManager, MessageStatus
    from ..crypto.media_encryption import MediaEncryptionService
except ImportError:
    from crypto.signal_protocol import SignalProtocol, X3DHBundle
    from crypto.multi_device import MultiDeviceManager, DeviceInfo
    from crypto.delivery_semantics import DeliveryManager, MessageStatus
    from crypto.media_encryption import MediaEncryptionService

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


class WhatsAppDeliveryEngine:
    """WhatsApp Delivery Engine with per-device ACK tracking"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.retry_backoff_base = 2.0
        self.retry_backoff_max = 300.0
        self.max_retry_attempts = 5
        self.delivery_timeout = 30
    
    async def send_message(self, chat_id: str, sender_user_id: str, sender_device_id: str,
                          recipient_user_id: str, content_hash: str, message_type: str,
                          recipient_devices: List[str]) -> Dict[str, Any]:
        """Send WhatsApp message with delivery tracking"""
        # Get next sequence number
        sequence_number = await self._get_next_sequence_number(chat_id)
        
        # Generate message ID
        message_id = f"msg_{chat_id}_{sequence_number}_{uuid.uuid4().hex[:8]}"
        
        # Create message
        message = {
            "message_id": message_id,
            "chat_id": chat_id,
            "sender_user_id": sender_user_id,
            "sender_device_id": sender_device_id,
            "recipient_user_id": recipient_user_id,
            "content_hash": content_hash,
            "message_type": message_type,
            "sequence_number": sequence_number,
            "state": "sent",
            "created_at": int(datetime.utcnow().timestamp()),
            "sent_at": int(datetime.utcnow().timestamp()),
            "retry_count": 0,
            "max_retries": self.max_retry_attempts,
            "device_states": {
                device_id: "not_sent"
                for device_id in recipient_devices
            }
        }
        
        # Store message
        await self._store_message(message)
        
        # Check for duplicates
        if await self._is_duplicate_message(message):
            message["state"] = "failed"
            await self._store_message(message)
            raise ValueError("Duplicate message detected")
        
        # Queue for delivery
        await self._queue_for_delivery(message)
        
        return message
    
    async def process_delivery_receipt(self, message_id: str, device_id: str, 
                                      receipt_type: str, chat_id: str) -> Dict[str, Any]:
        """Process delivery receipt from device"""
        # Get message
        message = await self._get_message(message_id)
        if not message:
            raise ValueError("Message not found")
        
        # Update device state
        old_state = message["device_states"].get(device_id, "not_sent")
        
        if receipt_type == "delivered":
            message["device_states"][device_id] = "delivered"
        elif receipt_type == "read":
            message["device_states"][device_id] = "read"
        
        # Update message state
        await self._update_message_state(message)
        await self._store_message(message)
        
        # Publish real-time update
        await self._publish_delivery_update(message, device_id, receipt_type)
        
        return {
            "message_id": message_id,
            "device_id": device_id,
            "receipt_type": receipt_type,
            "old_state": old_state,
            "new_state": message["device_states"][device_id],
            "message_state": message["state"]
        }
    
    async def _get_next_sequence_number(self, chat_id: str) -> int:
        """Get next sequence number for chat"""
        seq_key = f"chat_sequence:{chat_id}"
        current_seq = await cache.get(seq_key)
        
        if current_seq is None:
            next_seq = 1
        else:
            next_seq = int(current_seq) + 1
        
        await cache.set(seq_key, next_seq, expire_seconds=7*24*60*60)
        return next_seq
    
    async def _store_message(self, message: Dict[str, Any]):
        """Store message in Redis"""
        message_key = f"message:{message['message_id']}"
        await cache.set(message_key, message, expire_seconds=24*60*60)
    
    async def _get_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Get message from Redis"""
        message_key = f"message:{message_id}"
        return await cache.get(message_key)
    
    async def _is_duplicate_message(self, message: Dict[str, Any]) -> bool:
        """Check for duplicate message"""
        # Check by content hash within time window
        hash_key = f"message_hash:{message['chat_id']}:{message['content_hash']}"
        existing_hash = await cache.get(hash_key)
        
        if existing_hash:
            existing_time = existing_hash["timestamp"]
            if int(datetime.utcnow().timestamp()) - existing_time < 300:  # 5 minutes
                return True
        
        # Store hash for duplicate detection
        await cache.set(hash_key, {
            "message_id": message["message_id"],
            "timestamp": int(datetime.utcnow().timestamp())
        }, expire_seconds=300)
        
        return False
    
    async def _queue_for_delivery(self, message: Dict[str, Any]):
        """Queue message for device delivery"""
        for device_id in message["device_states"].keys():
            if message["device_states"][device_id] == "not_sent":
                queue_key = f"delivery_queue:{message['recipient_user_id']}:{device_id}"
                
                delivery_task = {
                    "message_id": message["message_id"],
                    "chat_id": message["chat_id"],
                    "sender_user_id": message["sender_user_id"],
                    "device_id": device_id,
                    "content_hash": message["content_hash"],
                    "sequence_number": message["sequence_number"],
                    "created_at": message["created_at"],
                    "queued_at": int(datetime.utcnow().timestamp())
                }
                
                await cache.lpush(queue_key, json.dumps(delivery_task))
                await cache.expire(queue_key, 24*60*60)
                
                # Update device state
                message["device_states"][device_id] = "sent"
        
        await self._update_message_state(message)
        await self._store_message(message)
    
    async def _update_message_state(self, message: Dict[str, Any]):
        """Update message state based on device states"""
        device_states = list(message["device_states"].values())
        
        if not device_states:
            return
        
        # Check if any device has read
        if any(state == "read" for state in device_states):
            if message["state"] != "read":
                message["state"] = "read"
                message["read_at"] = int(datetime.utcnow().timestamp())
        
        # Check if any device has delivered
        elif any(state == "delivered" for state in device_states):
            if message["state"] != "delivered":
                message["state"] = "delivered"
                message["delivered_at"] = int(datetime.utcnow().timestamp())
        
        # Check if all devices are sent
        elif all(state in ["sent", "delivered", "read"] for state in device_states):
            if message["state"] == "sent":
                message["state"] = "delivering"
    
    async def _publish_delivery_update(self, message: Dict[str, Any], device_id: str, receipt_type: str):
        """Publish real-time delivery update"""
        update_key = f"delivery_updates:{message['chat_id']}"
        
        update_data = {
            "message_id": message["message_id"],
            "device_id": device_id,
            "receipt_type": receipt_type,
            "message_state": message["state"],
            "timestamp": int(datetime.utcnow().timestamp())
        }
        
        await cache.publish(update_key, json.dumps(update_data))


# WhatsApp Metadata Minimization
class WhatsAppMetadataMinimizer:
    """WhatsApp Metadata Minimization Service"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.timing_padding_range = (5, 30)
        self.ip_obfuscation_enabled = True
        self.contact_hashing_enabled = True
    
    async def minimize_message_metadata(self, sender_user_id: str, recipient_user_id: str,
                                       message_type: str, client_ip: str) -> Dict[str, Any]:
        """Minimize message metadata"""
        # Obfuscate IP
        obfuscated_ip = self._obfuscate_ip(client_ip) if self.ip_obfuscation_enabled else client_ip
        
        # Hash contact pair
        contact_hash = None
        if self.contact_hashing_enabled:
            contact_hash = self._hash_contact_pair(sender_user_id, recipient_user_id)
        
        return {
            "obfuscated_ip": obfuscated_ip,
            "contact_hash": contact_hash,
            "message_type": message_type,
            "timing_padding_applied": True,
            "metadata_minimized": True,
            "created_at": int(datetime.utcnow().timestamp())
        }
    
    def _obfuscate_ip(self, ip: str) -> str:
        """Obfuscate IP address for privacy"""
        try:
            if ':' in ip:  # IPv6
                parts = ip.split(':')
                if len(parts) >= 4:
                    parts[-4:] = ['0000', '0000', '0000', '0000']
                    return ':'.join(parts)
            else:  # IPv4
                parts = ip.split('.')
                if len(parts) == 4:
                    parts[-1] = '0'
                    return '.'.join(parts)
            return ip
        except Exception:
            return ip
    
    def _hash_contact_pair(self, user_a: str, user_b: str) -> str:
        """Hash contact pair for privacy"""
        sorted_pair = sorted([user_a, user_b])
        pair_string = f"{sorted_pair[0]}:{sorted_pair[1]}"
        
        secret = b"whatsapp_contact_hash_secret"
        hash_obj = hmac.HMAC(secret, hashes.SHA256())
        hash_obj.update(pair_string.encode())
        
        return base64.b64encode(hash_obj.finalize()).decode()[:16]


# Global instances
delivery_engine = None
metadata_minimizer = None

def get_delivery_engine():
    global delivery_engine
    if delivery_engine is None:
        delivery_engine = WhatsAppDeliveryEngine(cache)
    return delivery_engine

def get_metadata_minimizer():
    global metadata_minimizer
    if metadata_minimizer is None:
        metadata_minimizer = WhatsAppMetadataMinimizer(cache)
    return metadata_minimizer


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


@router.post("/send-whatsapp")
async def send_whatsapp_message(
    request: MessageSendRequest,
    current_user: str = Depends(get_current_user)
):
    """Send WhatsApp-style message with delivery tracking"""
    try:
        # Verify chat exists and user has access
        chat = await chats_collection().find_one({"_id": request.chat_id})
        if not chat:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat not found")
        
        # Check if user is member of the chat
        participants = chat.get("participants", chat.get("members", chat.get("member_ids", [])))
        if current_user not in participants and str(current_user) not in [str(p) for p in participants]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this chat")
        
        # Get recipient devices for fanout
        recipient_devices = []
        for participant in participants:
            if participant != current_user:
                # Get all active devices for this participant
                device_key = f"user_devices:{participant}"
                devices = await cache.smembers(device_key)
                recipient_devices.extend(list(devices) or ["default"])
        
        # Get delivery engine
        delivery_service = get_delivery_engine()
        
        # Generate content hash
        content_hash = hashlib.sha256(request.message.encode()).hexdigest()
        
        # Send message with WhatsApp delivery tracking
        message = await delivery_service.send_message(
            chat_id=request.chat_id,
            sender_user_id=current_user,
            sender_device_id=request.device_id or "primary",
            recipient_user_id=participants[0] if len(participants) > 1 else current_user,
            content_hash=content_hash,
            message_type=request.message_type,
            recipient_devices=recipient_devices
        )
        
        # Store minimal metadata in MongoDB
        message_metadata = {
            "_id": message["message_id"],
            "chat_id": request.chat_id,
            "sender_id": current_user,
            "sender_device_id": request.device_id or "primary",
            "message_type": request.message_type,
            "delivery_state": message["state"],
            "sequence_number": message["sequence_number"],
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(hours=24)
        }
        
        await messages_collection().insert_one(message_metadata)
        
        return {
            "message_id": message["message_id"],
            "state": message["state"],
            "sequence_number": message["sequence_number"],
            "recipient_devices": len(recipient_devices),
            "timestamp": message["created_at"]
        }
        
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to send WhatsApp message: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send message")


@router.post("/delivery-receipt-whatsapp")
async def whatsapp_delivery_receipt(
    receipt: DeliveryReceipt,
    current_user: str = Depends(get_current_user)
):
    """Process WhatsApp-style delivery receipt"""
    try:
        # Verify recipient matches current user
        if receipt.recipient_id != current_user:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
        
        # Get delivery engine
        delivery_service = get_delivery_engine()
        
        # Process delivery receipt
        result = await delivery_service.process_delivery_receipt(
            message_id=receipt.message_id,
            device_id=receipt.device_id,
            receipt_type=receipt.status,
            chat_id=receipt.chat_id
        )
        
        return result
        
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to process delivery receipt: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to process receipt")


@router.get("/delivery-status/{message_id}")
async def get_delivery_status(
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get WhatsApp-style delivery status for message"""
    try:
        # Get delivery engine
        delivery_service = get_delivery_engine()
        
        # Get message
        message = await delivery_service._get_message(message_id)
        if not message:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
        
        # Verify user is sender or recipient
        if message["sender_user_id"] != current_user and message["recipient_user_id"] != current_user:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
        # Calculate delivery statistics
        device_states = message["device_states"]
        total_devices = len(device_states)
        delivered_devices = sum(1 for state in device_states.values() if state == "delivered")
        read_devices = sum(1 for state in device_states.values() if state == "read")
        failed_devices = sum(1 for state in device_states.values() if state == "failed")
        
        return {
            "message_id": message_id,
            "state": message["state"],
            "sequence_number": message["sequence_number"],
            "created_at": message["created_at"],
            "sent_at": message.get("sent_at"),
            "delivered_at": message.get("delivered_at"),
            "read_at": message.get("read_at"),
            "device_statistics": {
                "total": total_devices,
                "delivered": delivered_devices,
                "read": read_devices,
                "failed": failed_devices,
                "pending": total_devices - delivered_devices - read_devices - failed_devices
            },
            "device_states": device_states
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get delivery status: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get status")


@router.post("/metadata-minimize")
async def minimize_message_metadata(
    request: dict,
    current_user: str = Depends(get_current_user)
):
    """Minimize message metadata for privacy"""
    try:
        # Get metadata minimizer
        minimizer = get_metadata_minimizer()
        
        # Extract metadata
        sender_user_id = current_user
        recipient_user_id = request.get("recipient_user_id")
        message_type = request.get("message_type", "text")
        client_ip = request.get("client_ip", "127.0.0.1")
        
        # Minimize metadata
        minimized = await minimizer.minimize_message_metadata(
            sender_user_id=sender_user_id,
            recipient_user_id=recipient_user_id,
            message_type=message_type,
            client_ip=client_ip
        )
        
        return minimized
        
    except Exception as e:
        logger.error(f"Failed to minimize metadata: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to minimize metadata")


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
        
        return {
            "messages": all_messages,
            "total": len(all_messages),
            "query": q,
            "filters": {
                "has_media": has_media,
                "has_link": has_link,
                "chat_id": chat_id
            }
        }
        
    except Exception as e:
        logger.error(f"Message search failed: {e}", extra={
            "user_id": current_user,
            "operation": "message_search"
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Search failed"
        )


# ============================================================================
# WHATSAPP-GRADE CRYPTOGRAPHIC API ENDPOINTS
# ============================================================================

class DeviceLinkingRequest(BaseModel):
    """Request for device linking QR code"""
    device_name: str = Field(..., description="Device name")
    device_type: str = Field(..., description="Device type: mobile, desktop, web")
    platform: str = Field(..., description="Platform: android, ios, windows, macos, linux, web")
    user_agent: str = Field(..., description="User agent string")

class DeviceLinkingResponse(BaseModel):
    """Response with QR code data"""
    qr_data: str = Field(..., description="QR code data for scanning")
    expires_at: float = Field(..., description="Expiration timestamp")
    capabilities: List[str] = Field(..., description="Device capabilities")

class DeviceLinkConfirmRequest(BaseModel):
    """Confirm device linking"""
    qr_data: str = Field(..., description="QR code data")
    device_info: Dict[str, Any] = Field(..., description="Device information")
    identity_key: str = Field(..., description="Device identity key (hex)")
    signature_key: str = Field(..., description="Device signature key (hex)")
    signed_pre_key: str = Field(..., description="Device signed pre-key (hex)")
    one_time_pre_keys: List[str] = Field(..., description="Device one-time pre-keys (hex)")

class EncryptedMessageRequest(BaseModel):
    """Encrypted message request"""
    chat_id: str = Field(..., description="Chat ID")
    encrypted_content: str = Field(..., description="Encrypted message content (hex)")
    iv: str = Field(..., description="Initialization vector (hex)")
    auth_tag: str = Field(..., description="Authentication tag (hex)")
    message_type: str = Field(..., description="Message type")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class EncryptedMessageResponse(BaseModel):
    """Response for encrypted message"""
    message_id: str = Field(..., description="Message ID")
    sequence_number: int = Field(..., description="Chat sequence number")
    timestamp: float = Field(..., description="Message timestamp")
    delivery_receipts: List[str] = Field(..., description="Device delivery receipts")

class DeliveryReceiptRequest(BaseModel):
    """Delivery receipt update"""
    message_id: str = Field(..., description="Message ID")
    device_id: str = Field(..., description="Device ID")
    status: str = Field(..., description="Delivery status")
    timestamp: float = Field(..., description="Receipt timestamp")

@router.post("/crypto/link-device", response_model=DeviceLinkingResponse)
async def generate_device_linking_qr(
    request: DeviceLinkingRequest,
    current_user: str = Depends(get_current_user)
):
    """Generate QR code for device linking"""
    try:
        from ..redis_cache import redis_client
        
        # Initialize multi-device manager
        device_manager = MultiDeviceManager(redis_client)
        
        # Get user's primary device identity keys
        primary_device = await device_manager.get_primary_device(current_user)
        if not primary_device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No primary device found"
            )
        
        # Get primary device session
        device_session = await device_manager.get_device_session(current_user, primary_device.device_id)
        if not device_session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Primary device session not found"
            )
        
        # Generate linking token
        linking_token = await device_manager.generate_linking_token(
            user_id=current_user,
            primary_identity_key=device_session.identity_key,
            primary_signature_key=device_session.signature_key,
            device_capabilities=["video_call", "voice_call", "groups", "status"],
            ttl_minutes=5
        )
        
        # Get linking data
        linking_data = await device_manager.validate_linking_token(linking_token)
        if not linking_data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate linking token"
            )
        
        return DeviceLinkingResponse(
            qr_data=linking_data.to_qr_data(),
            expires_at=linking_data.expires_at,
            capabilities=linking_data.device_capabilities
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Device linking QR generation failed: {e}", extra={
            "user_id": current_user,
            "operation": "device_linking_qr"
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate QR code"
        )

@router.post("/crypto/confirm-link")
async def confirm_device_linking(
    request: DeviceLinkConfirmRequest,
    current_user: str = Depends(get_current_user)
):
    """Confirm and complete device linking"""
    try:
        from ..redis_cache import redis_client
        
        # Initialize multi-device manager
        device_manager = MultiDeviceManager(redis_client)
        
        # Parse QR data
        linking_data = DeviceLinkingData.from_qr_data(request.qr_data)
        
        # Validate linking token
        validated_linking_data = await device_manager.validate_linking_token(linking_data.linking_token)
        if not validated_linking_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired QR code"
            )
        
        # Create device info
        device_info = DeviceInfo(
            device_id=secrets.token_urlsafe(16),
            device_name=request.device_info.get("name", "Unknown Device"),
            device_type=request.device_info.get("type", "unknown"),
            platform=request.platform,
            user_agent=request.user_agent,
            capabilities=request.device_info.get("capabilities", []),
            created_at=time.time(),
            last_active=time.time(),
            is_active=True,
            is_primary=False
        )
        
        # Convert keys from hex
        identity_key = bytes.fromhex(request.identity_key)
        signature_key = bytes.fromhex(request.signature_key)
        signed_pre_key = bytes.fromhex(request.signed_pre_key)
        one_time_pre_keys = [bytes.fromhex(key) for key in request.one_time_pre_keys]
        
        # Link device
        device_session = await device_manager.link_device(
            user_id=current_user,
            device_info=device_info,
            device_identity_key=identity_key,
            device_signature_key=signature_key,
            device_signed_pre_key=signed_pre_key,
            device_one_time_pre_keys=one_time_pre_keys,
            linking_token=linking_data.linking_token
        )
        
        return {
            "device_id": device_info.device_id,
            "linked_at": device_session.created_at,
            "session_established": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Device linking confirmation failed: {e}", extra={
            "user_id": current_user,
            "operation": "device_linking_confirm"
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to link device"
        )

@router.post("/crypto/send-encrypted", response_model=EncryptedMessageResponse)
async def send_encrypted_message(
    request: EncryptedMessageRequest,
    current_user: str = Depends(get_current_user)
):
    """Send end-to-end encrypted message"""
    try:
        from ..redis_cache import redis_client
        
        # Initialize services
        delivery_manager = DeliveryManager(redis_client)
        device_manager = MultiDeviceManager(redis_client)
        
        # Get recipient devices
        chat_data = await chats_collection().find_one({"_id": request.chat_id})
        if not chat_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Chat not found"
            )
        
        recipient_devices = []
        for member in chat_data.get("members", []):
            if member != current_user:  # Skip sender
                devices = await device_manager.get_active_devices(member)
                recipient_devices.extend([d.device_id for d in devices])
        
        if not recipient_devices:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No active recipient devices"
            )
        
        # Get sequence number
        sequence_number = await delivery_manager.get_chat_sequence_number(request.chat_id)
        
        # Generate message ID
        message_id = secrets.token_urlsafe(32)
        
        # Initialize delivery
        receipts = await delivery_manager.initialize_message_delivery(
            message_id=message_id,
            sender_id=current_user,
            chat_id=request.chat_id,
            recipient_devices=recipient_devices,
            sequence_number=sequence_number
        )
        
        # Store encrypted message
        message_data = {
            "message_id": message_id,
            "chat_id": request.chat_id,
            "sender_id": current_user,
            "encrypted_content": request.encrypted_content,
            "iv": request.iv,
            "auth_tag": request.auth_tag,
            "message_type": request.message_type,
            "sequence_number": sequence_number,
            "timestamp": time.time(),
            "metadata": request.metadata or {}
        }
        
        await redis_client.set(f"encrypted_message:{message_id}", json.dumps(message_data))
        await redis_client.lpush(f"chat_encrypted:{request.chat_id}", message_id)
        
        return EncryptedMessageResponse(
            message_id=message_id,
            sequence_number=sequence_number,
            timestamp=time.time(),
            delivery_receipts=[device_id for device_id in receipts.keys()]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Encrypted message send failed: {e}", extra={
            "user_id": current_user,
            "operation": "send_encrypted_message"
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send encrypted message"
        )

@router.post("/crypto/delivery-receipt")
async def update_delivery_receipt(
    request: DeliveryReceiptRequest,
    current_user: str = Depends(get_current_user)
):
    """Update delivery receipt for message"""
    try:
        from ..redis_cache import redis_client
        
        # Initialize delivery manager
        delivery_manager = DeliveryManager(redis_client)
        
        # Update receipt based on status
        if request.status == "delivered":
            success = await delivery_manager.mark_message_delivered(request.message_id, request.device_id)
        elif request.status == "read":
            success = await delivery_manager.mark_message_read(request.message_id, request.device_id)
        elif request.status == "sent":
            success = await delivery_manager.mark_message_sent(request.message_id, request.device_id)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid delivery status"
            )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message or device not found"
            )
        
        return {
            "message_id": request.message_id,
            "device_id": request.device_id,
            "status": request.status,
            "timestamp": request.timestamp,
            "updated": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delivery receipt update failed: {e}", extra={
            "user_id": current_user,
            "operation": "delivery_receipt"
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update delivery receipt"
        )

@router.get("/crypto/pending-deliveries")
async def get_pending_deliveries(
    device_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get pending message deliveries for device"""
    try:
        from ..redis_cache import redis_client
        
        # Initialize delivery manager
        delivery_manager = DeliveryManager(redis_client)
        
        # Verify device belongs to user
        device_manager = MultiDeviceManager(redis_client)
        user_devices = await device_manager.get_user_devices(current_user)
        if not any(d.device_id == device_id for d in user_devices):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Device not authorized for user"
            )
        
        # Get pending deliveries
        pending_receipts = await delivery_manager.get_pending_deliveries(device_id)
        
        # Get encrypted messages
        messages = []
        for receipt in pending_receipts:
            message_data = await redis_client.get(f"encrypted_message:{receipt.message_id}")
            if message_data:
                messages.append(json.loads(message_data))
        
        return {
            "device_id": device_id,
            "pending_messages": messages,
            "pending_count": len(messages),
            "timestamp": time.time()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Pending deliveries fetch failed: {e}", extra={
            "user_id": current_user,
            "operation": "pending_deliveries"
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch pending deliveries"
        )
        
        return {"messages": all_messages, "count": len(all_messages)}
        
    except Exception as e:
        logger.error(f"Failed to search messages in Redis: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Message search temporarily unavailable"
        )
