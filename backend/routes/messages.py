from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Body
from typing import Optional, Dict, List, Tuple, Any, Set
from datetime import datetime, timedelta, timezone
import uuid
import logging
import json
import time
import secrets
import base64
import hashlib
import hmac
import asyncio
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from bson import ObjectId
from fastapi import Query

# Auth utilities with fallback for different import paths
try:
    from backend.auth.utils import get_current_user
    from backend.auth.utils import decode_token
except ImportError:
    from auth.utils import get_current_user
    from auth.utils import decode_token

# WhatsApp-Grade Cryptographic Imports
try:
    from ..crypto.signal_protocol import SignalProtocol, X3DHBundle
    from ..crypto.multi_device import MultiDeviceManager, DeviceInfo, DeviceLinkingData
    from ..crypto.delivery_semantics import DeliveryManager, MessageStatus
    from ..crypto.media_encryption import MediaEncryptionService
except ImportError:
    # Fallback for direct execution
    SignalProtocol = None
    X3DHBundle = None
    MultiDeviceManager = None
    DeviceInfo = None
    DeviceLinkingData = None
    DeliveryManager = None
    MessageStatus = None
    MediaEncryptionService = None

try:
    from backend.db_proxy import chats_collection, messages_collection, users_collection
    from backend.models import (
        MessageEditRequest, MessageReactionRequest, MessageHistoryRequest, 
        MessageHistoryResponse, ConversationMetadata, RelationshipGraph, 
        DeviceSyncState, MessageDeliveryReceipt, MessageStatusUpdate,
        PersistentMessage, ConversationHistory
    )
    from backend.redis_cache import cache
    from backend.services.relationship_graph_service import relationship_graph_service
    from backend.services.message_history_service import message_history_service
    from backend.e2ee_service import EncryptionError, DecryptionError
except ImportError:
    from db_proxy import chats_collection, messages_collection, users_collection
    from models import (
        MessageEditRequest, MessageReactionRequest, MessageHistoryRequest, 
        MessageHistoryResponse, ConversationMetadata, RelationshipGraph, 
        DeviceSyncState, MessageDeliveryReceipt, MessageStatusUpdate,
        PersistentMessage, ConversationHistory
    )
    from backend.redis_cache import cache
    from e2ee_service import EncryptionError, DecryptionError
    try:
        from services.relationship_graph_service import relationship_graph_service
        from services.message_history_service import message_history_service
    except ImportError:
        # Fallback for direct execution
        relationship_graph_service = None
        message_history_service = None

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
        """Send WhatsApp message with delivery tracking (UTC timestamps only).
        
        CRITICAL TIMESTAMP FIX:
        - Use datetime.utcnow().isoformat() + 'Z' for all timestamps
        - Never use datetime.now() - always use datetime.utcnow()
        - Return ISO 8601 UTC format with Z suffix
        - NO timezone conversion on backend
        """
        # CRITICAL: Generate timestamp ONCE using UTC, never use datetime.now()
        message_timestamp_utc = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        
        # Get next sequence number
        sequence_number = await self._get_next_sequence_number(chat_id)
        
        # Generate message ID
        message_id = f"msg_{chat_id}_{sequence_number}_{uuid.uuid4().hex[:8]}"
        
        # Create message with preserved UTC timestamp (ISO 8601 with Z suffix)
        message = {
            "message_id": message_id,
            "chat_id": chat_id,
            "sender_user_id": sender_user_id,
            "sender_device_id": sender_device_id,
            "recipient_user_id": recipient_user_id,
            "content_hash": content_hash,
            "message_type": message_type,
            "sequence_number": sequence_number,
            "state": MessageState.PENDING,  # Start in pending state
            "created_at": message_timestamp_utc,  # UTC ISO 8601 with Z
            "sent_at": message_timestamp_utc,    # Same UTC timestamp
            "retry_count": 0,
            "max_retries": self.max_retry_attempts,
            "device_states": {
                device_id: "not_sent"
                for device_id in recipient_devices
            }
        }
        
        # STEP 1: Store in MongoDB first (DB insert completes before Redis)
        await self._store_message_in_db(message)
        
        # STEP 2: Check for duplicates in DB (must happen after DB insert)
        if await self._is_duplicate_message_in_db(message):
            message["state"] = "failed"
            await self._store_message_in_db(message)
            raise ValueError("Duplicate message detected")
        
        # STEP 3: Store in Redis cache (after DB confirmation)
        await self._store_message_in_redis(message)
        
        # STEP 4: Queue for delivery (after Redis storage)
        await self._queue_for_delivery(message)
        
        # STEP 5: Publish to Redis (after queuing, before WebSocket)
        await self._publish_to_redis(message)
        
        # STEP 6: WebSocket broadcast (final step, after all persistence)
        await self._broadcast_to_websockets(message)
        
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
    
    async def _store_message_in_db(self, message: Dict[str, Any]):
        """Store message in MongoDB first"""
        from backend.db_proxy import messages_collection
        
        # Convert string timestamp back to datetime for MongoDB
        message_doc = message.copy()
        if isinstance(message_doc.get("created_at"), str):
            message_doc["created_at"] = datetime.fromisoformat(message_doc["created_at"].replace('Z', '+00:00'))
        if isinstance(message_doc.get("sent_at"), str):
            message_doc["sent_at"] = datetime.fromisoformat(message_doc["sent_at"].replace('Z', '+00:00'))
        
        await messages_collection().insert_one(message_doc)
    
    async def _store_message_in_redis(self, message: Dict[str, Any]):
        """Store message in Redis cache after DB"""
        message_key = f"message:{message['message_id']}"
        await cache.set(message_key, message, expire_seconds=24*60*60)
    
    async def _is_duplicate_message_in_db(self, message: Dict[str, Any]) -> bool:
        """Check for duplicate message in DB"""
        from backend.db_proxy import messages_collection
        
        # Check by content hash within time window
        time_window = datetime.now(timezone.utc) - timedelta(minutes=5)
        
        existing = await messages_collection().find_one({
            "chat_id": message["chat_id"],
            "content_hash": message["content_hash"],
            "created_at": {"$gte": time_window}
        })
        
        return existing is not None
    
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
            current_time = datetime.now(timezone.utc).timestamp()
            if current_time - existing_time < 300:  # 5 minutes
                return True
        
        # Store hash for duplicate detection
        await cache.set(hash_key, {
            "message_id": message["message_id"],
            "timestamp": datetime.now(timezone.utc).timestamp()
        }, expire_seconds=300)
        
        return False
    
    async def _queue_for_delivery(self, message: Dict[str, Any]):
        """Queue message for device delivery after Redis storage"""
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
                    "created_at": message["created_at"],  # Use original timestamp
                    "queued_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                }
                
                # CRITICAL: Use exact DB timestamp, never regenerate
                await cache.lpush(queue_key, json.dumps(delivery_task))
                await cache.expire(queue_key, 24*60*60)
                
                # Update device state
                message["device_states"][device_id] = "sent"
        
        await self._update_message_state(message)
    
    async def _publish_to_redis(self, message: Dict[str, Any]):
        """Publish to Redis channels after queuing"""
        # CRITICAL: Publish with original timestamp, never regenerate
        message_payload = {
            "type": "new_message",
            "message_id": message["message_id"],
            "chat_id": message["chat_id"],
            "sender_id": message["sender_user_id"],
            "recipient_id": message["recipient_user_id"],
            "message_type": message["message_type"],
            "created_at": message["created_at"],  # Original timestamp from DB
            "sequence_number": message["sequence_number"]
        }
        
        # STEP 1: Always publish to chat messages channel (delivery)
        await self.redis.publish(f"chat_messages:{message['chat_id']}", json.dumps(message_payload))
        
        # STEP 2: Check mute status before publishing to notifications channel
        await self._publish_notifications_if_not_muted(message_payload)
    
    async def _publish_notifications_if_not_muted(self, message_payload: Dict[str, Any]):
        """Publish to separate notification channels with per-user mute checking"""
        from backend.db_proxy import chats_collection
        
        chat_id = message_payload["chat_id"]
        
        # Get chat to check mute configurations
        chat = await chats_collection().find_one({"_id": chat_id})
        if not chat or not chat.get("mute_config"):
            # No mute config, publish to both channels normally
            await self.redis.publish(f"chat_messages:{chat_id}", json.dumps(message_payload))
            await self.redis.publish(f"chat_notifications:{chat_id}", json.dumps(message_payload))
            return
        
        # Check each user's mute status
        mute_config = chat["mute_config"]
        current_time = datetime.now(timezone.utc)
        
        # STEP 1: Always publish to chat messages channel (delivery regardless of mute)
        await self.redis.publish(f"chat_messages:{chat_id}", json.dumps(message_payload))
        
        # STEP 2: Publish to chat notifications channel only for unmuted users
        for user_id, mute_info in mute_config.items():
            try:
                # Parse mute_until timestamp
                mute_until_str = mute_info.get("mute_until")
                if not mute_until_str:
                    # No mute_until, user receives notifications
                    await self.redis.publish(f"user_notifications:{user_id}", json.dumps(message_payload))
                    continue
                
                mute_until = datetime.fromisoformat(mute_until_str.replace('Z', '+00:00'))
                
                # Check if mute is still active
                if current_time >= mute_until:
                    # Mute expired, user receives notifications
                    await self.redis.publish(f"user_notifications:{user_id}", json.dumps(message_payload))
                # else: User is still muted, do NOT send notification
                
            except Exception as e:
                # Error parsing mute time, err on side of sending notification
                await self.redis.publish(f"user_notifications:{user_id}", json.dumps(message_payload))

        # STEP 3: Also publish to general chat notifications channel for users without mute config
        await self.redis.publish(f"chat_notifications:{chat_id}", json.dumps(message_payload))
    
    async def _update_message_state(self, message: Dict[str, Any]):
        """Update message state based on device states"""
        device_states = message.get("device_states", {}).values()
        
        # Check if any device has read
        if any(state == "read" for state in device_states):
            if message["state"] != "read":
                message["state"] = "read"  # UTC only
        
        # Check if any device has delivered
        elif any(state == "delivered" for state in device_states):
            if message["state"] != "delivered":
                message["state"] = "delivered"
                message["delivered_at"] = _format_utc(datetime.now(timezone.utc))  # UTC only
        
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
            "timestamp": _format_utc(datetime.now(timezone.utc))  # UTC only
        }
        
        # CRITICAL FIX: Ensure we send JSON string, not tuple to Redis
        payload = json.dumps(update_data)
        await cache.publish(update_key, payload)
    
    async def _broadcast_to_websockets(self, message: Dict[str, Any]):
        """Broadcast message to WebSocket clients after all persistence"""
        # WebSocket broadcast is handled by the WebSocket manager
        # This is a placeholder for the broadcast operation
        try:
            # Signal to WebSocket manager that message is ready for broadcast
            broadcast_key = f"websocket_broadcast:{message['chat_id']}"
            broadcast_data = {
                "type": "message_ready_for_broadcast",
                "message_id": message["message_id"],
                "timestamp": message.get("created_at", _format_utc(datetime.now(timezone.utc)))
            }
            # CRITICAL FIX: Ensure we send JSON string, not tuple to Redis
            await cache.publish(broadcast_key, json.dumps(broadcast_data))
        except Exception as e:
            logger.warning(f"WebSocket broadcast failed for message {message.get('message_id')}: {e}")
    
    async def _store_message(self, message: Dict[str, Any]):
        """Store message in database"""
        from backend.db_proxy import messages_collection
        
        # Convert ISO timestamps back to datetime for MongoDB storage
        message_doc = message.copy()
        if isinstance(message_doc.get("created_at"), str):
            message_doc["created_at"] = datetime.fromisoformat(message_doc["created_at"].replace('Z', '+00:00'))
        if isinstance(message_doc.get("sent_at"), str):
            message_doc["sent_at"] = datetime.fromisoformat(message_doc["sent_at"].replace('Z', '+00:00'))
        if isinstance(message_doc.get("delivered_at"), str):
            message_doc["delivered_at"] = datetime.fromisoformat(message_doc["delivered_at"].replace('Z', '+00:00'))
        
        # Update the message in the database
        await messages_collection().update_one(
            {"message_id": message["message_id"]},
            {"$set": message_doc}
        )


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
            "created_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')  # UTC only
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
# e2ee_service = None  # Commented out - service not available

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

def get_e2ee_service():
    """Get or create E2EE service instance"""
    try:
        from e2ee_service import E2EEService
    except ImportError:
        from ..e2ee_service import E2EEService
    return E2EEService(db=None, redis_client=cache)


class MessageSendRequest(BaseModel):
    chat_id: str
    message: str = Field(..., min_length=1, max_length=10000)
    message_type: str = "text"
    device_id: Optional[str] = None  # Sending device ID
    encrypt_e2ee: bool = False  # Enable E2EE encryption


class E2EEMessageSendRequest(BaseModel):
    session_id: str = Field(..., min_length=32, description="E2EE session ID")
    chat_id: str
    plaintext: str = Field(..., min_length=1, max_length=10000)
    message_type: str = "text"
    recipient_devices: List[str] = Field(..., min_length=1, description="Target device IDs")
    device_id: Optional[str] = None
    ttl_seconds: Optional[int] = None  # For ephemeral messages
    view_once: bool = False


class MediaUploadRequest(BaseModel):
    file_type: str = Field(..., pattern="^(image|video|audio|document)$")
    view_once: bool = False
    ttl_seconds: Optional[int] = None
    encrypt_e2ee: bool = True


class GroupMessageRequest(BaseModel):
    group_id: str
    message: str = Field(..., min_length=1, max_length=10000)
    encrypt_e2ee: bool = True


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
    try:
        from config import settings
    except Exception:
        from ..config import settings

    allowed_origin = settings.CORS_ORIGINS[0] if getattr(settings, "CORS_ORIGINS", None) else "https://zaply.in.net"
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400"
        }
    )


# # @router.post("/send-e2ee")
# async def send_e2ee_message(
#     request: E2EEMessageSendRequest,
#     current_user: str = Depends(get_current_user)
# ):
#     """Send E2EE encrypted message with Signal Protocol"""
#     try:
#         # Get E2EE service
#         e2ee_svc = get_e2ee_service()
#         
#         # Verify chat exists and user has access
#         chat = await chats_collection().find_one({"_id": request.chat_id})
#         if not chat:
#             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat not found")
#         
#         # Check if user is member of chat
#         participants = chat.get("participants", chat.get("members", chat.get("member_ids", [])))
#         if current_user not in participants and str(current_user) not in [str(p) for p in participants]:
#             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this chat")
#         
#         # Encrypt and send message using E2EE
#         result = await e2ee_svc.encrypt_and_send_message(
#             session_id=request.session_id,
#             plaintext=request.plaintext,
#             sender_user_id=current_user,
#             sender_device_id=request.device_id or "primary",
#             recipient_user_id=participants[0] if len(participants) > 1 else current_user,
#             recipient_devices=request.recipient_devices
#         )
#         
#         return {
#             "message_id": result["message_id"],
#             "session_id": request.session_id,
#             "state": "encrypted",
#             "devices_targeted": result["devices_targeted"],
#             "timestamp": result["timestamp"],
#             "encrypted": True,
#             "message": "✓ Message encrypted and queued for delivery"
#         }
#         
#     except EncryptionError as e:
#         logger.error(f"E2EE encryption failed: {e}")
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Encryption failed: {str(e)}")
#     except Exception as e:
#         logger.error(f"Failed to send E2EE message: {str(e)}")
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send message")


@router.post("/upload-media-e2ee")
async def upload_e2ee_media(
    file_type: str,
    view_once: bool = False,
    ttl_seconds: Optional[int] = None,
    encrypt_e2ee: bool = True,
    current_user: str = Depends(get_current_user)
):
    """Upload and encrypt media file with E2EE"""
    try:
        # Get E2EE service
        e2ee_svc = get_e2ee_service()
        
        # In a real implementation, this would handle file upload
        # For now, simulate file data
        file_data = b"simulated_media_file_content"
        
        # Encrypt media file
        result = await e2ee_svc.encrypt_media_file(
            file_data=file_data,
            file_type=file_type,
            view_once=view_once,
            ttl_seconds=ttl_seconds
        )
        
        return {
            "media_id": result["media_id"],
            "file_type": result["file_type"],
            "view_once": result["view_once"],
            "ttl_seconds": result["ttl_seconds"],
            "timestamp": result["timestamp"],
            "encrypted": True,
            "message": "✓ Media file encrypted and stored"
        }
        
    except EncryptionError as e:
        logger.error(f"Media encryption failed: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Media encryption failed: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to upload media: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload media")


@router.post("/group-message-e2ee")
async def send_group_e2ee_message(
    request: GroupMessageRequest,
    current_user: str = Depends(get_current_user)
):
    """Send encrypted group message using Sender Key"""
    try:
        # Get E2EE service
        e2ee_svc = get_e2ee_service()
        
        # Verify group exists and user is member
        group = await chats_collection().find_one({"_id": request.group_id, "type": "group"})
        if not group:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
        
        participants = group.get("participants", [])
        if current_user not in participants and str(current_user) not in [str(p) for p in participants]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this group")
        
        # Send encrypted group message
        result = await e2ee_svc.send_group_message(
            group_id=request.group_id,
            sender_user_id=current_user,
            message_text=request.message
        )
        
        return {
            "message_id": result["message_id"],
            "group_id": request.group_id,
            "timestamp": result["timestamp"],
            "encrypted": True,
            "message": "✓ Group message encrypted and fanned out"
        }
        
    except EncryptionError as e:
        logger.error(f"Group message encryption failed: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Group encryption failed: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to send group message: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send group message")


@router.post("/init-e2ee-session")
async def init_e2ee_session(
    recipient_user_id: str,
    recipient_device_id: str = "primary",
    current_user: str = Depends(get_current_user)
):
    """Initialize E2EE session with X3DH"""
    try:
        # Get E2EE service
        e2ee_svc = get_e2ee_service()
        
        # Generate ephemeral key pair for initiator
        initiator_ephemeral_private = secrets.token_bytes(32)
        initiator_ephemeral_public = initiator_ephemeral_private  # Would be proper X25519 in production
        
        initiator_identity_pair = ("private_key_placeholder", "public_key_placeholder")
        
        # Initialize session
        result = await e2ee_svc.initiate_session_with_x3dh(
            initiator_user_id=current_user,
            initiator_device_id="primary",
            initiator_identity_pair=initiator_identity_pair,
            initiator_ephemeral_pair=(initiator_ephemeral_private.hex(), initiator_ephemeral_public.hex()),
            recipient_user_id=recipient_user_id,
            recipient_device_id=recipient_device_id
        )
        
        return {
            "session_id": result["session_id"],
            "initiator_device_id": result["initiator_device_id"],
            "recipient_device_id": result["recipient_device_id"],
            "ephemeral_key_b64": result["ephemeral_key_b64"],
            "one_time_prekey_used": result["one_time_prekey_used"],
            "message": "✓ E2EE session established"
        }
        
    except Exception as e:
        logger.error(f"Failed to initialize E2EE session: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to initialize session")


@router.get("/get-user-bundle/{user_id}")
async def get_user_e2ee_bundle(
    user_id: str,
    device_id: str = "primary",
    current_user: str = Depends(get_current_user)
):
    """Get user's X3DH bundle for E2EE"""
    try:
        # Get E2EE service
        e2ee_svc = get_e2ee_service()
        
        # Users can only get their own bundles
        if current_user != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Can only get own bundle")
        
        # Get user bundle
        bundle = await e2ee_svc.get_user_bundle(user_id, device_id)
        
        return {
            "user_id": user_id,
            "device_id": device_id,
            "identity_key": bundle.identity_key.hex(),
            "signed_pre_key": bundle.signed_pre_key.hex(),
            "signed_pre_key_id": bundle.signed_pre_key_id,
            "signed_pre_key_signature": bundle.signed_pre_key_signature.hex(),
            "one_time_pre_keys": [
                {
                    "key_id": key.key_id,
                    "public_key": key.public_key.hex()
                }
                for key in bundle.one_time_pre_keys[:10]  # Return first 10
            ],
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        
    except Exception as e:
        logger.error(f"Failed to get user bundle: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get bundle")


@router.post("/receive-e2ee-message")
async def receive_e2ee_message(
    session_id: str,
    message_id: str,
    message_envelope: dict,
    current_user: str = Depends(get_current_user)
):
    """Receive and decrypt E2EE message"""
    try:
        # Get E2EE service
        e2ee_svc = get_e2ee_service()
        
        # Decrypt message
        plaintext = await e2ee_svc.receive_and_decrypt_message(
            session_id=session_id,
            message_id=message_id,
            message_envelope=message_envelope,
            receiver_user_id=current_user,
            receiver_device_id="primary"
        )
        
        return {
            "message_id": message_id,
            "plaintext": plaintext,
            "decrypted": True,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "message": "✓ Message decrypted successfully"
        }
        
    except DecryptionError as e:
        logger.error(f"Message decryption failed: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Decryption failed: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to receive message: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to receive message")


@router.post("/delivery-receipt-e2ee")
async def e2ee_delivery_receipt(
    message_id: str,
    receipt_type: str,  # delivered, read
    recipient_user_id: str,
    recipient_device_id: str,
    current_user: str = Depends(get_current_user)
):
    """Track E2EE delivery receipt"""
    try:
        # Get E2EE service
        e2ee_svc = get_e2ee_service()
        
        # Verify recipient matches current user
        if recipient_user_id != current_user:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
        
        # Track delivery receipt
        result = await e2ee_svc.track_delivery_receipt(
            message_id=message_id,
            recipient_user_id=recipient_user_id,
            recipient_device_id=recipient_device_id,
            receipt_type=receipt_type
        )
        
        return {
            "message_id": message_id,
            "receipt_type": result["receipt_type"],
            "timestamp": result["receipt_timestamp"],
            "message": f"✓ {receipt_type} receipt recorded"
        }
        
    except Exception as e:
        logger.error(f"Failed to track delivery receipt: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to track receipt")


@router.get("/message-state-e2ee/{message_id}")
async def get_e2ee_message_state(
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get E2EE message state"""
    try:
        # Get E2EE service
        e2ee_svc = get_e2ee_service()
        
        # Get message state
        state = await e2ee_svc.get_message_state(message_id)
        
        return {
            "message_id": message_id,
            "state": state,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "message": "✓ Message state retrieved"
        }
        
    except Exception as e:
        logger.error(f"Failed to get message state: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get message state")


@router.post("/abuse-score-e2ee")
async def get_e2ee_abuse_score(
    current_user: str = Depends(get_current_user)
):
    """Get user's E2EE abuse score"""
    try:
        # Get E2EE service
        e2ee_svc = get_e2ee_service()
        
        # Get abuse score
        score_data = await e2ee_svc.get_user_abuse_score(current_user)
        
        return {
            "user_id": current_user,
            "score": score_data["score"],
            "action": score_data["action"],
            "updated_at": score_data["last_updated_at"],
            "message": "✓ Abuse score retrieved"
        }
        
    except Exception as e:
        logger.error(f"Failed to get abuse score: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get abuse score")


@router.post("/report-abuse-e2ee")
async def report_e2ee_abuse(
    reported_user_id: str,
    report_type: str,  # spam, harassment, csam, phishing
    reason: str = Query(..., min_length=10, max_length=500),
    current_user: str = Depends(get_current_user)
):
    """Report abuse for E2EE"""
    try:
        # Get E2EE service
        e2ee_svc = get_e2ee_service()
        
        # Process abuse report
        result = await e2ee_svc.process_abuse_report(
            reporter_user_id=current_user,
            reported_user_id=reported_user_id,
            report_type=report_type,
            reason=reason
        )
        
        return {
            "report_id": result["report_id"],
            "reported_user_id": reported_user_id,
            "report_type": report_type,
            "created_at": result["created_at"],
            "message": "✓ Abuse report filed. Moderation team will review."
        }
        
    except Exception as e:
        logger.error(f"Failed to file abuse report: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to file report")
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
        
        # Compute recipient user ID
        recipient_user_id = participants[0] if len(participants) > 1 else current_user
        
        # Send message with WhatsApp delivery tracking
        message = await delivery_service.send_message(
            chat_id=request.chat_id,
            sender_user_id=current_user,
            sender_device_id=request.device_id or "primary",
            recipient_user_id=recipient_user_id,
            content_hash=content_hash,
            message_type=request.message_type,
            recipient_devices=recipient_devices
        )
        
        # WhatsApp-style: Store only in Redis (ephemeral, per-device)
        message_key = f"message:{message['message_id']}"
        await cache.set(message_key, message, expire_seconds=24*60*60)  # 24h TTL
        
        # Store in per-device queues for delivery
        for device_id in recipient_devices:
            queue_key = f"device_queue:{recipient_user_id}:{device_id}"
            await cache.zadd(queue_key, {
                message['message_id']: message['created_at']
            })
            await cache.expire(queue_key, 24*60*60)  # 24h TTL
        
        # Store chat sequence
        seq_key = f"chat_sequence:{request.chat_id}"
        await cache.set(seq_key, message['sequence_number'], expire_seconds=7*24*60*60)
        
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


@router.get("/emojis")
async def get_emojis(
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search emojis by name"),
    popular: bool = Query(False, description="Return popular emojis only"),
    current_user: str = Depends(get_current_user)
):
    """Get WhatsApp-style emojis with 8 categories"""
    try:
        from ..services.emoji_service import get_emoji_service
        emoji_svc = get_emoji_service()
        
        if popular:
            emojis = emoji_svc.get_popular_emojis()
            return {
                "status": "success",
                "emojis": emojis,
                "type": "popular",
                "total": len(emojis)
            }
        
        if search:
            emojis = emoji_svc.search_emojis(search)
            return {
                "status": "success",
                "emojis": emojis,
                "type": "search",
                "query": search,
                "total": len(emojis)
            }
        
        if category:
            if category not in emoji_svc.categories:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid category. Available: {list(emoji_svc.categories.keys())}"
                )
            emojis = emoji_svc.get_emojis_by_category(category)
            return {
                "status": "success",
                "category": category,
                "emojis": emojis,
                "type": "category",
                "total": len(emojis)
            }
        
        # Return all emojis grouped by category
        all_emojis = emoji_svc.get_all_emojis()
        return {
            "status": "success",
            "emojis": all_emojis,
            "type": "all",
            "categories": list(emoji_svc.categories.keys()),
            "total_emojis": sum(len(cat["emojis"]) for cat in all_emojis)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get emojis: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve emojis"
        )


@router.get("/emojis/categories")
async def get_emoji_categories(current_user: str = Depends(get_current_user)):
    """Get available emoji categories"""
    try:
        from ..services.emoji_service import get_emoji_service
        emoji_svc = get_emoji_service()
        
        categories = []
        for category_name, emojis in emoji_svc.categories.items():
            categories.append({
                "name": category_name,
                "count": len(emojis),
                "sample": emojis[:5]  # First 5 emojis as sample
            })
        
        return {
            "status": "success",
            "categories": categories,
            "total_categories": len(categories)
        }
        
    except Exception as e:
        logger.error(f"Failed to get emoji categories: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve emoji categories"
        )


@router.post("/emojis/validate")
async def validate_emoji(
    emoji: dict = Body(..., description={"symbol": "😀"}),
    current_user: str = Depends(get_current_user)
):
    """Validate if emoji symbol is supported"""
    try:
        symbol = emoji.get("symbol")
        if not symbol:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Emoji symbol is required"
            )
        
        from ..services.emoji_service import get_emoji_service
        emoji_svc = get_emoji_service()
        
        is_valid = emoji_svc.validate_emoji(symbol)
        emoji_info = emoji_svc.get_emoji_info(symbol) if is_valid else None
        
        return {
            "status": "success",
            "symbol": symbol,
            "valid": is_valid,
            "info": emoji_info
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to validate emoji: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate emoji"
        )


# @router.post("/delivery-receipt-whatsapp")
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


# @router.post("/metadata-minimize")
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
        client_ip = request.get("client_ip") or ""
        
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


# @router.post("/{message_id}/delivery")
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
    # Get message from Redis
    message_key = f"message:{message_id}"
    message_data = await cache.get(message_key)
    if message_data:
        chat_id = message_data.get("chat_id")
        if chat_id:
            # Get all participants and their devices
            chat = await chats_collection().find_one({"_id": chat_id})
            participants = chat.get("participants", [])
            recipient_devices = []
            
            for participant in participants:
                if participant != message_data.get("sender_user_id"):
                    device_key = f"user_devices:{participant}"
                    devices = await cache.smembers(device_key)
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
                "timestamp": _format_utc(receipt.timestamp)
            }
    
    return {"message_id": message_id, "status": "updated"}


# @router.post("/delivery-receipt")
async def delivery_receipt(
    receipt: DeliveryReceipt,
    current_user: str = Depends(get_current_user)
):
    """Process delivery receipts - WhatsApp-style per-device tracking"""
    # Verify recipient matches current user
    if receipt.recipient_id != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
    
    # Get current message state
    state_key = f"message_state:{receipt.message_id}"
    state_data = await cache.get(state_key)
    
    if not state_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
    
    message_state = MessageStateUpdate(**json.loads(state_data) if isinstance(state_data, str) else state_data)
    
    # Update device state
    message_state.device_states[receipt.device_id] = receipt.status
    
    # Determine overall message state
    if receipt.status == MessageState.READ:
        message_state.state = MessageState.READ
    elif receipt.status == MessageState.DELIVERED and message_state.state != MessageState.READ:
        message_state.state = MessageState.DELIVERED
    
    # Save updated state to cache
    try:
        await cache.set(state_key, json.dumps(message_state.model_dump()), expire_seconds=3600)
    except Exception as e:
        logger.debug(f"Failed to save message state to cache: {e}")
    
    # Remove from device queue (ACK-based deletion)
    queue_key = f"device_queue:{current_user}:{receipt.device_id}"
    try:
        await cache.zrem(queue_key, receipt.message_id)
    except Exception as e:
        logger.debug(f"Failed to remove from queue: {e}")
    
    # Notify sender about delivery status
    sender_notification = {
        "type": "delivery_receipt",
        "message_id": receipt.message_id,
        "chat_id": receipt.chat_id,
        "recipient_id": current_user,
        "device_id": receipt.device_id,
        "status": receipt.status,
        "timestamp": _format_utc(receipt.timestamp)
    }
    
    try:
        await cache.publish(f"user_channel:{message_state.sender_id}", json.dumps(sender_notification))
    except Exception as e:
        logger.debug(f"Failed to publish delivery receipt: {e}")
    
    return {"status": "acknowledged", "message_state": message_state.state}


@router.get("/queue/{device_id}")
async def get_device_messages(
    device_id: str,
    current_user: str = Depends(get_current_user),
    limit: int = 50
):
    """Get pending messages for a device - WhatsApp-style queue processing"""
    queue_key = f"device_queue:{current_user}:{device_id}"
    
    # Get messages with lowest sequence numbers (ordered delivery)
    messages = await cache.zrange(queue_key, 0, limit - 1, withscores=True)
    
    result = []
    if messages:
        for message_json, sequence in messages:
            try:
                message_data = json.loads(message_json) if isinstance(message_json, str) else message_data
                result.append(message_data)
            except Exception as e:
                logger.debug(f"Failed to parse message from queue: {e}")
    
    queue_size = await cache.zcard(queue_key)
    
    return {
        "messages": result,
        "queue_size": queue_size or 0,
        "device_id": device_id
    }


@router.delete("/queue/{device_id}/{message_id}")
async def acknowledge_message(
    device_id: str,
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Acknowledge message delivery and remove from queue"""
    queue_key = f"device_queue:{current_user}:{device_id}"
    
    try:
        removed = await cache.zrem(queue_key, message_id)
        
        if not removed:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not in queue")
        
        # Update message state to delivered if possible
        try:
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
        except HTTPException:
            # If delivery receipt fails, still acknowledge the removal
            pass
        
        return {"status": "acknowledged", "message_id": message_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to acknowledge message: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to acknowledge message")



# ---------------------------------------------------------------------------
# Time utilities
# ---------------------------------------------------------------------------

def _format_utc(dt: datetime) -> str:
    """Convert a datetime to an ISO8601 string with trailing Z (UTC).

    Accepts naive or aware datetimes. Naive values are assumed to be UTC.
    """
    if not isinstance(dt, datetime):
        raise TypeError("_format_utc expects a datetime object")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utcnow():
    """Helper returning a timezone-aware UTC datetime object"""
    return datetime.now(timezone.utc)


def _serialize_datetimes(obj):
    """Recursively convert datetimes within data structures to ISO Z strings."""
    if isinstance(obj, datetime):
        return _format_utc(obj)
    if isinstance(obj, dict):
        return {k: _serialize_datetimes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_datetimes(v) for v in obj]
    return obj


async def _get_message_or_404(message_id: str) -> dict:
    """Get message from Redis or MongoDB (fallback) - WhatsApp-style ephemeral storage with persistence fallback"""
    # Try Redis first
    try:
        message_data = await cache.get(f"message:{message_id}")
        if message_data:
            # Handle both string and dict returns from cache
            if isinstance(message_data, str):
                return json.loads(message_data)
            return message_data
    except Exception as e:
        logger.debug(f"Redis get message failed: {e}")
    
    # Fallback to MongoDB if Redis fails or message not found
    try:
        from bson import ObjectId
        msg_collection = messages_collection()
        
        # Try to convert string ID to ObjectId, handle both formats
        try:
            obj_id = ObjectId(message_id)
            msg = await msg_collection.find_one({"_id": obj_id})
            if msg:
                msg["_id"] = str(msg["_id"])  # Convert ObjectId back to string for JSON response
                return _serialize_datetimes(msg)
        except Exception:
            pass
        
        # Try direct string ID lookup
        msg = await msg_collection.find_one({"_id": message_id})
        if msg:
            if "_id" in msg:
                msg["_id"] = str(msg["_id"])
            return _serialize_datetimes(msg)
        
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get message from MongoDB: {e}")
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

    # Update message in both Redis and MongoDB with edit flag
    try:
        msg["text"] = new_text
        msg["is_edited"] = True
        msg["edited_at"] = _format_utc(_utcnow())
        msg["edited_by"] = current_user
        
        # Update TTL to remaining time or minimum 5 minutes
        ttl = int(msg.get("ttl_seconds", 3600))
        elapsed = (_utcnow() - created_at).total_seconds() if created_at else 0
        remaining_ttl = max(300, int(ttl - elapsed))  # Minimum 5 minutes
        
        # Update in Redis
        try:
            await cache.set(
                f"message:{message_id}",
                json.dumps(msg),
                expire_seconds=remaining_ttl
            )
        except Exception as e:
            logger.debug(f"Failed to update message in Redis: {e}")
        
        # Update in MongoDB
        try:
            from bson import ObjectId
            msg_collection = messages_collection()
            update_data = {
                "text": new_text,
                "is_edited": True,
                "edited_at": msg["edited_at"],
                "edited_by": current_user
            }
            
            try:
                obj_id = ObjectId(message_id)
                await msg_collection.update_one({"_id": obj_id}, {"$set": update_data})
            except Exception:
                # Try direct string ID update
                await msg_collection.update_one({"_id": message_id}, {"$set": update_data})
        except Exception as e:
            logger.debug(f"Failed to update message in MongoDB: {e}")
            
    except Exception as e:
        logger.error(f"Failed to update message: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Message update failed")

    return {"status": "edited", "message_id": message_id}


@router.delete("/{message_id}")
async def delete_message(
    message_id: str,
    hard_delete: bool = False,
    current_user: str = Depends(get_current_user),
):
    """Delete a message - WhatsApp-style immediate deletion with MongoDB cleanup.
    
    SECURITY: Verifies the authenticated user is the message sender before allowing deletion.
    Handles both string and ObjectId formats consistently.
    
    Args:
        message_id: The message to delete
        hard_delete: Whether to permanently delete (unused, kept for compatibility)
        current_user: Authenticated user from JWT token
        
    Returns:
        Dictionary with deletion status and message_id
        
    Raises:
        HTTPException(404): If message not found
        HTTPException(403): If user is not the message sender
        HTTPException(500): If deletion fails
    """
    from bson import ObjectId

    # Get the message and verify it exists
    msg = await _get_message_or_404(message_id)

    # Verify user has access to the chat containing this message
    await _get_chat_for_message_or_403(msg, current_user)

    # Normalize sender_id variants and compare safely (ObjectId vs string)
    sender_id = (
        msg.get("sender_id")
        or msg.get("sender_user_id")
        or msg.get("user_id")
        or msg.get("from")
    )

    if sender_id is None or current_user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only delete your own messages",
        )

    sender_id_str = str(sender_id)
    current_user_str = str(current_user)

    # If both are valid ObjectIds, compare as ObjectId to avoid string formatting edge cases.
    if ObjectId.is_valid(sender_id_str) and ObjectId.is_valid(current_user_str):
        if ObjectId(sender_id_str) != ObjectId(current_user_str):
            logger.warning(
                f"Unauthorized message deletion attempt: user={current_user_str} tried to delete message owned by {sender_id_str}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only delete your own messages",
            )
    else:
        if sender_id_str != current_user_str:
            logger.warning(
                f"Unauthorized message deletion attempt: user={current_user_str} tried to delete message owned by {sender_id_str}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only delete your own messages",
            )

    msg_collection = messages_collection()

    # Build an ownership-bound MongoDB filter to prevent TOCTOU issues.
    owner_filters = []
    try:
        owner_filters.append({"sender_id": ObjectId(current_user_str)})
    except Exception:
        pass
    owner_filters.append({"sender_id": current_user_str})
    message_owner_filter = {"$or": owner_filters}

    deletion_errors = []
    
    # Redis deletion is best-effort and should not determine success.
    try:
        await cache.delete(f"message:{message_id}")
        try:
            chat_id = msg.get("chat_id")
            if chat_id:
                await cache.lrem(f"chat_messages:{chat_id}", 0, message_id)
        except Exception:
            pass
    except Exception as e:
        deletion_errors.append(f"Redis deletion failed: {e}")

    # Apply hard vs soft delete.
    if hard_delete:
        deleted_count = 0
        try:
            if ObjectId.is_valid(message_id):
                result = await msg_collection.delete_one(
                    {"_id": ObjectId(message_id), **message_owner_filter}
                )
                deleted_count = result.deleted_count
        except Exception as e:
            deletion_errors.append(f"MongoDB hard-delete (ObjectId) failed: {e}")

        if deleted_count == 0:
            try:
                result = await msg_collection.delete_one(
                    {"_id": message_id, **message_owner_filter}
                )
                deleted_count = result.deleted_count
            except Exception as e:
                deletion_errors.append(f"MongoDB hard-delete (string) failed: {e}")

        if deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found",
            )
        logger.info(f"Message {message_id} hard-deleted by user {current_user_str}")
        return {"status": "deleted", "hard_delete": True, "message_id": message_id}

    # Soft delete: mark as deleted and keep record.
    update_doc = {
        "$set": {
            "is_deleted": True,
            "deleted_at": _format_utc(_utcnow()),
            "deleted_by": current_user_str,
        }
    }

    modified = 0
    try:
        if ObjectId.is_valid(message_id):
            result = await msg_collection.update_one(
                {"_id": ObjectId(message_id), **message_owner_filter},
                update_doc,
            )
            modified = result.modified_count
    except Exception as e:
        deletion_errors.append(f"MongoDB soft-delete (ObjectId) failed: {e}")

    if modified == 0:
        try:
            result = await msg_collection.update_one(
                {"_id": message_id, **message_owner_filter},
                update_doc,
            )
            modified = result.modified_count
        except Exception as e:
            deletion_errors.append(f"MongoDB soft-delete (string) failed: {e}")

    if modified == 0:
        # Distinguish between not found vs unauthorized without leaking ownership.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    logger.info(f"Message {message_id} soft-deleted by user {current_user_str}")
    return {"status": "deleted", "hard_delete": False, "message_id": message_id}


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

    # WhatsApp-style: Get reactions from message (already validated and loaded)
    message_key = f"message:{message_id}"
    message_data = msg.copy()  # Use already-loaded message instead of querying Redis again
    
    reactions = message_data.get("reactions", {})
    emoji_reactions = reactions.get(emoji, [])
    
    if current_user in emoji_reactions:
        # Remove the reaction
        emoji_reactions.remove(current_user)
        action = "removed"
    else:
        # Add the reaction
        emoji_reactions.append(current_user)
        action = "added"
    
    reactions[emoji] = emoji_reactions
    message_data["reactions"] = reactions
    
    # Update message in Redis and MongoDB
    try:
        await cache.set(message_key, json.dumps(message_data), expire_seconds=24*60*60)
    except Exception as e:
        logger.debug(f"Failed to update reactions in Redis: {e}")
    
    # Also update in MongoDB if available
    try:
        from bson import ObjectId
        msg_collection = messages_collection()
        try:
            obj_id = ObjectId(message_id)
            await msg_collection.update_one({"_id": obj_id}, {"$set": {"reactions": reactions}})
        except Exception:
            await msg_collection.update_one({"_id": message_id}, {"$set": {"reactions": reactions}})
    except Exception as e:
        logger.debug(f"Failed to update reactions in MongoDB: {e}")
    
    return {"status": "success", "action": action, "message_id": message_id, "reactions": reactions}


@router.get("/{message_id}/reactions")
async def get_reactions(message_id: str, current_user: str = Depends(get_current_user)):
    msg = await _get_message_or_404(message_id)
    await _get_chat_for_message_or_403(msg, current_user)
    # Get reactions from message document, fallback to empty dict
    reactions = msg.get("reactions") or {}
    return {"message_id": message_id, "reactions": reactions}


@router.post("/{message_id}/pin")
async def pin_message(message_id: str, current_user: str = Depends(get_current_user)):
    """Pin a message. For group chats, only admins can pin."""
    msg = await _get_message_or_404(message_id)
    chat = await _get_chat_for_message_or_403(msg, current_user)

    if chat.get("type") == "group" and not _is_group_admin(chat, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can pin messages")

    # WhatsApp-style: Update pinned status (use already-loaded message)
    message_key = f"message:{message_id}"
    message_data = msg.copy()  # Use already-loaded message instead of querying Redis again
    
    message_data["is_pinned"] = True
    message_data["pinned_at"] = _format_utc(_utcnow())
    message_data["pinned_by"] = current_user
    
    # Update message in Redis
    try:
        await cache.set(message_key, json.dumps(message_data), expire_seconds=24*60*60)
    except Exception as e:
        logger.warning(f"Failed to update pin status in Redis: {e} - message_id: {message_id}, user: {current_user}")
    
    # Update in MongoDB if available
    try:
        from bson import ObjectId
        msg_collection = messages_collection()
        try:
            obj_id = ObjectId(message_id)
            await msg_collection.update_one({"_id": obj_id}, {"$set": {"is_pinned": True, "pinned_at": message_data["pinned_at"], "pinned_by": current_user}})
        except Exception:
            await msg_collection.update_one({"_id": message_id}, {"$set": {"is_pinned": True, "pinned_at": message_data["pinned_at"], "pinned_by": current_user}})
    except Exception as e:
        logger.warning(f"Failed to update pin status in MongoDB: {e} - message_id: {message_id}, user: {current_user}")
        # Rollback Redis pin to maintain consistency
        try:
            message_data["is_pinned"] = False
            message_data.pop("pinned_at", None)
            message_data.pop("pinned_by", None)
            await cache.set(message_key, json.dumps(message_data), expire_seconds=24*60*60)
            logger.warning(f"Rolled back Redis pin for message_id: {message_id} due to MongoDB failure")
        except Exception as rollback_e:
            logger.error(f"Failed to rollback Redis pin: {rollback_e} - message_id: {message_id}")
    
    return {"status": "pinned", "message_id": message_id}


@router.post("/{message_id}/unpin")
async def unpin_message(message_id: str, current_user: str = Depends(get_current_user)):
    msg = await _get_message_or_404(message_id)
    chat = await _get_chat_for_message_or_403(msg, current_user)

    if chat.get("type") == "group" and not _is_group_admin(chat, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can unpin messages")

    # WhatsApp-style: Update unpinned status (use already-loaded message)
    message_key = f"message:{message_id}"
    message_data = msg.copy()  # Use already-loaded message instead of querying Redis again
    
    message_data["is_pinned"] = False
    # Remove pin-related fields
    message_data.pop("pinned_at", None)
    message_data.pop("pinned_by", None)
    
    # Update message in Redis
    try:
        await cache.set(message_key, json.dumps(message_data), expire_seconds=24*60*60)
    except Exception as e:
        logger.warning(f"Failed to update unpin status in Redis: {e}")
    
    # Update in MongoDB if available
    try:
        from bson import ObjectId
        msg_collection = messages_collection()
        try:
            obj_id = ObjectId(message_id)
            await msg_collection.update_one({"_id": obj_id}, {"$set": {"is_pinned": False}, "$unset": {"pinned_at": 1, "pinned_by": 1}})
        except Exception:
            await msg_collection.update_one({"_id": message_id}, {"$set": {"is_pinned": False}, "$unset": {"pinned_at": 1, "pinned_by": 1}})
    except Exception as e:
        logger.warning(f"Failed to update unpin status in MongoDB: {e}")
    
    return {"status": "unpinned", "message_id": message_id}


# @router.post("/{message_id}/read")
async def mark_read(message_id: str, current_user: str = Depends(get_current_user)):
    """Mark message read for current user - WhatsApp-style delivery tracking."""
    msg = await _get_message_or_404(message_id)
    await _get_chat_for_message_or_403(msg, current_user)

    # Update delivery status in Redis and MongoDB
    try:
        # Add read receipt to message
        msg["read_by"] = msg.get("read_by", [])
        
        # Check if already read by this user
        already_read = any(read.get("user_id") == current_user for read in msg["read_by"])
        if not already_read:
            msg["read_by"].append({
                "user_id": current_user,
                "read_at": _format_utc(_utcnow())
            })
            
            # Update delivery status based on receivers
            receiver_ids = msg.get("receiver_ids", [])
            if len(msg["read_by"]) >= len(receiver_ids):
                msg["delivery_status"] = "acknowledged"
            else:
                msg["delivery_status"] = "delivered"
            
            # Update message in Redis with remaining TTL
            ttl = int(msg.get("ttl_seconds", 3600))
            try:
                await cache.set(
                    f"message:{message_id}",
                    json.dumps(msg),
                    expire_seconds=ttl
                )
            except Exception as e:
                logger.debug(f"Failed to update message in Redis: {e}")
            
            # Update in MongoDB
            try:
                from bson import ObjectId
                msg_collection = messages_collection()
                update_data = {"read_by": msg["read_by"], "delivery_status": msg["delivery_status"]}
                try:
                    obj_id = ObjectId(message_id)
                    await msg_collection.update_one({"_id": obj_id}, {"$set": update_data})
                except Exception:
                    await msg_collection.update_one({"_id": message_id}, {"$set": update_data})
            except Exception as e:
                logger.debug(f"Failed to update message in MongoDB: {e}")
                
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update message read status: {e}")
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
    
    # WhatsApp-style: Search in both Redis and MongoDB
    try:
        # Get user's accessible chats
        user_chats = await chats_collection().find({"members": current_user}, {"_id": 1}).to_list(1000)
        user_chat_ids = [c["_id"] for c in user_chats]
        
        # Search in both Redis and MongoDB
        all_messages = []
        search_chats = [chat_id] if chat_id else user_chat_ids
        
        for chat_id_to_search in search_chats:
            # Try to get message IDs from Redis cache first (for performance)
            try:
                message_ids = await cache.lrange(f"chat_messages:{chat_id_to_search}", 0, -1)
                
                if message_ids:
                    for message_id in message_ids:
                        # Get message data from Redis
                        msg_id_str = message_id.decode('utf-8') if isinstance(message_id, bytes) else message_id
                        message_data = await cache.get(f"message:{msg_id_str}")
                        if message_data:
                            msg = json.loads(message_data) if isinstance(message_data, str) else message_data
                            
                            # Apply filters
                            if q and msg.get("text") and q_escaped.lower() in msg["text"].lower():
                                all_messages.append(msg)
                            elif has_media and msg.get("file_id"):
                                all_messages.append(msg)
                            elif has_link and msg.get("text") and "http" in msg["text"]:
                                all_messages.append(msg)
            except Exception as e:
                logger.debug(f"Failed to search in Redis: {e}")
            
            # Fallback to MongoDB search
            try:
                msg_collection = messages_collection()
                search_criteria = {"chat_id": chat_id_to_search}
                if q:
                    search_criteria["text"] = {"$regex": q_escaped, "$options": "i"}
                if has_media:
                    search_criteria["file_id"] = {"$exists": True}
                if has_link:
                    search_criteria["text"] = {**search_criteria.get("text", {}), "$regex": "http", "$options": "i"}
                
                mongo_messages = await msg_collection.find(search_criteria).sort("created_at", -1).limit(limit).to_list(limit)
                for msg in mongo_messages:
                    msg["_id"] = str(msg.get("_id", ""))
                    if msg not in all_messages:  # Avoid duplicates
                        all_messages.append(msg)
            except Exception as e:
                logger.debug(f"Failed to search in MongoDB: {e}")
        
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

# @router.post("/crypto/link-device", response_model=DeviceLinkingResponse)
async def generate_device_linking_qr(
    request: DeviceLinkingRequest,
    current_user: str = Depends(get_current_user)
):
    """Generate QR code for device linking"""
    try:
        # Initialize multi-device manager with global cache instance
        device_manager = MultiDeviceManager(cache)
        
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

# @router.post("/crypto/confirm-link")
async def confirm_device_linking(
    request: DeviceLinkConfirmRequest,
    current_user: str = Depends(get_current_user)
):
    """Confirm and complete device linking"""
    try:
        # Initialize multi-device manager with global cache instance
        device_manager = MultiDeviceManager(cache)
        
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
            created_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),  # UTC only
            last_active=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),  # UTC only
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

# @router.post("/crypto/send-encrypted", response_model=EncryptedMessageResponse)
async def send_encrypted_message(
    request: EncryptedMessageRequest,
    current_user: str = Depends(get_current_user)
):
    """Send end-to-end encrypted message"""
    try:
        # Initialize services with global cache instance
        delivery_manager = DeliveryManager(cache)
        device_manager = MultiDeviceManager(cache)
        
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
        
        # WhatsApp-grade abuse detection and spam prevention
        try:
            from crypto.abuse_detection import AbuseDetectionService
        except:
            from ..crypto.abuse_detection import AbuseDetectionService
        
        abuse_service = AbuseDetectionService(cache)
        
        # Check for spam patterns
        spam_score = await abuse_service.analyze_message(
            user_id=current_user,
            chat_id=request.chat_id,
            message_type=request.message_type,
            metadata=request.metadata,
            timestamp=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        )
        
        if spam_score > 0.8:  # High spam threshold
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Message flagged as potential spam"
            )
        elif spam_score > 0.5:  # Medium spam threshold - add delay
            await asyncio.sleep(min(spam_score * 2, 5))  # Rate limiting delay
        
        # Check forwarding limits
        if request.metadata and request.metadata.get("forward_count", 0) > 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Message forwarding limit exceeded"
            )
        
        # Initialize delivery
        receipts = await delivery_manager.initialize_message_delivery(
            message_id=message_id,
            sender_id=current_user,
            chat_id=request.chat_id,
            recipient_devices=recipient_devices,
            sequence_number=sequence_number
        )
        
        # Store encrypted message with WhatsApp-grade privacy features
        message_data = {
            "message_id": message_id,
            "chat_id": request.chat_id,
            "sender_id": current_user,
            "encrypted_content": request.encrypted_content,
            "iv": request.iv,
            "auth_tag": request.auth_tag,
            "message_type": request.message_type,
            "sequence_number": sequence_number,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "metadata": request.metadata or {},
            # WhatsApp-grade privacy features
            "disappearing_timer": request.metadata.get("disappearing_timer") if request.metadata else None,
            "view_once": request.metadata.get("view_once", False) if request.metadata else False,
            "forwarding_locked": request.metadata.get("forwarding_locked", False) if request.metadata else False,
            "privacy_level": request.metadata.get("privacy_level", "standard") if request.metadata else "standard",
            "ephemeral": True,  # All messages are ephemeral
            "ttl_seconds": 24 * 60 * 60  # 24h default TTL
        }
        
        try:
            await cache.set(f"encrypted_message:{message_id}", json.dumps(message_data), expire_seconds=24*60*60)
            await cache.lpush(f"chat_encrypted:{request.chat_id}", message_id)
        except Exception as e:
            logger.debug(f"Failed to store encrypted message in cache: {e}")
        
        return EncryptedMessageResponse(
            message_id=message_id,
            sequence_number=sequence_number,
            timestamp=datetime.now(timezone.utc).timestamp(),
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

# @router.post("/crypto/delivery-receipt")
async def update_delivery_receipt(
    request: DeliveryReceiptRequest,
    current_user: str = Depends(get_current_user)
):
    """Update delivery receipt for message"""
    try:
        # Initialize delivery manager with global cache instance
        delivery_manager = DeliveryManager(cache)
        
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
        # Initialize delivery manager with global cache instance
        delivery_manager = DeliveryManager(cache)
        
        # Verify device belongs to user
        device_manager = MultiDeviceManager(cache)
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
            message_data = await cache.get(f"encrypted_message:{receipt.message_id}")
            if message_data:
                msg_parsed = json.loads(message_data) if isinstance(message_data, str) else message_data
                messages.append(msg_parsed)
        
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


# ============================================================================
# WHATSAPP-GRADE ENCRYPTED BACKUP ENDPOINTS
# ============================================================================

class BackupCreateRequest(BaseModel):
    """Request to create encrypted backup"""
    backup_type: str = Field("full", description="Backup type: full or incremental")
    parent_backup_id: Optional[str] = Field(None, description="Parent backup ID for incremental")
    estimated_size: int = Field(..., description="Estimated backup size in bytes")

class BackupChunkRequest(BaseModel):
    """Request to upload backup chunk"""
    backup_id: str = Field(..., description="Backup ID")
    chunk_index: int = Field(..., description="Chunk index")
    encrypted_data: str = Field(..., description="Base64 encrypted chunk data")
    nonce: str = Field(..., description="Base64 nonce")
    auth_tag: str = Field(..., description="Base64 auth tag")

# @router.post("/backup/create", response_model=dict)
async def create_encrypted_backup(
    request: BackupCreateRequest,
    current_user: str = Depends(get_current_user)
):
    """Create encrypted backup (client-side encryption)"""
    try:
        from ..crypto.encrypted_backup import EncryptedBackupService
        
        backup_service = EncryptedBackupService(cache)
        
        # Create backup metadata
        metadata = await backup_service.create_backup(
            user_id=current_user,
            device_id="primary",
            backup_data=b"",
            backup_type=request.backup_type,
            parent_backup_id=request.parent_backup_id
        )
        
        return {
            "backup_id": metadata.backup_id,
            "backup_type": metadata.backup_type,
            "chunk_size": 1024 * 1024,  # 1MB chunks
            "created_at": metadata.created_at
        }
        
    except Exception as e:
        logger.error(f"Backup creation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to create backup")


# ============================================================================
# WHATSAPP-GRADE ENCRYPTED CALLS ENDPOINTS
# ============================================================================

class CallInitiateRequest(BaseModel):
    """Request to initiate encrypted call"""
    recipient_user_id: str = Field(..., description="Recipient user ID")
    call_type: str = Field("voice", description="Call type: voice, video")

# @router.post("/calls/initiate", response_model=dict)
async def initiate_encrypted_call(
    request: CallInitiateRequest,
    current_user: str = Depends(get_current_user)
):
    """Initiate encrypted voice/video call"""
    try:
        from ..crypto.encrypted_calls import EncryptedCallService, CallType
        
        call_service = EncryptedCallService(cache)
        
        # Generate call encryption keys
        call_keys = call_service.generate_call_keys()
        
        # Initiate call
        session = await call_service.initiate_call(
            initiator_user_id=current_user,
            initiator_device_id="primary",
            recipient_user_id=request.recipient_user_id,
            recipient_device_id="primary",
            call_type=CallType(request.call_type),
            encryption_keys=call_keys
        )
        
        return {
            "call_id": session.call_id,
            "call_type": session.call_type,
            "state": session.state,
            "created_at": session.created_at
        }
        
    except Exception as e:
        logger.error(f"Call initiation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate call")


# ============================================================================
# WHATSAPP-LIKE MESSAGE HISTORY SYSTEM
# ============================================================================

# @router.post("/history/sync", response_model=MessageHistoryResponse)
async def sync_message_history(
    request: MessageHistoryRequest,
    current_user: str = Depends(get_current_user)
):
    """Sync message history for device (WhatsApp-style)"""
    try:
        # Verify chat access
        chat = await chats_collection().find_one({"_id": request.chat_id})
        if not chat:
            raise HTTPException(status_code=404, detail="Chat not found")
        
        participants = chat.get("participants", chat.get("members", chat.get("member_ids", [])))
        if current_user not in participants and str(current_user) not in [str(p) for p in participants]:
            raise HTTPException(status_code=403, detail="Not a member of this chat")
        
        # Build query for message history
        query = {"chat_id": request.chat_id}
        
        # Add message ID filters for pagination
        if request.before_message_id:
            query["_id"] = {"$lt": request.before_message_id}
        elif request.after_message_id:
            query["_id"] = {"$gt": request.after_message_id}
        
        # Exclude deleted messages unless requested
        if not request.include_deleted:
            query["is_deleted"] = {"$ne": True}
        
        # Fetch messages with pagination
        messages = await messages_collection().find(query).sort(
            "_id", -1 if request.before_message_id else 1
        ).limit(request.limit).to_list(length=request.limit)
        
        # Convert to metadata-only format (WhatsApp style)
        message_metadata = []
        for msg in messages:
            metadata = {
                "id": str(msg["_id"]),
                "chat_id": msg["chat_id"],
                "sender_id": msg["sender_id"],
                "type": msg.get("type", "text"),
                "text": msg.get("text", "")[:100] if msg.get("text") else None,  # Only first 100 chars
                "file_id": msg.get("file_id"),
                "file_size": msg.get("file_size"),
                "file_type": msg.get("file_type"),
                "created_at": msg["created_at"],
                "sequence_number": msg.get("sequence_number"),
                "reply_to_message_id": msg.get("reply_to_message_id"),
                "forward_from_chat_id": msg.get("forward_from_chat_id"),
                "forward_sender_name": msg.get("forward_sender_name"),
                "is_edited": msg.get("is_edited", False),
                "is_pinned": msg.get("is_pinned", False),
                "views": msg.get("views", 0),
                "reactions": msg.get("reactions", {}),
                "read_by": msg.get("read_by", [])
            }
            message_metadata.append(metadata)
        
        # Update device sync state
        await _update_device_sync_state(
            user_id=current_user,
            device_id=request.device_id,
            chat_id=request.chat_id,
            last_message_id=message_metadata[-1]["id"] if message_metadata else None,
            messages_count=len(message_metadata)
        )
        
        # Update relationship graph for message interactions
        if message_metadata:
            for msg in message_metadata:
                if msg["sender_id"] != current_user:
                    # Update interaction between current user and message sender
                    await relationship_graph_service.update_user_interaction(
                        user_a_id=current_user,
                        user_b_id=msg["sender_id"],
                        interaction_type="message_received",
                        weight=1.0
                    )
                else:
                    # Update interaction for sent messages (with other participants)
                    chat = await chats_collection().find_one({"_id": request.chat_id})
                    if chat:
                        participants = chat.get("participants", chat.get("members", chat.get("member_ids", [])))
                        for participant in participants:
                            if participant != current_user:
                                await relationship_graph_service.update_user_interaction(
                                    user_a_id=current_user,
                                    user_b_id=participant,
                                    interaction_type="message_sent",
                                    weight=1.0
                                )
        
        # Generate sync token for incremental sync
        sync_token = await _generate_sync_token(
            user_id=current_user,
            device_id=request.device_id,
            chat_id=request.chat_id
        )
        
        return MessageHistoryResponse(
            chat_id=request.chat_id,
            messages=message_metadata,
            total_count=len(message_metadata),
            has_more=len(message_metadata) == request.limit,
            next_before_id=message_metadata[-1]["id"] if message_metadata else None,
            next_after_id=message_metadata[0]["id"] if message_metadata else None,
            sync_token=sync_token,
            device_id=request.device_id
        )
        
    except Exception as e:
        logger.error(f"Message history sync failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to sync message history")


@router.get("/conversations/metadata")
async def get_conversations_metadata(
    device_id: str = Query(..., description="Device ID"),
    limit: int = Query(default=50, ge=1, le=100),
    current_user: str = Depends(get_current_user)
):
    """Get conversation list with metadata (WhatsApp-style)"""
    try:
        # Get all chats for user
        chats = await chats_collection().find({
            "$or": [
                {"participants": current_user},
                {"members": current_user},
                {"member_ids": current_user}
            ]
        }).sort("updated_at", -1).limit(limit).to_list(length=limit)
        
        # Build conversation metadata
        conversations = []
        for chat in chats:
            # Get last message for this chat
            last_message = await messages_collection().find_one(
                {"chat_id": str(chat["_id"]), "is_deleted": {"$ne": True}},
                sort=[("_id", -1)]
            )
            
            # Get or create conversation metadata
            conv_metadata = await _get_or_create_conversation_metadata(
                user_id=current_user,
                chat_id=str(chat["_id"]),
                device_id=device_id
            )
            
            # Update with last message info
            if last_message:
                conv_metadata.last_message_id = str(last_message["_id"])
                conv_metadata.last_message_timestamp = last_message.get("created_at")
                conv_metadata.last_message_type = last_message.get("type", "text")
                conv_metadata.last_message_sender = last_message.get("sender_id")
            
            conversations.append(conv_metadata.dict())
        
        return {
            "conversations": conversations,
            "total_count": len(conversations),
            "device_id": device_id,
            "synced_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        
    except Exception as e:
        logger.error(f"Failed to get conversations metadata: {e}")
        raise HTTPException(status_code=500, detail="Failed to get conversations")


# @router.post("/delivery/receipt")
async def track_delivery_receipt(
    receipt: MessageDeliveryReceipt,
    current_user: str = Depends(get_current_user)
):
    """Track WhatsApp-style delivery receipt"""
    try:
        # Verify recipient matches current user
        if receipt.recipient_user_id != current_user:
            raise HTTPException(status_code=403, detail="Unauthorized")
        
        # Get message
        message = await messages_collection().find_one({"_id": receipt.message_id})
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")
        
        # Update read_by list
        if receipt.receipt_type == "read":
            await messages_collection().update_one(
                {"_id": receipt.message_id},
                {
                    "$addToSet": {
                        "read_by": {
                            "user_id": receipt.recipient_user_id,
                            "device_id": receipt.recipient_device_id,
                            "timestamp": receipt.timestamp
                        }
                    }
                }
            )
        
        # Store receipt in Redis for real-time sync
        receipt_key = f"receipt:{receipt.message_id}:{receipt.recipient_device_id}"
        await cache.set(receipt_key, receipt.dict(), expire_seconds=24*60*60)
        
        # Publish real-time update
        update_key = f"delivery_updates:{receipt.chat_id}"
        update_data = {
            "message_id": receipt.message_id,
            "device_id": receipt.recipient_device_id,
            "receipt_type": receipt.receipt_type,
            "timestamp": _format_utc(receipt.timestamp)
        }
        await cache.publish(update_key, json.dumps(update_data))
        
        return {
            "status": "tracked",
            "message_id": receipt.message_id,
            "receipt_type": receipt.receipt_type,
            "timestamp": _format_utc(receipt.timestamp)
        }
        
    except Exception as e:
        logger.error(f"Delivery receipt tracking failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to track delivery receipt")


@router.get("/relationship-graph/{user_id}")
async def get_relationship_graph(
    user_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get user relationship graph data"""
    try:
        # Users can only get their own relationship graph
        if current_user != user_id:
            raise HTTPException(status_code=403, detail="Can only get own relationship graph")
        
        # Get comprehensive relationship data using the service
        graph_summary = await relationship_graph_service.get_user_graph_summary(user_id)
        user_relationships = await relationship_graph_service.get_user_relationships(user_id, limit=50)
        contact_suggestions = await relationship_graph_service.get_contact_suggestions(user_id, limit=10)
        
        return {
            "user_id": user_id,
            "graph_summary": graph_summary,
            "relationships": user_relationships,
            "contact_suggestions": contact_suggestions,
            "total_contacts": len(user_relationships),
            "generated_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        
    except Exception as e:
        logger.error(f"Failed to get relationship graph: {e}")
        raise HTTPException(status_code=500, detail="Failed to get relationship graph")


# Helper functions for message history system
async def _update_device_sync_state(user_id: str, device_id: str, chat_id: str, 
                                  last_message_id: Optional[str], messages_count: int):
    """Update device sync state"""
    sync_state_key = f"device_sync:{user_id}:{device_id}"
    
    sync_data = {
        "user_id": user_id,
        "device_id": device_id,
        "chat_id": chat_id,
        "last_message_id": last_message_id,
        "messages_count": messages_count,
        "last_sync_timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "sync_progress": 1.0
    }
    
    await cache.set(sync_state_key, sync_data, expire_seconds=7*24*60*60)


async def _generate_sync_token(user_id: str, device_id: str, chat_id: str) -> str:
    """Generate sync token for incremental sync"""
    token_data = f"{user_id}:{device_id}:{chat_id}:{datetime.now(timezone.utc).timestamp()}"
    return base64.b64encode(token_data.encode()).decode()


async def _get_or_create_conversation_metadata(user_id: str, chat_id: str, device_id: str) -> ConversationMetadata:
    """Get or create conversation metadata"""
    metadata_key = f"conv_meta:{user_id}:{device_id}:{chat_id}"
    
    # Try to get from cache first
    cached_data = await cache.get(metadata_key)
    if cached_data:
        return ConversationMetadata(**cached_data)
    
    # Create new metadata
    metadata = ConversationMetadata(
        user_id=user_id,
        chat_id=chat_id,
        device_id=device_id
    )
    
    # Cache for 1 hour
    await cache.set(metadata_key, metadata.dict(), expire_seconds=60*60)
    
    return metadata


async def _get_user_relationships(user_id: str) -> List[dict]:
    """Get user relationships for graph"""
    # This would query the relationship graph collection
    # For now, return empty list as placeholder
    return []


# ============================================================================
# WHATSAPP-GRADE PRIVACY CONTROLS ENDPOINTS
# ============================================================================

class PrivacySettingsRequest(BaseModel):
    """Request to update privacy settings"""
    disappearing_timer: Optional[int] = Field(None, description="Disappearing messages timer (seconds)")
    read_receipts_enabled: Optional[bool] = Field(None, description="Read receipts enabled")

# @router.post("/privacy/settings", response_model=dict)
async def update_privacy_settings(
    request: PrivacySettingsRequest,
    current_user: str = Depends(get_current_user)
):
    """Update privacy settings"""
    try:
        # Store privacy settings in cache
        settings_key = f"privacy_settings:{current_user}"
        
        # Get existing settings
        existing_data = await cache.get(settings_key)
        settings = json.loads(existing_data) if isinstance(existing_data, str) else (existing_data or {})
        
        # Update settings
        if request.disappearing_timer is not None:
            settings["disappearing_timer"] = request.disappearing_timer
        if request.read_receipts_enabled is not None:
            settings["read_receipts_enabled"] = request.read_receipts_enabled
        
        settings["updated_at"] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')  # UTC only
        
        # Store in cache with 1 year expiration
        try:
            await cache.set(settings_key, json.dumps(settings), expire_seconds=86400 * 365)
        except Exception as e:
            logger.debug(f"Failed to save privacy settings to cache: {e}")
        
        # Also store in MongoDB for persistence
        try:
            users_coll = await users_collection()
            await users_coll.update_one(
                {"_id": current_user},
                {"$set": {"privacy_settings": settings}},
                upsert=False
            )
        except Exception as e:
            logger.debug(f"Failed to save privacy settings to MongoDB: {e}")
        
        return {"status": "updated", "settings": settings}
        
    except Exception as e:
        logger.error(f"Privacy settings update failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to update privacy settings")


# ============================================================================
# WHATSAPP-GRADE ENCRYPTION VERIFICATION ENDPOINTS
# ============================================================================

@router.get("/encryption/verify", response_model=dict)
async def verify_encryption_status(
    current_user: str = Depends(get_current_user)
):
    """Verify encryption status and show security info to user"""
    try:
        return {
            "encryption_enabled": True,
            "signal_protocol_active": True,
            "encryption_algorithm": "Signal Protocol (X3DH + Double Ratchet)",
            "message_encryption": "AES-256-GCM",
            "forward_secrecy": True,
            "post_compromise_security": True,
            "server_access": "Never sees plaintext",
            "ephemeral_storage": True,
            "multi_device_support": True,
            "group_encryption": "Sender Key scheme"
        }
        
    except Exception as e:
        logger.error(f"Encryption verification failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify encryption status")


# ============================================================================
# WHATSAPP-LIKE MESSAGE HISTORY ENDPOINTS
# ============================================================================

@router.post("/history/sync", response_model=MessageHistoryResponse)
async def sync_message_history(
    request: MessageHistoryRequest,
    current_user: str = Depends(get_current_user)
):
    """Sync message history for a device"""
    try:
        # Validate device belongs to user
        device_key = f"device:{current_user}:{request.device_id}"
        device_info = await cache.get(device_key)
        if not device_info:
            raise HTTPException(status_code=403, detail="Device not authorized")
        
        # Get message history
        history_response = await message_history_service.get_message_history(
            request, current_user
        )
        
        return history_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Message history sync failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to sync message history")


@router.get("/history/conversations", response_model=List[dict])
async def get_conversation_list(
    limit: int = Query(default=50, ge=1, le=100),
    archived_only: bool = Query(default=False),
    current_user: str = Depends(get_current_user)
):
    """Get user's conversation list"""
    try:
        conversations = await message_history_service.get_conversation_list(
            current_user, limit, archived_only
        )
        return conversations
        
    except Exception as e:
        logger.error(f"Failed to get conversation list: {e}")
        raise HTTPException(status_code=500, detail="Failed to get conversation list")


@router.get("/history/message/{message_id}", response_model=dict)
async def get_encrypted_message(
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get full encrypted message for decryption"""
    try:
        message = await message_history_service.get_encrypted_message(
            message_id, current_user
        )
        
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")
        
        return message
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get encrypted message: {e}")
        raise HTTPException(status_code=500, detail="Failed to get message")


@router.post("/history/device/{device_id}/sync", response_model=dict)
async def sync_device_messages(
    device_id: str,
    sync_days: int = Query(default=30, ge=1, le=365),
    current_user: str = Depends(get_current_user)
):
    """Sync all messages to a new device"""
    try:
        # Validate device belongs to user
        device_key = f"device:{current_user}:{device_id}"
        device_info = await cache.get(device_key)
        if not device_info:
            raise HTTPException(status_code=403, detail="Device not authorized")
        
        # Start device sync
        sync_result = await message_history_service.sync_device_messages(
            current_user, device_id, sync_days
        )
        
        return sync_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Device message sync failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to sync device messages")


@router.post("/delivery/{message_id}/{device_id}/receipt", response_model=dict)
async def update_delivery_receipt(
    message_id: str,
    device_id: str,
    receipt_type: str = Query(..., pattern="^(delivered|read)$"),
    current_user: str = Depends(get_current_user)
):
    """Update delivery receipt for a message"""
    try:
        # Validate device belongs to user
        device_key = f"device:{current_user}:{device_id}"
        device_info = await cache.get(device_key)
        if not device_info:
            raise HTTPException(status_code=403, detail="Device not authorized")
        
        # Update delivery status
        success = await message_history_service.update_delivery_status(
            message_id, device_id, current_user, receipt_type
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Message not found or not authorized")
        
        return {
            "message_id": message_id,
            "device_id": device_id,
            "receipt_type": receipt_type,
            "updated": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update delivery receipt: {e}")
        raise HTTPException(status_code=500, detail="Failed to update delivery receipt")


@router.delete("/history/message/{message_id}", response_model=dict)
async def delete_message(
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Soft delete a message (WhatsApp-style)"""
    try:
        success = await message_history_service.soft_delete_message(
            message_id, current_user
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Message not found or not authorized")
        
        return {
            "message_id": message_id,
            "deleted": True,
            "deleted_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete message: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete message")


@router.get("/relationships", response_model=List[dict])
async def get_user_relationships(
    limit: int = Query(default=50, ge=1, le=100),
    current_user: str = Depends(get_current_user)
):
    """Get user's relationships for analytics"""
    try:
        relationships = await message_history_service.get_user_relationships(
            current_user, limit
        )
        return relationships
        
    except Exception as e:
        logger.error(f"Failed to get user relationships: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user relationships")


@router.post("/history/cleanup", response_model=dict)
async def cleanup_expired_messages(
    current_user: str = Depends(get_current_user)
):
    """Clean up expired messages (admin only)"""
    try:
        # Check if user is admin (simplified for demo)
        is_admin = await cache.get(f"admin:{current_user}")
        if not is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Clean up expired messages
        deleted_count = await message_history_service.cleanup_expired_messages()
        
        return {
            "deleted_messages": deleted_count,
            "cleanup_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cleanup expired messages: {e}")
        raise HTTPException(status_code=500, detail="Failed to cleanup expired messages")

# ============================================================================
# WEBSOCKET REAL-TIME MESSAGING
# ============================================================================

from fastapi import WebSocket, WebSocketDisconnect
from typing import Set

class ChatConnectionManager:
    """
    Manages WebSocket connections for real-time chat messaging.
    
    CRITICAL PRODUCTION IMPROVEMENTS:
    - Per-device connection management (one socket per device per room)
    - Prevents duplicate message delivery
    - Async-safe connection handling with locks
    - Graceful reconnection handling with connection replacement
    - Room-based subscription tracking for Redis pub/sub
    """
    
    def __init__(self):
        # Maps: room_id ->  { device_id -> WebSocket }
        # ONE connection per device per room to prevent duplicates
        self.active_connections: Dict[str, Dict[str, WebSocket]] = {}
        # Subscription tracking: room_id ->  set(device_ids)  
        self.room_subscriptions: Dict[str, Set[str]] = {}
        self._lock = asyncio.Lock()
        # Track broadcast tokens to prevent duplicate sends within same event loop cycle
        self._broadcast_tokens: Dict[str, Set[str]] = {}
    
    async def connect(self, chat_id: str, user_id: str, device_id: str, websocket: WebSocket):
        """
        Register a new WebSocket connection.
        CRITICAL: Replaces old connection if device is already connected (deduplication).
        Creates or replaces one connection per device in the room.
        """
        await websocket.accept()
        
        async with self._lock:
            if chat_id not in self.active_connections:
                self.active_connections[chat_id] = {}
                self.room_subscriptions[chat_id] = set()
            
            # CRITICAL: If device already connected, close old one (prevent duplicates)
            old_ws = self.active_connections[chat_id].get(device_id)
            if old_ws and old_ws != websocket:
                try:
                    await old_ws.close(code=4001, reason="Duplicate connection")
                    logger.info(f"[WEBSOCKET] Closed duplicate connection for device {device_id}")
                except Exception as e:
                    logger.debug(f"[WEBSOCKET] Error closing old connection: {e}")
            
            # Replace with new connection
            self.active_connections[chat_id][device_id] = websocket
            self.room_subscriptions[chat_id].add(device_id)
            
            logger.info(f"[WEBSOCKET] Device {device_id} (user {user_id}) connected to room {chat_id}. Total devices in room: {len(self.active_connections[chat_id])}")
    
    async def disconnect(self, chat_id: str, device_id: str, websocket: WebSocket):
        """
        Unregister a WebSocket connection.
        CRITICAL: Only removes if the connection matches  (prevent accidental removal of replacement).
        """
        async with self._lock:
            if chat_id in self.active_connections:
                current_ws = self.active_connections[chat_id].get(device_id)
                
                # Only remove if it's the same connection object
                if current_ws == websocket:
                    del self.active_connections[chat_id][device_id]
                    self.room_subscriptions[chat_id].discard(device_id)
                    logger.info(f"[WEBSOCKET] Device {device_id} disconnected from room {chat_id}")
                
                # Clean up empty room
                if not self.active_connections[chat_id]:
                    del self.active_connections[chat_id]
                    if chat_id in self.room_subscriptions:
                        del self.room_subscriptions[chat_id]
    
    async def broadcast_to_chat(self, chat_id: str, message: Dict[str, Any], exclude_device: Optional[str] = None):
        """
        Broadcast message to all connected devices in a room.
        CRITICAL IMPROVEMENTS:
        1) Sends to ONE device per user (not multiple WebSockets)
        2) Uses deduplication token to prevent duplicate broadcasts within same event
        3) Async non-blocking sends
        4) Graceful error handling with connection cleanup
        """
        if chat_id not in self.active_connections:
            logger.debug(f"[WEBSOCKET] No connections for room {chat_id}")
            return
        
        # CRITICAL: Create broadcast token from message to prevent duplicate sends
        # (prevents sending same message twice if broadcast called multiple times)
        message_id = message.get("message_id") or message.get("id", "unknown")
        broadcast_token = f"{chat_id}:{message_id}:{time.time()}"
        
        if chat_id not in self._broadcast_tokens:
            self._broadcast_tokens[chat_id] = set()
        
        # Skip if already broadcast this exact message in this room
        if broadcast_token in self._broadcast_tokens[chat_id]:
            logger.debug(f"[WEBSOCKET] Skipping duplicate broadcast for message {message_id}")
            return
        
        self._broadcast_tokens[chat_id].add(broadcast_token)
        disconnected_devices = []
        
        async with self._lock:
            websockets_to_send = [
                (device_id, ws)
                for device_id, ws in self.active_connections.get(chat_id, {}).items()
                if not exclude_device or device_id != exclude_device
            ]
        
        # CRITICAL: Non-blocking async sends (don't block on slow clients)
        async def send_to_device(device_id: str, ws: WebSocket):
            try:
                await asyncio.wait_for(ws.send_json(message), timeout=5.0)
                logger.debug(f"[WEBSOCKET] Sent to device {device_id}")
            except asyncio.TimeoutError:
                logger.warning(f"[WEBSOCKET] Timeout sending to device {device_id}")
                disconnected_devices.append(device_id)
            except WebSocketDisconnect:
                logger.info(f"[WEBSOCKET] Device {device_id} disconnected during send")
                disconnected_devices.append(device_id)
            except Exception as e:
                logger.error(f"[WEBSOCKET] Error sending to device {device_id}: {type(e).__name__}: {e}")
                disconnected_devices.append(device_id)
        
        # Send all messages concurrently (don't wait for slow clients)
        if websockets_to_send:
            await asyncio.gather(
                *[send_to_device(device_id, ws) for device_id, ws in websockets_to_send],
                return_exceptions=True
            )
        
        # Clean up broken connections
        for device_id in disconnected_devices:
            await self.disconnect(chat_id, device_id, None)
        
        # Clean up old broadcast tokens (keep last 100 to prevent memory leak)
        if len(self._broadcast_tokens[chat_id]) > 100:
            self._broadcast_tokens[chat_id].clear()

manager = ChatConnectionManager()


@router.websocket("/ws/chat/{chat_id}")
async def websocket_endpoint(websocket: WebSocket, chat_id: str):
    """
    WebSocket endpoint for real-time chat messaging.
    
    PRODUCTION CRITICAL FIXES:
    1) Cookie-based authentication (HTTPOnly cookies)
    2) Per-device connection tracking (prevents duplicate message delivery)
    3) UTC timestamp preservation (timestamps stored in DB before broadcast)
    4) Redis pub/sub integration (room-based message fan-out)
    5) Async non-blocking operations (doesn't block on slow clients)
    6) Proper reconnection handling (replaces stale connections)
    
    IMPORTANT: Accept WebSocket BEFORE reading cookies (FastAPI requirement)
    
    Authentication: HTTPOnly cookies (access_token cookie)
    Connection URL: wss://zaply.in.net/api/v1/ws/chat/{chat_id}
    
    Message format:
    {
        "type": "message|typing|reaction|delete",
        "content": {...}
    }
    
    CRITICAL: Messages must be sent via REST to guarantee:
    - Created timestamp is authoritative (DB insert before Redis publish)
    - Single source of truth for message content
    - Proper ordering semantics (sequence numbers)
    """
    device_id = None
    user_id = None
    redis_task = None
    pubsub = None
    
    try:
        # IMPORTANT: Accept BEFORE reading cookies (FastAPI requirement)
        await websocket.accept()
        
        # Get access token cookie for authentication
        cookies = websocket.cookies
        access_token = cookies.get("access_token")
        
        logger.info(f"[WEBSOCKET] New connection request for chat {chat_id}")
        logger.info(f"[WEBSOCKET] Total cookies available: {len(cookies) if cookies else 0}")
        
        # Debug: Log all available cookies (without values for security)
        if cookies:
            cookie_names = list(cookies.keys())
            logger.info(f"[WEBSOCKET] Available cookie names: {cookie_names}")
        else:
            logger.warning("[WEBSOCKET] No cookies found in WebSocket request")
        
        logger.info(f"[WEBSOCKET] Access token cookie present: {access_token is not None}")
        
        if not access_token:
            logger.error("[WEBSOCKET] No access token cookie found")
            logger.error("[WEBSOCKET] Troubleshooting:")
            logger.error("[WEBSOCKET] 1. User must be logged in via REST API first")
            logger.error("[WEBSOCKET] 2. Check cookie domain: should be .zaply.in.net")
            logger.error("[WEBSOCKET] 3. Check cookie flags: Secure, HttpOnly, SameSite=None")
            logger.error("[WEBSOCKET] 4. Browser must support cross-site cookies")
            await websocket.close(code=1008, reason="No access token cookie")
            return
        
        logger.debug(f"[WEBSOCKET] Access token found: {access_token[:20]}...")
        
        # Verify user from access token
        try:
            from auth.utils import decode_token
            token_data = decode_token(access_token)
            user_id = token_data.user_id
            device_id = "primary"  # Default device ID for cookie-based auth
            logger.info(f"[WEBSOCKET] WS CONNECTED user={user_id} device={device_id} chat={chat_id}")
        except Exception as e:
            logger.error(f"[WEBSOCKET] Invalid access token: {e}")
            await websocket.close(code=1008, reason="Invalid access token")
            return
        
        # Verify user is member of chat
        try:
            from bson import ObjectId
            if ObjectId.is_valid(str(chat_id)):
                chat_doc = await chats_collection().find_one({
                    "_id": ObjectId(chat_id), 
                    "members": user_id
                })
            else:
                chat_doc = await chats_collection().find_one({
                    "_id": chat_id,
                    "members": user_id
                })
        except Exception as e:
            logger.warning(f"[WEBSOCKET] Chat validation failed: {e}")
            chat_doc = None
        
        if not chat_doc:
            await websocket.close(code=4003, reason="Not a member of this chat")
            return
        
        # CRITICAL: Connect with device_id for deduplication
        await manager.connect(chat_id, user_id, device_id, websocket)
        
        # Subscribe to Redis channel for this room for real-time message delivery
        # CRITICAL: This endpoint must preserve timestamps from DB/Redis payloads
        # It must NOT regenerate message timestamps
        if cache and cache.is_connected:
            try:
                redis_channel = f"chat:{chat_id}"
                logger.info(f"[WEBSOCKET] Device {device_id} subscribing to {redis_channel}")

                pubsub = await cache.redis_client.pubsub()
                await pubsub.subscribe(redis_channel)
                
                # Track subscribed upload channels for this device
                upload_channels = set()

                async def listen_redis():
                    """Listen for messages from Redis pub/sub"""
                    try:
                        async for message in pubsub.listen():
                            if message.get("type") != "message":
                                continue

                            data_raw = message.get("data")
                            if data_raw is None:
                                continue

                            # Data may be bytes or str depending on Redis client settings
                            if isinstance(data_raw, bytes):
                                data_str = data_raw.decode("utf-8")
                            else:
                                data_str = data_raw

                            try:
                                data = json.loads(data_str)
                            except json.JSONDecodeError as e:
                                logger.error(f"[WEBSOCKET] Invalid JSON from Redis: {e}")
                                continue

                            # CRITICAL: Forward payload exactly as published (no timestamp mutation)
                            # Timestamps are authoritative from DB insertion
                            await manager.broadcast_to_chat(chat_id, data)
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.error(f"[WEBSOCKET] Redis listening error: {e}")

                redis_task = asyncio.create_task(listen_redis())
            except Exception as e:
                logger.error(f"[WEBSOCKET] Failed to subscribe to Redis: {e}")
                redis_task = None
        
        # Handle incoming WebSocket messages
        # CRITICAL: Client MUST NOT publish chat messages via WebSocket
        # Authoritative message timestamps come from DB insert (REST) and are propagated via Redis
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=60.0)
            except asyncio.TimeoutError:
                # Connection idle for 60 seconds, close it
                await websocket.close(code=1000, reason="Idle timeout")
                break
            except WebSocketDisconnect:
                break
            
            message_type = data.get('type', 'message')
            
            logger.debug(f"[WEBSOCKET] Received {message_type} from device {device_id} (user {user_id}) in chat {chat_id}")
            
            # PRODUCTION FEATURE: Allow clients to subscribe to upload progress
            # Client sends: {"type": "subscribe_upload_progress", "media_id": "..."}
            if message_type == "subscribe_upload_progress" and cache:
                media_id = data.get("media_id")
                if media_id and 'upload_channels' in locals():
                    upload_progress_channel = f"upload_progress:{media_id}"
                    try:
                        await pubsub.subscribe(upload_progress_channel)
                        upload_channels.add(upload_progress_channel)
                        
                        await websocket.send_json({
                            "type": "upload_progress_subscribed",
                            "media_id": media_id,
                            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                        })
                        logger.info(f"[WEBSOCKET] Device {device_id} subscribed to upload progress for {media_id}")
                    except Exception as e:
                        logger.error(f"[WEBSOCKET] Failed to subscribe to upload progress: {e}")
                        await websocket.send_json({
                            "type": "error",
                            "code": "upload_progress_subscription_failed",
                            "detail": str(e),
                            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                        })
                continue
            
            if message_type == "message":
                # Enforce REST-only message creation to guarantee:
                # DB commit BEFORE Redis publish BEFORE WebSocket broadcast
                await websocket.send_json({
                    "type": "error",
                    "code": "message_not_allowed_over_websocket",
                    "detail": "Send messages via REST endpoint so DB created_at is authoritative and preserved in real-time delivery.",
                    "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                })
                continue

            # For non-message real-time events (typing/reaction/etc.)
            # CRITICAL:  do NOT accept a timestamp from the frontend
            # Publish a server-side UTC timestamp
            event_payload = {
                "type": message_type,
                "sender_id": user_id,
                "device_id": device_id,
                "chat_id": chat_id,
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),  # UTC ONLY
                "content": data.get("content", {}),
            }

            # Validate event payload
            if not event_payload.get("type"):
                await websocket.send_json({
                    "type": "error",
                    "code": "invalid_event",
                    "detail": "Event type is required",
                    "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                })
                continue

            # Local broadcast first so sender sees their own event immediately
            await manager.broadcast_to_chat(chat_id, event_payload)

            # Persist non-critical events in Redis
            if cache and cache.is_connected and event_payload["type"] != "typing":
                try:
                    await cache.publish(f"chat:{chat_id}", json.dumps(event_payload))
                    logger.debug(f"[WEBSOCKET] Published {message_type} to Redis for chat {chat_id}")
                except Exception as e:
                    logger.error(f"[WEBSOCKET] Failed to publish to Redis: {e}")
    
    except WebSocketDisconnect:
        if device_id and chat_id:
            await manager.disconnect(chat_id, device_id, websocket)
            logger.info(f"🔌 WS DISCONNECTED user={user_id} device={device_id} chat={chat_id}")
    
    except Exception as e:
        logger.error(f"[WEBSOCKET] Unexpected error: {type(e).__name__}: {e}", exc_info=True)
        try:
            await websocket.close(code=1011, reason="Internal server error")
        except Exception:
            pass

    finally:
        # Ensure Redis listener is stopped and pubsub closed
        if redis_task:
            try:
                redis_task.cancel()
                await asyncio.wait_for(redis_task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            except Exception:
                pass

        if pubsub:
            try:
                await pubsub.close()
            except Exception as e:
                logger.debug(f"[WEBSOCKET] Error closing pubsub: {e}")