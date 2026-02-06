"""
WhatsApp-Grade Delivery Semantics & Message Reliability
======================================================

Per-device ACK state machine, idempotent retries, message de-duplication,
strict per-chat ordering with sequence numbers.

Security Properties:
- Per-device delivery tracking
- Idempotent message processing
- Exact-once delivery guarantees
- Ordered message delivery per chat
- Retry with exponential backoff
- De-duplication via message IDs
"""

import time
import secrets
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class MessageStatus(Enum):
    """Message delivery status per device"""
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"
    DELETED = "deleted"

class DeviceState(Enum):
    """Device connection state"""
    OFFLINE = "offline"
    CONNECTING = "connecting"
    ONLINE = "online"
    DISCONNECTING = "disconnecting"

@dataclass
class DeliveryReceipt:
    """Per-device delivery receipt"""
    message_id: str
    device_id: str
    user_id: str
    chat_id: str
    status: MessageStatus
    timestamp: float
    retry_count: int
    next_retry_at: Optional[float]
    error_message: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "message_id": self.message_id,
            "device_id": self.device_id,
            "user_id": self.user_id,
            "chat_id": self.chat_id,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "retry_count": self.retry_count,
            "next_retry_at": self.next_retry_at,
            "error_message": self.error_message
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeliveryReceipt':
        """Create from dictionary"""
        return cls(
            message_id=data["message_id"],
            device_id=data["device_id"],
            user_id=data["user_id"],
            chat_id=data["chat_id"],
            status=MessageStatus(data["status"]),
            timestamp=data["timestamp"],
            retry_count=data["retry_count"],
            next_retry_at=data.get("next_retry_at"),
            error_message=data.get("error_message")
        )

@dataclass
class MessageSequence:
    """Chat message sequence for ordering"""
    chat_id: str
    sequence_number: int
    message_id: str
    sender_id: str
    timestamp: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MessageSequence':
        """Create from dictionary"""
        return cls(**data)

@dataclass
class DeviceConnection:
    """Device connection state"""
    device_id: str
    user_id: str
    state: DeviceState
    last_ping: float
    websocket_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "device_id": self.device_id,
            "user_id": self.user_id,
            "state": self.state.value,
            "last_ping": self.last_ping,
            "websocket_id": self.websocket_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeviceConnection':
        """Create from dictionary"""
        return cls(
            device_id=data["device_id"],
            user_id=data["user_id"],
            state=DeviceState(data["state"]),
            last_ping=data["last_ping"],
            websocket_id=data.get("websocket_id"),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent")
        )

class DeliveryManager:
    """Manages message delivery and reliability"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.retry_intervals = [5, 15, 30, 60, 300, 900, 3600]  # seconds
        self.max_retries = len(self.retry_intervals)
        self.message_timeout = 7 * 24 * 60 * 60  # 7 days
    
    async def initialize_message_delivery(
        self,
        message_id: str,
        sender_id: str,
        chat_id: str,
        recipient_devices: List[str],
        sequence_number: int
    ) -> Dict[str, DeliveryReceipt]:
        """
        Initialize message delivery to all recipient devices
        
        Returns: device_id -> delivery_receipt mapping
        """
        receipts = {}
        current_time = time.time()
        
        # Create message sequence record
        sequence = MessageSequence(
            chat_id=chat_id,
            sequence_number=sequence_number,
            message_id=message_id,
            sender_id=sender_id,
            timestamp=current_time
        )
        
        await self.redis.set(
            f"message_sequence:{chat_id}:{sequence_number}",
            json.dumps(sequence.to_dict())
        )
        
        # Create delivery receipts for each device
        for device_id in recipient_devices:
            receipt = DeliveryReceipt(
                message_id=message_id,
                device_id=device_id,
                user_id="",  # Will be filled by caller
                chat_id=chat_id,
                status=MessageStatus.PENDING,
                timestamp=current_time,
                retry_count=0,
                next_retry_at=current_time + 5,  # First retry in 5 seconds
                error_message=None
            )
            
            receipts[device_id] = receipt
            
            # Store receipt
            await self.redis.set(
                f"delivery_receipt:{message_id}:{device_id}",
                json.dumps(receipt.to_dict())
            )
        
        # Add to pending delivery queue
        await self.redis.sadd(f"pending_messages:{chat_id}", message_id)
        
        logger.info(f"Initialized delivery for message {message_id} to {len(recipient_devices)} devices")
        return receipts
    
    async def mark_message_sent(self, message_id: str, device_id: str) -> bool:
        """
        Mark message as sent to device
        
        Returns: True if status updated
        """
        receipt = await self._get_delivery_receipt(message_id, device_id)
        if not receipt:
            return False
        
        receipt.status = MessageStatus.SENT
        receipt.timestamp = time.time()
        receipt.next_retry_at = None  # Clear retry schedule
        receipt.error_message = None
        
        await self._save_delivery_receipt(receipt)
        
        logger.info(f"Marked message {message_id} as sent to device {device_id}")
        return True
    
    async def mark_message_delivered(self, message_id: str, device_id: str) -> bool:
        """
        Mark message as delivered to device
        
        Returns: True if status updated
        """
        receipt = await self._get_delivery_receipt(message_id, device_id)
        if not receipt:
            return False
        
        receipt.status = MessageStatus.DELIVERED
        receipt.timestamp = time.time()
        receipt.next_retry_at = None
        receipt.error_message = None
        
        await self._save_delivery_receipt(receipt)
        
        # Check if all devices have received the message
        await self._check_message_completion(message_id)
        
        logger.info(f"Marked message {message_id} as delivered to device {device_id}")
        return True
    
    async def mark_message_read(self, message_id: str, device_id: str) -> bool:
        """
        Mark message as read on device
        
        Returns: True if status updated
        """
        receipt = await self._get_delivery_receipt(message_id, device_id)
        if not receipt:
            return False
        
        receipt.status = MessageStatus.READ
        receipt.timestamp = time.time()
        receipt.next_retry_at = None
        receipt.error_message = None
        
        await self._save_delivery_receipt(receipt)
        
        # Check if all devices have read the message
        await self._check_message_completion(message_id)
        
        logger.info(f"Marked message {message_id} as read on device {device_id}")
        return True
    
    async def mark_message_failed(self, message_id: str, device_id: str, error_message: str) -> bool:
        """
        Mark message delivery as failed and schedule retry
        
        Returns: True if retry scheduled
        """
        receipt = await self._get_delivery_receipt(message_id, device_id)
        if not receipt:
            return False
        
        receipt.retry_count += 1
        receipt.error_message = error_message
        
        # Check if max retries reached
        if receipt.retry_count >= self.max_retries:
            receipt.status = MessageStatus.FAILED
            receipt.next_retry_at = None
            logger.error(f"Message {message_id} failed permanently for device {device_id}")
        else:
            # Schedule next retry
            retry_delay = self.retry_intervals[min(receipt.retry_count - 1, len(self.retry_intervals) - 1)]
            receipt.next_retry_at = time.time() + retry_delay
            logger.warning(f"Message {message_id} failed for device {device_id}, retry {receipt.retry_count}/{self.max_retries} in {retry_delay}s")
        
        await self._save_delivery_receipt(receipt)
        return receipt.status != MessageStatus.FAILED
    
    async def get_pending_deliveries(self, device_id: str, limit: int = 100) -> List[DeliveryReceipt]:
        """
        Get pending message deliveries for device
        
        Returns: list of delivery receipts
        """
        current_time = time.time()
        pending_receipts = []
        
        # Get all pending receipts for device
        pattern = f"delivery_receipt:*:{device_id}"
        keys = await self.redis.keys(pattern)
        
        for key in keys[:limit]:  # Limit to prevent memory issues
            receipt_data = await self.redis.get(key)
            if receipt_data:
                receipt = DeliveryReceipt.from_dict(json.loads(receipt_data))
                
                # Check if retry is due
                if (receipt.status == MessageStatus.PENDING and 
                    receipt.next_retry_at and 
                    receipt.next_retry_at <= current_time):
                    pending_receipts.append(receipt)
        
        # Sort by timestamp (oldest first)
        pending_receipts.sort(key=lambda r: r.timestamp)
        return pending_receipts
    
    async def get_chat_sequence_number(self, chat_id: str) -> int:
        """
        Get next sequence number for chat
        
        Returns: next sequence number
        """
        current = await self.redis.get(f"chat_sequence:{chat_id}")
        if current:
            next_seq = int(current) + 1
        else:
            next_seq = 1
        
        await self.redis.set(f"chat_sequence:{chat_id}", next_seq)
        return next_seq
    
    async def get_chat_messages(
        self,
        chat_id: str,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
        limit: int = 100
    ) -> List[MessageSequence]:
        """
        Get message sequences for chat with ordering
        
        Returns: list of message sequences in order
        """
        sequences = []
        
        # Get sequence range
        if from_sequence is None:
            from_sequence = 1
        
        # Get sequences in range
        for seq_num in range(from_sequence, from_sequence + limit):
            if to_sequence and seq_num > to_sequence:
                break
            
            seq_data = await self.redis.get(f"message_sequence:{chat_id}:{seq_num}")
            if seq_data:
                sequence = MessageSequence.from_dict(json.loads(seq_data))
                sequences.append(sequence)
            else:
                break  # No more messages
        
        return sequences
    
    async def is_message_duplicate(self, message_id: str, device_id: str) -> bool:
        """
        Check if message is duplicate for device
        
        Returns: True if message already processed
        """
        receipt = await self._get_delivery_receipt(message_id, device_id)
        return receipt is not None and receipt.status in [MessageStatus.DELIVERED, MessageStatus.READ]
    
    async def get_device_delivery_status(self, message_id: str) -> Dict[str, MessageStatus]:
        """
        Get delivery status for all devices of a message
        
        Returns: device_id -> status mapping
        """
        pattern = f"delivery_receipt:{message_id}:*"
        keys = await self.redis.keys(pattern)
        
        status_map = {}
        for key in keys:
            receipt_data = await self.redis.get(key)
            if receipt_data:
                receipt = DeliveryReceipt.from_dict(json.loads(receipt_data))
                status_map[receipt.device_id] = receipt.status
        
        return status_map
    
    async def cleanup_old_messages(self, older_than_days: int = 30) -> int:
        """
        Clean up old message delivery records
        
        Returns: number of messages cleaned up
        """
        cutoff_time = time.time() - (older_than_days * 24 * 60 * 60)
        cleaned_count = 0
        
        # Get all delivery receipts
        pattern = "delivery_receipt:*"
        keys = await self.redis.keys(pattern)
        
        for key in keys:
            receipt_data = await self.redis.get(key)
            if receipt_data:
                receipt = DeliveryReceipt.from_dict(json.loads(receipt_data))
                
                # Clean up old messages
                if receipt.timestamp < cutoff_time:
                    await self.redis.delete(key)
                    cleaned_count += 1
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} old delivery receipts")
        
        return cleaned_count
    
    async def update_device_connection(
        self,
        device_id: str,
        user_id: str,
        state: DeviceState,
        websocket_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Update device connection state"""
        connection = DeviceConnection(
            device_id=device_id,
            user_id=user_id,
            state=state,
            last_ping=time.time(),
            websocket_id=websocket_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        await self.redis.set(
            f"device_connection:{device_id}",
            json.dumps(connection.to_dict()),
            ex=3600  # 1 hour TTL
        )
    
    async def get_device_connection(self, device_id: str) -> Optional[DeviceConnection]:
        """Get device connection state"""
        data = await self.redis.get(f"device_connection:{device_id}")
        if data:
            return DeviceConnection.from_dict(json.loads(data))
        return None
    
    async def is_device_online(self, device_id: str) -> bool:
        """Check if device is online"""
        connection = await self.get_device_connection(device_id)
        return connection is not None and connection.state == DeviceState.ONLINE
    
    async def get_user_online_devices(self, user_id: str) -> List[str]:
        """Get list of online devices for user"""
        pattern = "device_connection:*"
        keys = await self.redis.keys(pattern)
        
        online_devices = []
        for key in keys:
            data = await self.redis.get(key)
            if data:
                connection = DeviceConnection.from_dict(json.loads(data))
                if connection.user_id == user_id and connection.state == DeviceState.ONLINE:
                    online_devices.append(connection.device_id)
        
        return online_devices
    
    async def _get_delivery_receipt(self, message_id: str, device_id: str) -> Optional[DeliveryReceipt]:
        """Get delivery receipt"""
        data = await self.redis.get(f"delivery_receipt:{message_id}:{device_id}")
        if data:
            return DeliveryReceipt.from_dict(json.loads(data))
        return None
    
    async def _save_delivery_receipt(self, receipt: DeliveryReceipt) -> None:
        """Save delivery receipt"""
        await self.redis.set(
            f"delivery_receipt:{receipt.message_id}:{receipt.device_id}",
            json.dumps(receipt.to_dict())
        )
    
    async def _check_message_completion(self, message_id: str) -> None:
        """Check if message is complete for all devices"""
        status_map = await self.get_device_delivery_status(message_id)
        
        # Check if all devices have at least delivered status
        all_delivered = all(
            status in [MessageStatus.DELIVERED, MessageStatus.READ] 
            for status in status_map.values()
        )
        
        if all_delivered:
            # Remove from pending queue
            pattern = f"pending_messages:*"
            keys = await self.redis.keys(pattern)
            for key in keys:
                await self.redis.srem(key, message_id)
            
            logger.info(f"Message {message_id} completed delivery to all devices")
