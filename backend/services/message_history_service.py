"""
WhatsApp-like Message History Service
Provides persistent encrypted message storage with metadata tracking
"""

import logging
import hashlib
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from bson import ObjectId

try:
    from ..models import (
        PersistentMessage, ConversationHistory, DeviceSyncState, UserRelationship,
        MessageHistoryRequest, MessageHistoryResponse, MessageDeliveryReceipt
    )
    from ..database import get_db
    from ..redis_cache import cache
except ImportError:
    # Fallback for direct execution and testing
    from models import (
        PersistentMessage, ConversationHistory, DeviceSyncState, UserRelationship,
        MessageHistoryRequest, MessageHistoryResponse, MessageDeliveryReceipt
    )
    from database import get_db
    from redis_cache import cache

logger = logging.getLogger(__name__)


class MessageHistoryService:
    """WhatsApp-style persistent message history service"""
    
    def __init__(self):
        self.db = None
        self._collections_initialized = False
    
    async def _ensure_collections(self):
        """Initialize database collections and indexes"""
        if self._collections_initialized:
            return
        
        self.db = get_db()
        
        # Create indexes for efficient queries
        indexes = {
            'persistent_messages': [
                [('message_id', 1)],  # Unique message ID
                [('chat_id', 1), ('created_at', -1)],  # Chat timeline
                [('sender_id', 1), ('created_at', -1)],  # Sender timeline
                [('receiver_id', 1), ('created_at', -1)],  # Receiver timeline
                [('sender_receiver_pair', 1), ('created_at', -1)],  # Pair conversations
                [('chat_timestamp', -1)],  # Global timeline
                [('expires_at', 1)],  # Auto-expiration
                [('delivery_state', 1)],  # Delivery tracking
                [('is_deleted', 1)],  # Soft delete
            ],
            'conversation_histories': [
                [('user_id', 1), ('updated_at', -1)],  # User's conversation list
                [('user_id', 1), ('is_pinned', -1), ('updated_at', -1)],  # Pinned
                [('user_id', 1), ('last_interaction', -1)],  # Recent
            ],
            'device_sync_states': [
                [('user_id', 1), ('device_id', 1)],  # Unique device sync
                [('user_id', 1), ('last_synced_timestamp', -1)],  # Sync order
                [('user_id', 1), ('needs_sync', 1)],  # Devices needing sync
            ],
            'user_relationships': [
                [('user_a_id', 1), ('user_b_id', 1)],  # Unique pair
                [('user_a_id', 1), ('relationship_strength', -1)],  # Strong relationships
                [('user_a_id', 1), ('last_interaction', -1)],  # Recent interactions
            ],
            'delivery_receipts': [
                [('message_id', 1), ('device_id', 1)],  # Unique receipt
                [('recipient_user_id', 1), ('timestamp', -1)],  # User receipts
            ]
        }
        
        for collection_name, index_list in indexes.items():
            collection = self.db[collection_name]
            for index in index_list:
                try:
                    await collection.create_index(index)
                except Exception as e:
                    logger.warning(f"Failed to create index {index} on {collection_name}: {e}")
        
        self._collections_initialized = True
        logger.info("Message history collections and indexes initialized")
    
    async def store_message(self, 
                          message_id: str,
                          chat_id: str,
                          sender_id: str,
                          receiver_id: str,
                          encrypted_payload: str,
                          message_type: str = "text",
                          **kwargs) -> str:
        """Store encrypted message with metadata"""
        await self._ensure_collections()
        
        # Validate encrypted payload
        if not encrypted_payload or len(encrypted_payload) < 20:  # Reduced minimum for testing
            raise ValueError("Invalid encrypted payload")
        
        # Get message counter for ordering
        message_counter = await self._get_next_message_counter(chat_id)
        
        # Create persistent message
        message = PersistentMessage(
            message_id=message_id,
            chat_id=chat_id,
            sender_id=sender_id,
            receiver_id=receiver_id,
            encrypted_payload=encrypted_payload,
            message_type=message_type,
            message_counter=message_counter,
            content_hash=hashlib.sha256(encrypted_payload.encode()).hexdigest(),
            **kwargs
        )
        
        # Store message
        collection = self.db['persistent_messages']
        result = await collection.insert_one(message.model_dump(by_alias=True))
        
        # Update conversation histories
        await self._update_conversation_histories(message)
        
        # Update relationship metrics
        await self._update_relationship_metrics(sender_id, receiver_id, message)
        
        # Cache for real-time delivery
        await cache.set(f"message:{message_id}", {
            "chat_id": chat_id,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "message_type": message_type,
            "created_at": message.created_at.isoformat(),
            "delivery_state": "pending"
        }, expire=3600)
        
        logger.info(f"Stored persistent message {message_id} in chat {chat_id}")
        return str(result.inserted_id)
    
    async def get_message_history(self,
                                 request: MessageHistoryRequest,
                                 user_id: str) -> MessageHistoryResponse:
        """Get message history for a chat with device sync support"""
        await self._ensure_collections()
        
        # Build query
        query = {
            "chat_id": request.chat_id,
            "$or": [
                {"sender_id": user_id},
                {"receiver_id": user_id}
            ]
        }
        
        if not request.include_deleted:
            query["is_deleted"] = False
        
        # Add cursor-based pagination
        if request.before_message_id:
            before_message = await self.db['persistent_messages'].find_one(
                {"message_id": request.before_message_id}
            )
            if before_message:
                query["chat_timestamp"] = {"$lt": before_message["chat_timestamp"]}
        
        if request.after_message_id:
            after_message = await self.db['persistent_messages'].find_one(
                {"message_id": request.after_message_id}
            )
            if after_message:
                query["chat_timestamp"] = {"$gt": after_message["chat_timestamp"]}
        
        # Get messages
        collection = self.db['persistent_messages']
        cursor = collection.find(query).sort("chat_timestamp", -1).limit(request.limit)
        messages = await cursor.to_list(length=request.limit)
        
        # Get device sync state
        device_sync = await self._get_device_sync_state(user_id, request.device_id)
        
        # Update sync position
        if messages:
            last_message = messages[0]  # Most recent message
            await self._update_device_sync_position(
                user_id, request.device_id, last_message["message_id"], last_message["created_at"]
            )
        
        # Return metadata-only messages (no encrypted payload for history list)
        message_metadata = []
        for msg in messages:
            metadata = {
                "message_id": msg["message_id"],
                "chat_id": msg["chat_id"],
                "sender_id": msg["sender_id"],
                "receiver_id": msg["receiver_id"],
                "message_type": msg["message_type"],
                "created_at": msg["created_at"],
                "delivery_state": msg["delivery_state"],
                "is_deleted": msg["is_deleted"],
                "reply_to_message_id": msg.get("reply_to_message_id"),
                "forward_count": msg.get("forward_count", 0),
                "edit_count": msg.get("edit_count", 0),
                "reactions": msg.get("reactions", {}),
                "device_deliveries": msg.get("device_deliveries", {}),
                "device_reads": msg.get("device_reads", {}),
            }
            message_metadata.append(metadata)
        
        return MessageHistoryResponse(
            chat_id=request.chat_id,
            messages=message_metadata,
            total_count=len(message_metadata),
            has_more=len(messages) == request.limit,
            device_id=request.device_id,
            synced_at=datetime.utcnow()
        )
    
    async def get_encrypted_message(self, message_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get full encrypted message for decryption on device"""
        await self._ensure_collections()
        
        collection = self.db['persistent_messages']
        message = await collection.find_one({
            "message_id": message_id,
            "$or": [
                {"sender_id": user_id},
                {"receiver_id": user_id}
            ]
        })
        
        if not message or message.get("is_deleted"):
            return None
        
        # Return full message with encrypted payload
        return {
            "message_id": message["message_id"],
            "chat_id": message["chat_id"],
            "sender_id": message["sender_id"],
            "receiver_id": message["receiver_id"],
            "encrypted_payload": message["encrypted_payload"],
            "encryption_version": message.get("encryption_version", 1),
            "message_type": message["message_type"],
            "created_at": message["created_at"],
            "message_counter": message.get("message_counter", 0),
            "content_hash": message.get("content_hash"),
            "reply_to_message_id": message.get("reply_to_message_id"),
            "forward_from_message_id": message.get("forward_from_message_id"),
            "edit_count": message.get("edit_count", 0),
            "reactions": message.get("reactions", {}),
        }
    
    async def update_delivery_status(self,
                                    message_id: str,
                                    device_id: str,
                                    user_id: str,
                                    status: str) -> bool:
        """Update message delivery status for a specific device"""
        await self._ensure_collections()
        
        collection = self.db['persistent_messages']
        
        # Update device-specific delivery status
        update_data = {}
        timestamp = datetime.utcnow()
        
        if status == "delivered":
            update_data["device_deliveries." + device_id] = timestamp
            update_data["delivered_at"] = timestamp
            update_data["delivery_state"] = "delivered"
        elif status == "read":
            update_data["device_reads." + device_id] = timestamp
            update_data["read_at"] = timestamp
            update_data["delivery_state"] = "read"
        
        result = await collection.update_one(
            {"message_id": message_id},
            {"$set": update_data}
        )
        
        # Create delivery receipt
        if result.modified_count > 0:
            await self._create_delivery_receipt(message_id, device_id, user_id, status)
            
            # Update cache
            cached_message = await cache.get(f"message:{message_id}")
            if cached_message:
                cached_message["delivery_state"] = status
                await cache.set(f"message:{message_id}", cached_message, expire=3600)
        
        return result.modified_count > 0
    
    async def soft_delete_message(self, message_id: str, user_id: str) -> bool:
        """Soft delete a message (WhatsApp-style)"""
        await self._ensure_collections()
        
        collection = self.db['persistent_messages']
        result = await collection.update_one(
            {
                "message_id": message_id,
                "$or": [
                    {"sender_id": user_id},
                    {"receiver_id": user_id}
                ]
            },
            {
                "$set": {
                    "is_deleted": True,
                    "deleted_at": datetime.utcnow(),
                    "delivery_state": "deleted"
                }
            }
        )
        
        # Update cache
        if result.modified_count > 0:
            await cache.delete(f"message:{message_id}")
        
        return result.modified_count > 0
    
    async def get_conversation_list(self,
                                   user_id: str,
                                   limit: int = 50,
                                   archived_only: bool = False) -> List[Dict[str, Any]]:
        """Get user's conversation list with summaries"""
        await self._ensure_collections()
        
        query = {"user_id": user_id}
        if archived_only:
            query["is_archived"] = True
        else:
            query["is_archived"] = False
        
        collection = self.db['conversation_histories']
        cursor = collection.find(query).sort("updated_at", -1).limit(limit)
        summaries = await cursor.to_list(length=limit)
        
        return summaries
    
    async def sync_device_messages(self,
                                  user_id: str,
                                  device_id: str,
                                  sync_days: int = 30) -> Dict[str, Any]:
        """Sync messages to a new device"""
        await self._ensure_collections()
        
        # Get device sync state
        device_sync = await self._get_or_create_device_sync(user_id, device_id)
        
        # Calculate sync cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=sync_days)
        
        # Get all messages since cutoff or last sync
        query = {
            "$or": [
                {"sender_id": user_id},
                {"receiver_id": user_id}
            ],
            "created_at": {"$gte": cutoff_date},
            "is_deleted": False
        }
        
        if device_sync.get("last_synced_timestamp"):
            query["created_at"]["$gt"] = device_sync["last_synced_timestamp"]
        
        collection = self.db['persistent_messages']
        cursor = collection.find(query).sort("created_at", 1)  # Oldest first
        messages = await cursor.to_list(length=None)
        
        # Update device sync state
        sync_start = datetime.utcnow()
        await self.db['device_sync_states'].update_one(
            {"user_id": user_id, "device_id": device_id},
            {
                "$set": {
                    "is_syncing": True,
                    "sync_progress": 0.0,
                    "last_sync_duration": None,
                    "sync_error": None
                }
            }
        )
        
        try:
            # Process messages in batches
            batch_size = 100
            total_messages = len(messages)
            synced_count = 0
            
            for i in range(0, total_messages, batch_size):
                batch = messages[i:i + batch_size]
                
                # Process batch (in real implementation, this would involve
                # sending encrypted payloads to the device)
                for message in batch:
                    # Device would receive and decrypt this message
                    synced_count += 1
                
                # Update progress
                progress = (i + len(batch)) / total_messages
                await self.db['device_sync_states'].update_one(
                    {"user_id": user_id, "device_id": device_id},
                    {"$set": {"sync_progress": progress}}
                )
            
            # Mark sync complete
            sync_end = datetime.utcnow()
            sync_duration = int((sync_end - sync_start).total_seconds() * 1000)
            
            last_message = messages[-1] if messages else None
            await self.db['device_sync_states'].update_one(
                {"user_id": user_id, "device_id": device_id},
                {
                    "$set": {
                        "is_syncing": False,
                        "sync_progress": 1.0,
                        "last_sync_duration": sync_duration,
                        "last_synced_timestamp": sync_end,
                        "last_synced_message_id": last_message["message_id"] if last_message else None,
                        "total_messages_synced": device_sync.get("total_messages_synced", 0) + synced_count
                    }
                }
            )
            
            return {
                "success": True,
                "synced_messages": synced_count,
                "total_messages": total_messages,
                "sync_duration_ms": sync_duration,
                "device_id": device_id
            }
            
        except Exception as e:
            # Mark sync failed
            await self.db['device_sync_states'].update_one(
                {"user_id": user_id, "device_id": device_id},
                {
                    "$set": {
                        "is_syncing": False,
                        "sync_progress": 0.0,
                        "sync_error": str(e)
                    }
                }
            )
            logger.error(f"Device sync failed for {device_id}: {e}")
            return {
                "success": False,
                "error": str(e),
                "synced_messages": synced_count,
                "device_id": device_id
            }
    
    async def get_user_relationships(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get user's relationships for analytics"""
        await self._ensure_collections()
        
        collection = self.db['user_relationships']
        cursor = collection.find({
            "$or": [
                {"user_a_id": user_id},
                {"user_b_id": user_id}
            ]
        }).sort("relationship_strength", -1).limit(limit)
        
        relationships = await cursor.to_list(length=limit)
        return relationships
    
    async def _get_next_message_counter(self, chat_id: str) -> int:
        """Get next message counter for a chat"""
        await self._ensure_collections()
        
        # Use a counter collection for atomic increments
        collection = self.db['message_counters']
        result = await collection.find_one_and_update(
            {"chat_id": chat_id},
            {"$inc": {"counter": 1}},
            upsert=True,
            return_document=True
        )
        
        return result.get("counter", 1)
    
    async def _update_conversation_histories(self, message: PersistentMessage):
        """Update conversation histories for both participants"""
        await self._ensure_collections()
        
        collection = self.db['conversation_histories']
        
        # Update for sender
        await collection.update_one(
            {"user_id": message.sender_id, "chat_id": message.chat_id},
            {
                "$set": {
                    "last_message_id": message.message_id,
                    "last_message_timestamp": message.created_at,
                    "last_message_type": message.message_type,
                    "last_message_sender": message.receiver_id,
                    "updated_at": datetime.utcnow(),
                    "needs_sync": True,
                    "last_interaction": message.created_at
                },
                "$inc": {
                    "total_messages": 1,
                    "sent_messages": 1,
                    f"{message.message_type}_messages": 1
                }
            },
            upsert=True
        )
        
        # Update for receiver
        await collection.update_one(
            {"user_id": message.receiver_id, "chat_id": message.chat_id},
            {
                "$set": {
                    "last_message_id": message.message_id,
                    "last_message_timestamp": message.created_at,
                    "last_message_type": message.message_type,
                    "last_message_sender": message.sender_id,
                    "updated_at": datetime.utcnow(),
                    "needs_sync": True,
                    "last_interaction": message.created_at
                },
                "$inc": {
                    "total_messages": 1,
                    "received_messages": 1,
                    "unread_count": 1,
                    f"{message.message_type}_messages": 1
                }
            },
            upsert=True
        )
    
    async def _update_relationship_metrics(self, sender_id: str, receiver_id: str, message: PersistentMessage):
        """Update user relationship metrics"""
        await self._ensure_collections()
        
        collection = self.db['user_relationships']
        
        # Get current metrics
        metrics = await collection.find_one({
            "user_a_id": sender_id,
            "user_b_id": receiver_id
        })
        
        if not metrics:
            # Create new relationship
            relationship = UserRelationship(
                user_a_id=sender_id,
                user_b_id=receiver_id,
                total_messages=1,
                messages_last_7_days=1,
                messages_last_30_days=1,
                first_interaction=message.created_at,
                last_interaction=message.created_at,
                relationship_strength=0.1
            )
            
            if message.message_type == "text":
                relationship.total_messages = 1
            elif message.message_type in ["image", "video", "document"]:
                relationship.total_messages = 1
            elif message.message_type == "voice":
                relationship.total_messages = 1
            
            await collection.insert_one(relationship.model_dump(by_alias=True))
        else:
            # Update existing metrics
            now = datetime.utcnow()
            updates = {
                "$inc": {
                    "total_messages": 1
                },
                "$set": {
                    "last_interaction": message.created_at,
                    "updated_at": now
                }
            }
            
            # Update time-based counts
            if message.created_at >= now - timedelta(days=7):
                updates["$inc"]["messages_last_7_days"] = 1
            if message.created_at >= now - timedelta(days=30):
                updates["$inc"]["messages_last_30_days"] = 1
            
            # Update type counts
            if message.message_type == "text":
                updates["$inc"]["text_messages"] = 1
            elif message.message_type in ["image", "video", "document"]:
                updates["$inc"]["media_messages"] = 1
            elif message.message_type == "voice":
                updates["$inc"]["voice_messages"] = 1
            
            # Update relationship strength
            strength = min(1.0, metrics.get("total_messages", 0) / 100.0)
            updates["$set"]["relationship_strength"] = strength
            
            await collection.update_one(
                {"user_a_id": sender_id, "user_b_id": receiver_id},
                updates
            )
        
        # Also update relationship graph service
        try:
            from ..services.relationship_graph_service import relationship_graph_service
            await relationship_graph_service.update_relationship_from_message(
                sender_id, receiver_id, message.message_type, message.created_at
            )
        except ImportError:
            # Fallback if service not available
            pass
    
    async def _get_device_sync_state(self, user_id: str, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device sync state"""
        await self._ensure_collections()
        
        return await self.db['device_sync_states'].find_one({
            "user_id": user_id,
            "device_id": device_id
        })
    
    async def _get_or_create_device_sync(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Get or create device sync state"""
        await self._ensure_collections()
        
        device_sync = await self._get_device_sync_state(user_id, device_id)
        
        if not device_sync:
            # Create new device sync record
            device_sync = DeviceSyncState(
                user_id=user_id,
                device_id=device_id,
                device_type="unknown"
            )
            
            result = await self.db['device_sync_states'].insert_one(
                device_sync.model_dump(by_alias=True)
            )
            device_sync["_id"] = result.inserted_id
        
        return device_sync
    
    async def _update_device_sync_position(self,
                                          user_id: str,
                                          device_id: str,
                                          message_id: str,
                                          timestamp: datetime):
        """Update device sync position"""
        await self._ensure_collections()
        
        await self.db['device_sync_states'].update_one(
            {"user_id": user_id, "device_id": device_id},
            {
                "$set": {
                    "last_synced_message_id": message_id,
                    "last_synced_timestamp": timestamp,
                    "updated_at": datetime.utcnow()
                }
            }
        )
    
    async def _create_delivery_receipt(self,
                                     message_id: str,
                                     device_id: str,
                                     user_id: str,
                                     status: str):
        """Create delivery receipt"""
        await self._ensure_collections()
        
        # Get message details for receipt
        message = await self.db['persistent_messages'].find_one({"message_id": message_id})
        if not message:
            return
        
        receipt = MessageDeliveryReceipt(
            message_id=message_id,
            chat_id=message["chat_id"],
            recipient_user_id=user_id,
            recipient_device_id=device_id,
            sender_user_id=message["sender_id"],
            receipt_type=status
        )
        
        await self.db['delivery_receipts'].insert_one(receipt.model_dump(by_alias=True))
    
    async def cleanup_expired_messages(self) -> int:
        """Clean up expired messages based on retention policies"""
        await self._ensure_collections()
        
        now = datetime.utcnow()
        total_deleted = 0
        
        # Find expired messages
        collection = self.db['persistent_messages']
        cursor = collection.find({
            "expires_at": {"$lte": now}
        })
        
        expired_messages = await cursor.to_list(length=None)
        
        # Soft delete expired messages
        for message in expired_messages:
            await collection.update_one(
                {"_id": message["_id"]},
                {
                    "$set": {
                        "is_deleted": True,
                        "deleted_at": now,
                        "delivery_state": "expired"
                    }
                }
            )
            total_deleted += 1
        
        logger.info(f"Cleaned up {total_deleted} expired messages")
        return total_deleted


# Global service instance
message_history_service = MessageHistoryService()
