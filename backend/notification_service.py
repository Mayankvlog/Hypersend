"""
Notification Service - Handles push notifications with group mute logic
Separate from message delivery to ensure muted users still receive messages
but don't receive notification events.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from bson import ObjectId

logger = logging.getLogger(__name__)


class GroupNotificationService:
    """
    Service to manage group notifications with mute/unmute logic.
    
    CRITICAL ARCHITECTURE:
    - Message delivery: DB commit → Redis publish → WebSocket broadcast
    - Notification events: Separate from messages, checks mute_until before publishing
    - Muted users: Still receive messages via WebSocket, but NO notification events
    """
    
    def __init__(self, redis_client, messages_collection, chats_collection):
        self.redis = redis_client
        self.messages_collection = messages_collection
        self.chats_collection = chats_collection
    
    async def should_send_notification_to_user(
        self, 
        user_id: str, 
        group_id: str, 
        message: Dict[str, Any]
    ) -> bool:
        """
        Check if notificationevent should be sent to user in group.
        
        Notification is SKIPPED if:
        1. User is in group's muted_by list AND
        2. Current UTC time < mute_until timestamp
        
        Notification is SENT if:
        1. User is NOT muted, OR
        2. User mute_until has expired
        
        CRITICAL: All timestamps must be UTC.
        """
        try:
            # Get group document
            group = await self.chats_collection.find_one({"_id": ObjectId(group_id)})
            if not group:
                logger.warning(f"Group {group_id} not found for notification check")
                return False
            
            # Check if user is in muted_by list
            muted_by = group.get("muted_by", [])
            if user_id not in muted_by:
                # User is not muted
                return True
            
            # User is muted, check mute_until expiration
            mute_config = group.get("mute_config", {})
            user_mute = mute_config.get(user_id)
            
            if not user_mute:
                # No mute config, treat as permanently muted (until explicitly unmuted)
                logger.debug(f"User {user_id} has no mute_until, skipping notification")
                return False
            
            # Get mute_until timestamp
            mute_until_str = user_mute.get("mute_until")
            if not mute_until_str:
                # No expiration set, permanently muted
                logger.debug(f"User {user_id} has no mute_until, skipping notification")
                return False
            
            # Parse mute_until as UTC datetime
            try:
                mute_until = datetime.fromisoformat(mute_until_str.replace('Z', '+00:00'))
                if mute_until.tzinfo is None:
                    # Naive datetime, treat as UTC
                    mute_until = mute_until.replace(tzinfo=timezone.utc)
            except Exception as e:
                logger.error(f"Failed to parse mute_until: {mute_until_str}: {e}")
                return False
            
            # Check if mute has expired
            now_utc = datetime.now(timezone.utc)
            
            if now_utc >= mute_until:
                # Mute has expired, should send notification
                logger.debug(f"User {user_id} mute expired ({mute_until} < {now_utc}), sending notification")
                return True
            else:
                # Mute is still active, skip notification
                logger.debug(f"User {user_id} is muted until {mute_until}, skipping notification")
                return False
            
        except Exception as e:
            logger.error(f"Error checking notification eligibility: {e}")
            # Default to sending notification on error
            return True
    
    async def send_group_notification(
        self,
        group_id: str,
        message_id: str,
        sender_id: str,
        notification_channel: str = None
    ) -> Dict[str, Any]:
        """
        Send notification event for group message.
        
        This is SEPARATE from message delivery.
        Muted users are excluded from notification events.
        
        Args:
            group_id: Group ID
            message_id: Message ID
            sender_id: User ID of sender
            notification_channel: Redis channel for notifications (separate from message channel)
        
        Returns:
            Dict with notification stats (sent, skipped, errors)
        """
        if notification_channel is None:
            notification_channel = f"notifications:group:{group_id}"
        
        stats = {
            "group_id": group_id,
            "message_id": message_id,
            "sent_to": [],
            "skipped_muted": [],
            "errors": []
        }
        
        try:
            # Get group members
            group = await self.chats_collection.find_one({"_id": ObjectId(group_id)})
            if not group:
                logger.warning(f"Group {group_id} not found")
                return stats
            
            members = group.get("members", [])
            message = await self.messages_collection.find_one({"_id": ObjectId(message_id)})
            
            if not message:
                logger.warning(f"Message {message_id} not found")
                return stats
            
            # For each member (except sender)
            for member_id in members:
                if member_id == sender_id:
                    # Don't send notifications to sender
                    continue
                
                try:
                    # Check if should send notification
                    should_send = await self.should_send_notification_to_user(
                        member_id, 
                        group_id, 
                        message
                    )
                    
                    if not should_send:
                        stats["skipped_muted"].append(member_id)
                        continue
                    
                    # Create notification event
                    notification_event = {
                        "type": "new_message_notification",
                        "group_id": str(group_id),
                        "message_id": str(message_id),
                        "sender_id": str(sender_id),
                        "recipient_id": str(member_id),
                        "sender_name": message.get("sender_name", "Unknown"),
                        "preview": message.get("content", "")[:100],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "created_at": message.get("created_at")
                    }
                    
                    # Publish to Redis notification channel
                    if self.redis:
                        await self.redis.publish(
                            notification_channel,
                            json.dumps(notification_event, default=str)
                        )
                    
                    stats["sent_to"].append(member_id)
                    logger.debug(f"Sent notification to {member_id} for message {message_id}")
                    
                except Exception as e:
                    logger.error(f"Error sending notification to {member_id}: {e}")
                    stats["errors"].append({
                        "user_id": member_id,
                        "error": str(e)
                    })
            
            # Log summary
            total_members = len([m for m in members if m != sender_id])
            logger.info(
                f"Notification results for group {group_id}: "
                f"sent={len(stats['sent_to'])}, "
                f"skipped_muted={len(stats['skipped_muted'])}, "
                f"errors={len(stats['errors'])}, "
                f"total_members={total_members}"
            )
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to send group notifications: {e}")
            return stats


# Global notification service instance
_notification_service: Optional[GroupNotificationService] = None


async def init_notification_service(redis_client, messages_collection, chats_collection):
    """Initialize global notification service"""
    global _notification_service
    _notification_service = GroupNotificationService(redis_client, messages_collection, chats_collection)
    logger.info("Notification service initialized")


def get_notification_service() -> Optional[GroupNotificationService]:
    """Get global notification service instance"""
    return _notification_service
