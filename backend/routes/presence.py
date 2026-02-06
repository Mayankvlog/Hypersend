"""
WhatsApp-style Presence & Typing Indicators
Redis pub/sub only - no persistent storage
Ephemeral indicators with privacy controls
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional, Dict, List
from datetime import datetime, timezone, timedelta
import json
import logging
import asyncio
from pydantic import BaseModel, Field

from auth.utils import get_current_user

logger = logging.getLogger(__name__)


class PresenceStatus:
    ONLINE = "online"
    OFFLINE = "offline"
    AWAY = "away"
    BUSY = "busy"


class PrivacyLevel:
    EVERYONE = "everyone"
    CONTACTS = "contacts"
    NOBODY = "nobody"
    LAST_SEEN = "last_seen"


class TypingEvent(BaseModel):
    chat_id: str
    user_id: str
    device_id: str
    typing: bool  # True for typing started, False for typing stopped
    timestamp: datetime


class PresenceUpdate(BaseModel):
    user_id: str
    status: str
    last_seen: Optional[datetime] = None
    privacy_level: str = PrivacyLevel.CONTACTS
    device_count: int = 1


class LastSeenSettings(BaseModel):
    show_last_seen: bool = True
    privacy_level: str = PrivacyLevel.CONTACTS
    custom_users: List[str] = []


router = APIRouter(prefix="/presence", tags=["Presence & Typing"])


@router.post("/typing")
async def send_typing_indicator(
    typing_event: TypingEvent,
    current_user: str = Depends(get_current_user)
):
    """Send typing indicator via Redis pub/sub - WhatsApp style"""
    from ..redis_cache import redis_client
    
    # Verify user owns the typing event
    if typing_event.user_id != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
    
    # Validate chat membership
    if not await _is_user_in_chat(current_user, typing_event.chat_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this chat")
    
    # Create typing event
    typing_data = {
        "type": "typing",
        "chat_id": typing_event.chat_id,
        "user_id": typing_event.user_id,
        "device_id": typing_event.device_id,
        "typing": typing_event.typing,
        "timestamp": typing_event.timestamp.isoformat()
    }
    
    # Publish to chat channel
    await redis_client.publish(f"chat_channel:{typing_event.chat_id}", json.dumps(typing_data))
    
    # Store ephemeral typing state (5 seconds TTL)
    if typing_event.typing:
        await redis_client.setex(
            f"typing:{typing_event.chat_id}:{typing_event.user_id}",
            5,  # 5 seconds
            json.dumps(typing_data)
        )
    else:
        await redis_client.delete(f"typing:{typing_event.chat_id}:{typing_event.user_id}")
    
    return {"status": "published", "chat_id": typing_event.chat_id}


@router.get("/typing/{chat_id}")
async def get_typing_indicators(
    chat_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get current typing indicators for chat - WhatsApp style"""
    from ..redis_cache import redis_client
    
    # Verify user is member of chat
    if not await _is_user_in_chat(current_user, chat_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this chat")
    
    # Get all typing users in this chat
    typing_pattern = f"typing:{chat_id}:*"
    typing_keys = await redis_client.keys(typing_pattern)
    
    typing_users = []
    for key in typing_keys:
        typing_data = await redis_client.get(key)
        if typing_data:
            typing_event = json.loads(typing_data)
            if typing_event["typing"] and typing_event["user_id"] != current_user:
                typing_users.append({
                    "user_id": typing_event["user_id"],
                    "device_id": typing_event["device_id"],
                    "timestamp": typing_event["timestamp"]
                })
    
    return {
        "chat_id": chat_id,
        "typing_users": typing_users,
        "total_typing": len(typing_users)
    }


@router.post("/status")
async def update_presence_status(
    presence_update: PresenceUpdate,
    current_user: str = Depends(get_current_user)
):
    """Update presence status - WhatsApp style"""
    from ..redis_cache import redis_client
    
    # Verify user owns the presence update
    if presence_update.user_id != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
    
    # Get user's privacy settings
    privacy_settings = await _get_user_privacy_settings(current_user)
    
    # Create presence data
    presence_data = {
        "user_id": current_user,
        "status": presence_update.status,
        "last_seen": presence_update.last_seen.isoformat() if presence_update.last_seen else None,
        "privacy_level": privacy_settings["show_last_seen"],
        "device_count": presence_update.device_count,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Store presence with TTL (30 minutes for online, 24 hours for offline)
    ttl = 1800 if presence_update.status == PresenceStatus.ONLINE else 86400
    await redis_client.setex(f"presence:{current_user}", ttl, json.dumps(presence_data))
    
    # Publish to user's contacts (if privacy allows)
    if privacy_settings["show_last_seen"] or presence_update.status == PresenceStatus.ONLINE:
        await _publish_to_contacts(current_user, "presence", presence_data)
    
    return {"status": "updated", "presence_status": presence_update.status}


@router.get("/status/{user_id}")
async def get_user_presence(
    user_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get user presence status - WhatsApp style with privacy controls"""
    from ..redis_cache import redis_client
    
    # Get user's privacy settings
    privacy_settings = await _get_user_privacy_settings(user_id)
    
    # Check if current user can see this user's presence
    if not await _can_see_presence(current_user, user_id, privacy_settings):
        return {
            "user_id": user_id,
            "status": "hidden",
            "last_seen": None,
            "privacy_level": privacy_settings["show_last_seen"]
        }
    
    # Get presence data
    presence_data = await redis_client.get(f"presence:{user_id}")
    if not presence_data:
        # User not online, check if we have last seen
        return {
            "user_id": user_id,
            "status": PresenceStatus.OFFLINE,
            "last_seen": None,
            "privacy_level": privacy_settings["show_last_seen"]
        }
    
    presence = json.loads(presence_data)
    
    # Apply privacy filters
    if not privacy_settings["show_last_seen"]:
        presence["last_seen"] = None
    
    return presence


@router.post("/last-seen-settings")
async def update_last_seen_settings(
    settings: LastSeenSettings,
    current_user: str = Depends(get_current_user)
):
    """Update last seen privacy settings - WhatsApp style"""
    from ..redis_cache import redis_client
    
    # Validate privacy level
    valid_levels = [PrivacyLevel.EVERYONE, PrivacyLevel.CONTACTS, PrivacyLevel.NOBODY, PrivacyLevel.LAST_SEEN]
    if settings.privacy_level not in valid_levels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid privacy level. Must be one of: {valid_levels}"
        )
    
    # Store privacy settings
    privacy_data = {
        "show_last_seen": settings.show_last_seen,
        "privacy_level": settings.privacy_level,
        "custom_users": settings.custom_users,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    await redis_client.setex(
        f"privacy_settings:{current_user}",
        7 * 24 * 3600,  # 7 days
        json.dumps(privacy_data)
    )
    
    return {"status": "updated", "privacy_settings": privacy_data}


@router.get("/last-seen-settings")
async def get_last_seen_settings(
    current_user: str = Depends(get_current_user)
):
    """Get user's last seen privacy settings"""
    from ..redis_cache import redis_client
    
    privacy_data = await redis_client.get(f"privacy_settings:{current_user}")
    if not privacy_data:
        # Default settings
        return {
            "show_last_seen": True,
            "privacy_level": PrivacyLevel.CONTACTS,
            "custom_users": []
        }
    
    return json.loads(privacy_data)


@router.post("/online-status")
async def set_online_status(
    device_id: str,
    current_user: str = Depends(get_current_user)
):
    """Set user as online - WhatsApp style heartbeat"""
    from ..redis_cache import redis_client
    
    # Update device heartbeat
    await redis_client.setex(
        f"device_heartbeat:{current_user}:{device_id}",
        300,  # 5 minutes
        json.dumps({
            "device_id": device_id,
            "last_seen": datetime.now(timezone.utc).isoformat()
        })
    )
    
    # Count active devices
    pattern = f"device_heartbeat:{current_user}:*"
    device_keys = await redis_client.keys(pattern)
    active_devices = len(device_keys)
    
    # Update presence if this is the first active device
    if active_devices == 1:
        await update_presence_status(
            PresenceUpdate(
                user_id=current_user,
                status=PresenceStatus.ONLINE,
                device_count=active_devices
            ),
            current_user
        )
    
    return {
        "status": "online",
        "active_devices": active_devices,
        "device_id": device_id
    }


@router.post("/offline-status")
async def set_offline_status(
    device_id: str,
    current_user: str = Depends(get_current_user)
):
    """Set device as offline - WhatsApp style"""
    from ..redis_cache import redis_client
    
    # Remove device heartbeat
    await redis_client.delete(f"device_heartbeat:{current_user}:{device_id}")
    
    # Check remaining active devices
    pattern = f"device_heartbeat:{current_user}:*"
    device_keys = await redis_client.keys(pattern)
    active_devices = len(device_keys)
    
    # Update presence if no active devices
    if active_devices == 0:
        await update_presence_status(
            PresenceUpdate(
                user_id=current_user,
                status=PresenceStatus.OFFLINE,
                last_seen=datetime.now(timezone.utc),
                device_count=0
            ),
            current_user
        )
    
    return {
        "status": "offline",
        "active_devices": active_devices,
        "device_id": device_id
    }


# Helper functions
async def _is_user_in_chat(user_id: str, chat_id: str) -> bool:
    """Check if user is member of chat"""
    try:
        from ..db_proxy import chats_collection
        chat = await chats_collection().find_one({"_id": chat_id})
        if not chat:
            return False
        
        members = chat.get("members", chat.get("participants", chat.get("member_ids", [])))
        return user_id in members or str(user_id) in [str(m) for m in members]
    except Exception as e:
        logger.error(f"Error checking chat membership: {e}")
        return False


async def _get_user_privacy_settings(user_id: str) -> Dict:
    """Get user's privacy settings"""
    from ..redis_cache import redis_client
    
    privacy_data = await redis_client.get(f"privacy_settings:{user_id}")
    if not privacy_data:
        # Default settings
        return {
            "show_last_seen": True,
            "privacy_level": PrivacyLevel.CONTACTS,
            "custom_users": []
        }
    
    return json.loads(privacy_data)


async def _can_see_presence(requester_id: str, target_id: str, privacy_settings: Dict) -> bool:
    """Check if requester can see target's presence"""
    # If target doesn't show last seen to anyone
    if not privacy_settings["show_last_seen"]:
        return False
    
    # If target shows to everyone
    if privacy_settings["privacy_level"] == PrivacyLevel.EVERYONE:
        return True
    
    # If target shows to contacts, check if they're contacts
    if privacy_settings["privacy_level"] == PrivacyLevel.CONTACTS:
        return await _are_contacts(requester_id, target_id)
    
    # If target shows to nobody
    if privacy_settings["privacy_level"] == PrivacyLevel.NOBODY:
        return False
    
    # If custom users, check if requester is in custom list
    if privacy_settings["privacy_level"] == PrivacyLevel.LAST_SEEN:
        return requester_id in privacy_settings.get("custom_users", [])
    
    return False


async def _are_contacts(user_id1: str, user_id2: str) -> bool:
    """Check if two users are contacts"""
    try:
        from ..db_proxy import users_collection
        user1 = await users_collection().find_one({"_id": user_id1})
        if not user1:
            return False
        
        contacts = user1.get("contacts", [])
        return user_id2 in contacts or str(user_id2) in [str(c) for c in contacts]
    except Exception as e:
        logger.error(f"Error checking contact status: {e}")
        return False


async def _publish_to_contacts(user_id: str, event_type: str, data: Dict):
    """Publish event to user's contacts"""
    try:
        from ..db_proxy import users_collection
        user = await users_collection().find_one({"_id": user_id})
        if not user:
            return
        
        contacts = user.get("contacts", [])
        from ..redis_cache import redis_client
        
        for contact_id in contacts:
            await redis_client.publish(f"user_channel:{contact_id}", json.dumps({
                "type": event_type,
                "from_user": user_id,
                "data": data
            }))
            
    except Exception as e:
        logger.error(f"Error publishing to contacts: {e}")


# Background task to clean up expired presence data
async def cleanup_expired_presence():
    """Clean up expired presence and typing data"""
    from ..redis_cache import redis_client
    
    try:
        # Clean up expired typing indicators
        typing_pattern = "typing:*"
        typing_keys = await redis_client.keys(typing_pattern)
        
        for key in typing_keys:
            ttl = await redis_client.ttl(key)
            if ttl == -1:  # No TTL set, clean up
                await redis_client.delete(key)
        
        # Clean up offline presence data older than 24 hours
        presence_pattern = "presence:*"
        presence_keys = await redis_client.keys(presence_pattern)
        
        for key in presence_keys:
            presence_data = await redis_client.get(key)
            if presence_data:
                presence = json.loads(presence_data)
                if presence.get("status") == PresenceStatus.OFFLINE:
                    # Check if older than 24 hours
                    updated_at = datetime.fromisoformat(presence.get("updated_at", ""))
                    if datetime.now(timezone.utc) - updated_at > timedelta(hours=24):
                        await redis_client.delete(key)
        
    except Exception as e:
        logger.error(f"Error in presence cleanup: {e}")


# WebSocket handler for real-time presence updates
async def handle_presence_websocket(websocket, user_id: str):
    """Handle WebSocket connection for presence updates"""
    from ..redis_cache import redis_client
    
    # Subscribe to user's presence channel
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(f"user_channel:{user_id}")
    
    try:
        while True:
            message = await pubsub.get_message(timeout=1)
            if message:
                data = json.loads(message["data"])
                await websocket.send_json(data)
    except Exception as e:
        logger.error(f"Presence WebSocket error: {e}")
    finally:
        await pubsub.close()
