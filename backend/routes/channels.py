from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from datetime import datetime, timezone
from bson import ObjectId
import logging

from auth.utils import get_current_user
from db_proxy import chats_collection, messages_collection
from models import ChatCreate, MessageCreate, ChatType, ChatPermissions
from database import client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/channels", tags=["Channels"])

# OPTIONS handlers for CORS preflight requests
@router.options("")
@router.options("/{channel_id}")
@router.options("/{channel_id}/subscribe")
@router.options("/{channel_id}/unsubscribe")
@router.options("/{channel_id}/posts")
@router.options("/{channel_id}/remove")
@router.options("/{channel_id}/posts/{message_id}/view")
async def channels_options():
    """Handle CORS preflight for channels endpoints"""
    from fastapi.responses import Response
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400"
        }
    )

async def _get_channel(channel_id: str) -> dict:
    channel = await chats_collection().find_one({"_id": channel_id, "type": ChatType.CHANNEL})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    return channel

async def _check_admin(channel: dict, user_id: str) -> bool:
    return user_id in channel.get("admins", []) or user_id == channel.get("owner_id")

@router.post("", status_code=status.HTTP_201_CREATED)
async def create_channel(payload: ChatCreate, current_user: str = Depends(get_current_user)):
    """Create a new broadcast channel"""
    if not payload.name:
        raise HTTPException(status_code=400, detail="Channel name is required")
    
    # Check for username uniqueness if provided
    if payload.username:
        existing = await chats_collection().find_one({"username": payload.username})
        if existing:
            raise HTTPException(status_code=400, detail="Username already taken")

    channel_id = str(ObjectId())
    channel_doc = {
        "_id": channel_id,
        "type": ChatType.CHANNEL,
        "name": payload.name,
        "description": payload.description,
        "username": payload.username,
        "avatar_url": payload.avatar_url,
        "owner_id": current_user,
        "admins": [current_user],
        "members": [current_user], # Creator is first subscriber
        "member_count": 1,
        "created_at": datetime.now(timezone.utc),
        "permissions": ChatPermissions().model_dump(), # Default permissions
        "views_count": 0
    }
    
    await chats_collection().insert_one(channel_doc)
    logger.info(f"Channel created: {channel_id} by {current_user}")
    
    return {"channel_id": channel_id, "channel": channel_doc}

@router.get("/{channel_id}")
async def get_channel_info(channel_id: str, current_user: str = Depends(get_current_user)):
    """Get channel info (public or private if member)"""
    channel = await _get_channel(channel_id)
    
    # If private channel, check membership
    is_public = channel.get("username") is not None
    is_member = current_user in channel.get("members", [])
    
    if not is_public and not is_member:
        raise HTTPException(status_code=403, detail="This is a private channel")
        
    return {
        "channel": channel,
        "is_member": is_member,
        "is_admin": await _check_admin(channel, current_user)
    }

@router.post("/{channel_id}/subscribe")
async def subscribe_channel(channel_id: str, current_user: str = Depends(get_current_user)):
    """Subscribe/Join a channel"""
    channel = await _get_channel(channel_id)
    
    if current_user in channel.get("members", []):
         return {"status": "already_subscribed"}
         
    # Check if private and not invited (simplification: private channels need invite link logic, skipping for now)
    # If it has a username it's public.
    if not channel.get("username") and current_user not in channel.get("invited_ids", []):
         # For now, allow join if they have the ID (link sharing logic to be improved)
         pass

    # Update channel atomically with proper member count
    result = await chats_collection().update_one(
        {"_id": channel_id},
        {
            "$addToSet": {"members": current_user}
        }
    )
        
    if result.modified_count > 0:
        # Recalculate member count to avoid race conditions
        channel = await chats_collection().find_one({"_id": channel_id})
        if channel:
            new_member_count = len(channel.get("members", []))
            await chats_collection().update_one(
                {"_id": channel_id},
                {"$set": {"member_count": new_member_count}}
            )
    return {"status": "subscribed"}

@router.post("/{channel_id}/unsubscribe")
async def unsubscribe_channel(channel_id: str, current_user: str = Depends(get_current_user)):
    """Leave a channel"""
    channel = await _get_channel(channel_id)
    
    if current_user == channel.get("owner_id"):
        raise HTTPException(status_code=400, detail="Owner cannot leave. Delete channel instead.")

    result = await chats_collection().update_one(
        {"_id": channel_id},
        {
            "$pull": {"members": current_user, "admins": current_user}
        }
    )
    
    if result.modified_count > 0:
        # Recalculate member count to avoid race conditions
        channel = await chats_collection().find_one({"_id": channel_id})
        if channel:
            new_member_count = len(channel.get("members", []))
            await chats_collection().update_one(
                {"_id": channel_id},
                {"$set": {"member_count": new_member_count}}
            )
    return {"status": "unsubscribed"}

@router.post("/{channel_id}/posts", status_code=201)
async def post_to_channel(
    channel_id: str, 
    message: MessageCreate, 
    current_user: str = Depends(get_current_user)
):
    """Admin only: Post message to channel"""
    channel = await _get_channel(channel_id)
    
    if not await _check_admin(channel, current_user):
        raise HTTPException(status_code=403, detail="Only admins can post in this channel")

    msg_type = "file" if message.file_id else "text"
    msg_doc = {
        "_id": str(ObjectId()),
        "chat_id": channel_id,
        "sender_id": current_user, # Or system ID if anonymous
        "type": msg_type,
        "text": message.text,
        "file_id": message.file_id,
        "created_at": datetime.now(timezone.utc),
        "views": 0,
        "author_signature": channel.get("name") # Default to channel name
    }
    
    await messages_collection().insert_one(msg_doc)
    
    # Update channel updated_at
    await chats_collection().update_one(
        {"_id": channel_id},
        {"$set": {"updated_at": datetime.now(timezone.utc)}}
    )
    
    return {"message_id": msg_doc["_id"], "post": msg_doc}




@router.post("/{channel_id}/remove", status_code=200)
async def remove_channel(channel_id: str, current_user: str = Depends(get_current_user)):
    """Remove a channel (admin/owner only). Deletes channel and all its messages atomically."""
    channel = await _get_channel(channel_id)
    if not await _check_admin(channel, current_user):
        raise HTTPException(status_code=403, detail="Only admins/owner can remove the channel")
    if current_user != channel.get("owner_id"):
        raise HTTPException(status_code=403, detail="Only the owner can remove the channel")

    # Use MongoDB transaction for atomicity
    async with await client.start_session() as s:
        async with s.start_transaction():
            await messages_collection().delete_many({"chat_id": channel_id}, session=s)
            await chats_collection().delete_one({"_id": channel_id}, session=s)
    logger.info(f"Channel removed: {channel_id} by {current_user}")
    return {"status": "removed", "channel_id": channel_id}

@router.post("/{channel_id}/posts/{message_id}/view")
async def view_post(channel_id: str, message_id: str):
    """Increment view counter (can be called by any unauthenticated user if public)"""
    # Simple increment, in production would need unique view tracking (Redis/HyperLogLog)
    await messages_collection().update_one(
        {"_id": message_id},
        {"$inc": {"views": 1}}
    )
    return {"status": "ok"}
