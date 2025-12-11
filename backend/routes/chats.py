from fastapi import APIRouter, HTTPException, status, Depends
from typing import Optional
from datetime import datetime
from bson import ObjectId
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from models import ChatCreate, MessageCreate
from database import chats_collection, messages_collection
from auth.utils import get_current_user
import logging

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

router = APIRouter(prefix="/chats", tags=["Chats"])


@router.get("/saved", response_model=dict)
async def get_or_create_saved_chat(current_user: str = Depends(get_current_user)):
    """Get or create the personal Saved Messages chat for the current user"""
    logger.info(f"Looking for saved chat for user: {current_user}")
    existing = await chats_collection().find_one({"type": "saved", "members": current_user})
    if existing:
        logger.info(f"Found existing saved chat: {existing['_id']}")
        return {"chat_id": existing["_id"], "chat": existing}

    logger.info(f"Creating new saved chat for user: {current_user}")
    chat_doc = {
        "_id": str(ObjectId()),
        "type": "saved",
        "name": "Saved Messages",
        "members": [current_user],
        "created_at": datetime.utcnow()
    }
    await chats_collection().insert_one(chat_doc)
    logger.info(f"Created new saved chat: {chat_doc['_id']}")
    return {"chat_id": chat_doc["_id"], "chat": chat_doc}


# IMPORTANT: This route MUST come BEFORE /{chat_id}/messages
# Otherwise FastAPI will match "messages" as a chat_id
@router.get("/messages/saved")
async def get_saved_messages(
    current_user: str = Depends(get_current_user),
    limit: int = 50
):
    """Get all messages saved by current user"""
    
    logger.info(f"Getting saved messages for user: {current_user}")
    messages = []
    async for msg in messages_collection().find({"saved_by": current_user}).sort("created_at", -1).limit(limit):
        messages.append(msg)
    
    logger.info(f"Found {len(messages)} saved messages for user: {current_user}")
    return {"messages": list(reversed(messages))}


@router.post("/", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_chat(chat: ChatCreate, current_user: str = Depends(get_current_user)):
    """Create a new chat (private, group, channel, or saved)"""
    
    # Validate chat type
    valid_types = ["private", "group", "channel", "saved"]
    if chat.type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid chat type. Must be one of: {', '.join(valid_types)}"
        )
    
    # Ensure current user is in members
    if current_user not in chat.member_ids:
        chat.member_ids.append(current_user)
    
    # Validate members based on type
    if chat.type == "private" and len(chat.member_ids) != 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Private chats must have exactly 2 members"
        )
    if chat.type == "saved" and len(chat.member_ids) != 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Saved chat must have exactly 1 member (yourself)"
        )
    
    # For group and channel: name is required
    if chat.type in ["group", "channel"] and not chat.name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{chat.type.capitalize()} must have a name"
        )
    
    # Check if private or saved chat already exists
    if chat.type == "private":
        existing = await chats_collection().find_one({
            "type": "private",
            "members": {"$all": chat.member_ids}
        })
        if existing:
            return {"chat_id": existing["_id"], "message": "Chat already exists"}
    if chat.type == "saved":
        existing = await chats_collection().find_one({
            "type": "saved",
            "members": current_user
        })
        if existing:
            return {"chat_id": existing["_id"], "message": "Chat already exists"}
    
    # Create chat document
    chat_doc = {
        "_id": str(ObjectId()),
        "type": chat.type,
        "name": chat.name,
        "members": chat.member_ids,
        "created_at": datetime.utcnow()
    }

    # Default name for saved chat
    if chat_doc["type"] == "saved" and not chat_doc["name"]:
        chat_doc["name"] = "Saved Messages"
    
    await chats_collection().insert_one(chat_doc)
    
    return {"chat_id": chat_doc["_id"], "message": "Chat created"}


@router.get("/")
async def list_chats(current_user: str = Depends(get_current_user)):
    """List all chats for current user"""
    
    chats = []
    async for chat in chats_collection().find({"members": current_user}).sort("created_at", -1):
        # Get last message
        last_message = await messages_collection().find_one(
            {"chat_id": chat["_id"]},
            sort=[("created_at", -1)]
        )
        
        chat["last_message"] = last_message
        chats.append(chat)
    
    return {"chats": chats}


@router.get("/{chat_id}")
async def get_chat(chat_id: str, current_user: str = Depends(get_current_user)):
    """Get chat details"""
    
    chat = await chats_collection().find_one({"_id": chat_id, "members": current_user})
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )
    
    return chat


@router.get("/{chat_id}/messages")
async def get_messages(
    chat_id: str,
    limit: int = 50,
    before: Optional[str] = None,
    current_user: str = Depends(get_current_user)
):
    """Get messages in a chat with pagination"""
    
    # Verify user is member
    chat = await chats_collection().find_one({"_id": chat_id, "members": current_user})
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )
    
    # Build query
    query = {"chat_id": chat_id}
    if before:
        before_msg = await messages_collection().find_one({"_id": before})
        if before_msg:
            query["created_at"] = {"$lt": before_msg["created_at"]}
    
    # Fetch messages
    messages = []
    async for msg in messages_collection().find(query).sort("created_at", -1).limit(limit):
        messages.append(msg)
    
    return {"messages": list(reversed(messages))}


@router.post("/{chat_id}/messages", status_code=status.HTTP_201_CREATED)
async def send_message(
    chat_id: str,
    message: MessageCreate,
    current_user: str = Depends(get_current_user)
):
    """Send a message in a chat"""
    
    # Verify user is member
    chat = await chats_collection().find_one({"_id": chat_id, "members": current_user})
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )
    
    # Validate message
    if not message.text and not message.file_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message must have text or file_id"
        )
    
    # Create message document
    msg_type = "file" if message.file_id else "text"
    msg_doc = {
        "_id": str(ObjectId()),
        "chat_id": chat_id,
        "sender_id": current_user,
        "type": msg_type,
        "text": message.text,
        "file_id": message.file_id,
        # Store language code if provided (frontend may send it)
        "language": message.language,
        "created_at": datetime.utcnow()
    }
    
    # If this is a saved chat, automatically mark as saved by the user
    chat = await chats_collection().find_one({"_id": chat_id})
    if chat and chat.get("type") == "saved":
        msg_doc["saved_by"] = [current_user]
        logger.info(f"Message sent to saved chat, marking as saved for user: {current_user}")
    
    await messages_collection().insert_one(msg_doc)
    logger.info(f"Message inserted with ID: {msg_doc['_id']}")
    
    return {"message_id": msg_doc["_id"], "created_at": msg_doc["created_at"]}


@router.post("/messages/{message_id}/save", status_code=status.HTTP_200_OK)
async def save_message(
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Save a message to Saved Messages"""
    
    # Find the message
    message = await messages_collection().find_one({"_id": message_id})
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Verify user is member of the chat
    chat = await chats_collection().find_one({"_id": message["chat_id"], "members": current_user})
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this message"
        )
    
    # Add user to saved_by list if not already there
    if current_user not in message.get("saved_by", []):
        await messages_collection().update_one(
            {"_id": message_id},
            {"$push": {"saved_by": current_user}}
        )
    
    return {"status": "saved"}


@router.post("/messages/{message_id}/unsave", status_code=status.HTTP_200_OK)
async def unsave_message(
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Unsave a message from Saved Messages"""
    
    # Find the message
    message = await messages_collection().find_one({"_id": message_id})
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Verify user is member of the chat
    chat = await chats_collection().find_one({"_id": message["chat_id"], "members": current_user})
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this message"
        )
    
    # Remove user from saved_by list
    await messages_collection().update_one(
        {"_id": message_id},
        {"$pull": {"saved_by": current_user}}
    )
    
    return {"status": "unsaved"}


@router.patch("/{message_id}/edit")
async def edit_message(
    message_id: str,
    edit_data: dict,
    current_user: str = Depends(get_current_user)
):
    """Edit a message (only by sender)"""
    message = await messages_collection().find_one({"_id": message_id})
    
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    if message["sender_id"] != current_user:
        raise HTTPException(status_code=403, detail="Can only edit your own messages")
    
    new_text = edit_data.get("text", "").strip()
    if not new_text:
        raise HTTPException(status_code=400, detail="Message text cannot be empty")
    
    await messages_collection().update_one(
        {"_id": message_id},
        {"$set": {
            "text": new_text,
            "edited_at": datetime.utcnow(),
            "is_edited": True
        }}
    )
    
    return {"status": "edited", "message_id": message_id}


@router.post("/{message_id}/react")
async def react_to_message(
    message_id: str,
    reaction_data: dict,
    current_user: str = Depends(get_current_user)
):
    """Add emoji reaction to a message"""
    emoji = reaction_data.get("emoji", "").strip()
    
    if not emoji:
        raise HTTPException(status_code=400, detail="Emoji required")
    
    message = await messages_collection().find_one({"_id": message_id})
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    reactions = message.get("reactions", {})
    if emoji not in reactions:
        reactions[emoji] = []
    
    if current_user not in reactions[emoji]:
        reactions[emoji].append(current_user)
    
    await messages_collection().update_one(
        {"_id": message_id},
        {"$set": {"reactions": reactions}}
    )
    
    return {"status": "reacted", "emoji": emoji}


@router.post("/{message_id}/pin")
async def pin_message(
    chat_id: str,
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Pin a message to the top of chat"""
    chat = await chats_collection().find_one({"_id": chat_id, "members": current_user})
    if not chat:
        raise HTTPException(status_code=403, detail="Not a member of this chat")
    
    message = await messages_collection().find_one({"_id": message_id})
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    await messages_collection().update_one(
        {"_id": message_id},
        {"$set": {"is_pinned": True}}
    )
    
    return {"status": "pinned", "message_id": message_id}


@router.delete("/{message_id}")
async def delete_message(
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Delete a message"""
    message = await messages_collection().find_one({"_id": message_id})
    
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    if message["sender_id"] != current_user:
        raise HTTPException(status_code=403, detail="Can only delete your own messages")
    
    await messages_collection().delete_one({"_id": message_id})
    
    return {"status": "deleted", "message_id": message_id}
