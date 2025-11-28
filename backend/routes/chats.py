from fastapi import APIRouter, HTTPException, status, Depends
from typing import List, Optional
from datetime import datetime
from bson import ObjectId
from backend.models import ChatCreate, ChatInDB, MessageCreate, MessageInDB, UserResponse
from backend.database import chats_collection, messages_collection, users_collection
from backend.auth.utils import get_current_user

router = APIRouter(prefix="/chats", tags=["Chats"])


@router.get("/saved", response_model=dict)
async def get_or_create_saved_chat(current_user: str = Depends(get_current_user)):
    """Get or create the personal Saved Messages chat for the current user"""
    existing = await chats_collection().find_one({"type": "saved", "members": current_user})
    if existing:
        return {"chat_id": existing["_id"], "chat": existing}

    chat_doc = {
        "_id": str(ObjectId()),
        "type": "saved",
        "name": "Saved Messages",
        "members": [current_user],
        "created_at": datetime.utcnow()
    }
    await chats_collection().insert_one(chat_doc)
    return {"chat_id": chat_doc["_id"], "chat": chat_doc}


@router.post("/", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_chat(chat: ChatCreate, current_user: str = Depends(get_current_user)):
    """Create a new chat (private or group)"""
    
    # Validate members
    if current_user not in chat.member_ids:
        chat.member_ids.append(current_user)
    
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
        "created_at": datetime.utcnow()
    }
    
    await messages_collection().insert_one(msg_doc)
    
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


@router.get("/messages/saved")
async def get_saved_messages(
    current_user: str = Depends(get_current_user),
    limit: int = 50
):
    """Get all messages saved by current user"""
    
    messages = []
    async for msg in messages_collection().find({"saved_by": current_user}).sort("created_at", -1).limit(limit):
        messages.append(msg)
    
    return {"messages": list(reversed(messages))}
