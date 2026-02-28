from fastapi import APIRouter, HTTPException, status, Depends, Request
from typing import Optional
from datetime import datetime, timezone
from bson import ObjectId
import asyncio

try:
    from ..models import ChatCreate, MessageCreate, ChatType
    from ..db_proxy import chats_collection, messages_collection, users_collection
except ImportError:
    from models import ChatCreate, MessageCreate, ChatType
    from db_proxy import chats_collection, messages_collection, users_collection

from auth.utils import get_current_user, get_current_user_for_upload
import logging

import sys

sys.modules.setdefault("routes.chats", sys.modules[__name__])
sys.modules.setdefault("backend.routes.chats", sys.modules[__name__])

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

router = APIRouter(prefix="", tags=["Chats"])


def _parse_object_id(value: str, field_name: str) -> ObjectId:
    if not value or not isinstance(value, str) or not ObjectId.is_valid(value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name}"
        )
    return ObjectId(value)


def _to_json_safe(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, dict):
        return {k: _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json_safe(v) for v in value]
    return value

# OPTIONS handlers for CORS preflight requests
@router.options("/saved")
@router.options("/messages/saved")
@router.options("")
@router.options("/{chat_id}")
@router.options("/{chat_id}/pin_chat")
@router.options("/{chat_id}/unpin_chat")
@router.options("/{chat_id}/messages")
@router.options("/messages/{message_id}/save")
@router.options("/messages/{message_id}/unsave")
@router.options("/messages/{message_id}/react")
@router.options("/messages/{message_id}/pin")
@router.options("/{chat_id}/messages/{message_id}")
@router.options("/{message_id}")
@router.options("/{chat_id}/ban")
@router.options("/{chat_id}/unban")
@router.options("/{chat_id}/banned")
async def chats_options():
    """Handle CORS preflight for chats endpoints"""
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


@router.get("/saved", response_model=dict)
async def get_or_create_saved_chat(current_user: Optional[str] = Depends(get_current_user)):
    """Get or create personal Saved Messages chat for current user"""
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authentication credentials")
    logger.info(f"Looking for saved chat for user: {current_user}")
    # CRITICAL FIX: Use case-insensitive search for database name compatibility
    existing = await chats_collection().find_one({
        "type": "saved", 
        "members": current_user
    })
    # Fallback: Try case-insensitive search if exact match fails
    if not existing:
        logger.info(f"Exact match failed, trying case-insensitive search for user: {current_user}")
        # Get all saved chats and filter by members case-insensitively
        all_saved_cursor = chats_collection().find({"type": "saved"})
        if asyncio.iscoroutine(all_saved_cursor) or (hasattr(all_saved_cursor, "__await__") and not hasattr(all_saved_cursor, "__aiter__")):
            all_saved_cursor = await all_saved_cursor
        all_saved = await all_saved_cursor.to_list(length=None)
        
        # Search for existing chat with current user as member
        existing = None
        for chat in all_saved:
            members = chat.get("members", [])
            if any(str(member).lower() == str(current_user).lower() for member in members):
                existing = chat
                logger.info(f"Found saved chat with case-insensitive match: {existing['_id']}")
                break
    if existing:
        logger.info(f"Found existing saved chat: {existing['_id']}")
        return {
            "chat_id": str(existing["_id"]),
            "name": existing.get("name", "Saved Messages"),
            "type": existing.get("type", "saved")
        }

    logger.info(f"Creating new saved chat for user: {current_user}")
    chat_doc = {
        "type": "saved",
        "name": "Saved Messages",
        "members": [current_user],
        "created_at": datetime.now(timezone.utc)
    }
    # CRITICAL FIX: Let Atlas generate the ObjectId, don't pre-generate
    result = await chats_collection().insert_one(chat_doc)
    inserted_id = result.inserted_id
    logger.info(f"Created new saved chat with Atlas ObjectId: {inserted_id}")
    return {
        "chat_id": str(inserted_id),
        "name": chat_doc["name"],
        "type": chat_doc["type"]
    }


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

    cursor = messages_collection().find({"saved_by": current_user})
    if asyncio.iscoroutine(cursor):
        cursor = await cursor

    if hasattr(cursor, "__aiter__"):
        async for msg in cursor:
            messages.append(msg)
    elif hasattr(cursor, "to_list"):
        messages = await cursor.to_list(length=limit)
    else:
        try:
            messages = list(cursor)
        except Exception:
            messages = []
    
    # Sort messages by created_at in ascending order (oldest first), preserving insertion order for equal timestamps
    messages.sort(key=lambda x: x.get("created_at", datetime.now(timezone.utc)))
    
    logger.info(f"Found {len(messages)} saved messages for user: {current_user}")
    return {"messages": messages}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_chat_root(chat: ChatCreate, current_user: str = Depends(get_current_user)):
    """Create a new chat (private, group, channel, or saved) - root endpoint"""
    
    # Backward compatibility: convert 'direct' to 'private' at route level too
    if chat.type == 'direct':
        chat.type = 'private'
    
    return await create_chat(chat, current_user)


@router.post("/create")
async def create_chat(chat: ChatCreate, current_user: str = Depends(get_current_user)):
    """Create a new chat (private, group, channel, or saved)"""
    
    # Backward compatibility: convert 'direct' to 'private' at route level too
    if chat.type == 'direct':
        chat.type = 'private'

    valid_types = [
        ChatType.PRIVATE,
        ChatType.GROUP,
        ChatType.SUPERGROUP,
        ChatType.CHANNEL,
        ChatType.SECRET,
        ChatType.SAVED,
    ]
    if chat.type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid chat type. Must be one of: {', '.join(valid_types)}",
        )
    
    # Chat type validation is now handled by the model validator
    # Ensure current user is in members FIRST, before validation
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
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Private chat with these members already exists"
            )
    if chat.type == "saved":
        existing = await chats_collection().find_one({
            "type": "saved",
            "members": current_user
        })
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Saved messages chat already exists for this user"
            )
    
    # Create chat document
    chat_doc = {
        "type": chat.type,
        "name": chat.name,
        "description": getattr(chat, "description", None),
        "avatar_url": getattr(chat, "avatar_url", None),
        "members": chat.member_ids,
        "created_at": datetime.now(timezone.utc)
    }

    # Group/channel metadata
    if chat_doc["type"] in ["group", "channel"]:
        chat_doc["created_by"] = current_user
        chat_doc["admins"] = [current_user]
        chat_doc["muted_by"] = []

    # Default name for saved chat
    if chat_doc["type"] == "saved" and not chat_doc["name"]:
        chat_doc["name"] = "Saved Messages"
    
    result = await chats_collection().insert_one(chat_doc)
    inserted_id = result.inserted_id
    inserted_id_str = str(inserted_id)
    
    return {
        "chat_id": inserted_id_str,
        "id": inserted_id_str,  # Frontend compatibility
        "_id": inserted_id_str,  # Frontend compatibility
        "message": "Chat created"
    }


@router.get("")
async def list_chats(current_user: str = Depends(get_current_user)):
    """List all chats for current user"""
    print(f"[CHATS_LIST] Request from user: {current_user}")
    
    try:
        # Get user's pinned chats once
        user_doc = await users_collection().find_one({"_id": current_user}, {"pinned_chats": 1})
        pinned_chats = user_doc.get("pinned_chats", []) if user_doc else []
        
        chats = []
        cursor = chats_collection().find({"members": {"$in": [current_user]}}).sort("created_at", -1)
        
        async for chat in cursor:
            # Get last message
            last_message = await messages_collection().find_one(
                {"chat_id": {"$in": [str(chat["_id"]), chat["_id"]]}},
                sort=[("created_at", -1)],
            )
            
            chat["last_message"] = last_message
            
            # Add display fields for UI
            try:
                if chat.get("type") == "private":
                    # Best-effort resolve other user's name
                    members = chat.get("members", [])
                    other_id = None
                    for mid in members:
                        if mid != current_user:
                            other_id = mid
                            break
                    if other_id:
                        other_user = await users_collection().find_one({"_id": other_id}, {"name": 1, "avatar_url": 1})
                        if other_user:
                            chat["display_name"] = other_user.get("name") or "Private Chat"
                            chat["avatar_url"] = other_user.get("avatar_url")
                        else:
                            chat["display_name"] = "Private Chat"
                    else:
                        chat["display_name"] = "Private Chat"
                else:
                    chat["display_name"] = chat.get("name") or chat.get("type", "Chat").capitalize()

                # For group chats, include sender name in last message
                if chat.get("type") == "group" and last_message and last_message.get("sender_id"):
                    sender = await users_collection().find_one({"_id": last_message["sender_id"]}, {"name": 1})
                    chat["last_message_sender_name"] = sender.get("name") if sender else None
            except Exception as e:
                # Don't break listing if enrichment fails
                print(f"[CHATS_LIST] Warning enriching chat: {str(e)}")
                pass
            
            # Check if pinned by user
            chat["is_pinned"] = chat["_id"] in pinned_chats
            chats.append(chat)
        
        # Sort: Pinned first, then by last/created date
        def get_sort_key(x):
            is_pinned = x.get("is_pinned", False)
            # Use last message time if available, otherwise chat creation time
            last_msg = x.get("last_message")
            msg_time = last_msg.get("created_at") if last_msg else None
            chat_time = x.get("created_at")
            
            # Ensure we have a valid datetime for sorting
            # If msg_time is None (no messages), fall back to chat_time
            sort_time = msg_time if msg_time else chat_time
            # Return tuple for sorting (pinned first, then by time)
            return (is_pinned, sort_time)

        chats.sort(key=get_sort_key, reverse=True)
        
        print(f"[CHATS_LIST] SUCCESS: Retrieved {len(chats)} chats for user {current_user}")
        return {"chats": _to_json_safe(chats)}
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[CHATS_LIST] ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error retrieving chats: {str(e)}")


@router.post("/{chat_id}/pin_chat")
async def pin_chat(chat_id: str, current_user: str = Depends(get_current_user)):
    """Pin a chat to the top of the list for current user"""
    # Verify chat existence and membership
    chat_oid = _parse_object_id(chat_id, "chat_id")
    chat = await chats_collection().find_one({"_id": chat_oid, "members": {"$in": [current_user]}})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
        
    await users_collection().update_one(
        {"_id": current_user},
        {"$addToSet": {"pinned_chats": str(chat_oid)}}
    )
    return {"status": "pinned", "chat_id": str(chat_oid)}


@router.post("/{chat_id}/unpin_chat")
async def unpin_chat(chat_id: str, current_user: str = Depends(get_current_user)):
    """Unpin a chat"""
    chat_oid = _parse_object_id(chat_id, "chat_id")
    await users_collection().update_one(
        {"_id": current_user},
        {"$pull": {"pinned_chats": str(chat_oid)}}
    )
    return {"status": "unpinned", "chat_id": str(chat_oid)}


@router.get("/{chat_id}")
async def get_chat(chat_id: str, current_user: str = Depends(get_current_user)):
    """Get chat details"""
    
    chat_oid = _parse_object_id(chat_id, "chat_id")
    chat = await chats_collection().find_one({"_id": chat_oid, "members": {"$in": [current_user]}})
    if not chat:
        # Backward compatibility: older data stored chats._id as a string.
        chat = await chats_collection().find_one({"_id": chat_id, "members": {"$in": [current_user]}})
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )
    
    return chat


@router.get("/{chat_id}/messages")
async def get_messages_route(
    chat_id: str,
    request: Request,
    limit: int = 50,
    offset: int = 0,
    before: Optional[str] = None,
    current_user: str = Depends(get_current_user)
):
    return await get_messages(
        chat_id=chat_id,
        request=request,
        limit=limit,
        offset=offset,
        before=before,
        current_user=current_user,
    )


async def get_messages(
    chat_id: str,
    request=None,
    limit: int = 50,
    offset: int = 0,
    before: Optional[str] = None,
    current_user: str = None,
):
    """Get messages in a chat with pagination"""

    chat_oid = _parse_object_id(chat_id, "chat_id")

    db = None
    if request is not None:
        # Query Atlas directly from app state (authoritative)
        state = getattr(getattr(request, "app", None), "state", None)
        db = getattr(state, "db", None)
    if db is None:
        from database import get_database
        db = get_database()
    chats_col = db["chats"]
    msgs_col = db["messages"]

    # Verify user is member
    chat = await chats_col.find_one({"_id": chat_oid, "members": {"$in": [current_user]}})
    chat_key = chat_oid
    if not chat:
        # Backward compatibility: older data stored chats._id as a string.
        chat = await chats_col.find_one({"_id": chat_id, "members": {"$in": [current_user]}})
        chat_key = chat_id
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )

    # Build query
    # Support both Atlas ObjectId schema and legacy string chat_id schema
    query = {"chat_id": chat_key}
    if before:
        before_oid = _parse_object_id(before, "before")
        before_msg = await msgs_col.find_one({"_id": before_oid}, {"created_at": 1})
        if before_msg and before_msg.get("created_at") is not None:
            query = {
                "$and": [
                    query,
                    {"created_at": {"$lt": before_msg["created_at"]}},
                ]
            }

    if limit < 1:
        limit = 1
    if limit > 200:
        limit = 200
    if offset < 0:
        offset = 0

    total = await msgs_col.count_documents(query)

    messages = []
    cursor = msgs_col.find(query).sort("created_at", 1).skip(offset).limit(limit)
    async for msg in cursor:
        messages.append(msg)

    return {
        "messages": _to_json_safe(messages),
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.post("/{chat_id}/messages", status_code=status.HTTP_201_CREATED)
async def send_message(
    chat_id: str,
    request: Request,
    message: MessageCreate,
    current_user: str = Depends(get_current_user)
):
    """Send a message in a chat"""

    chat_oid = _parse_object_id(chat_id, "chat_id")

    # Verify user is member
    chat = await chats_collection().find_one({"_id": chat_oid, "members": {"$in": [current_user]}})
    chat_key = chat_oid
    if not chat:
        # Backward compatibility: older data stored chats._id as a string.
        chat = await chats_collection().find_one({"_id": chat_id, "members": {"$in": [current_user]}})
        chat_key = chat_id
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
    
    if not ObjectId.is_valid(current_user):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user_id")

    # Create message document (Atlas ObjectId schema)
    msg_type = "file" if message.file_id else "text"
    now = datetime.now(timezone.utc)
    msg_doc = {
        # Support legacy string chat ids as well.
        "chat_id": chat_key,
        "sender_id": ObjectId(current_user),
        "content": message.text,
        "type": msg_type,
        "created_at": now,
        # Backward compatibility fields still used in other parts of the codebase
        "text": message.text,
        "file_id": message.file_id,
        "language": message.language,
        "reply_to_message_id": message.reply_to_message_id,
        "scheduled_at": message.scheduled_at,
        "reactions": {},
        "read_by": [{"user_id": ObjectId(current_user), "read_at": now}],
        "is_pinned": False,
        "is_edited": False,
        "edit_history": [],
        "is_deleted": False,
    }
    
    # If this is a saved chat, automatically mark as saved by the user
    if chat.get("type") == "saved":
        msg_doc["saved_by"] = [ObjectId(current_user)]
        logger.info(f"Message sent to saved chat, marking as saved for user: {current_user}")
    
    result = await messages_collection().insert_one(msg_doc)
    inserted_id = result.inserted_id
    logger.info(f"Message inserted with ID: {inserted_id}")

    # Update chat last_message and updated_at
    await chats_collection().update_one(
        {"_id": chat_key},
        {
            "$set": {
                "last_message": {
                    "message_id": inserted_id,
                    "sender_id": ObjectId(current_user),
                    "type": msg_type,
                    "content": message.text,
                    "created_at": now,
                },
                "updated_at": now,
            }
        },
    )
    
    return {"message_id": str(inserted_id), "created_at": msg_doc["created_at"]}


@router.post("/messages/{message_id}/save", status_code=status.HTTP_200_OK)
async def save_message(
    message_id: str,
    current_user: str = Depends(get_current_user)
):
    """Save a message to Saved Messages"""
    
    # Find message
    message = await messages_collection().find_one({"_id": message_id})
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Verify user is member of chat
    chat = await chats_collection().find_one({"_id": message["chat_id"], "members": {"$in": [current_user]}})
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this message"
        )
    
    # Add user to saved_by list if not already present
    saved_by = message.get("saved_by", [])
    if isinstance(saved_by, list) and current_user not in saved_by:
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
    
    # Find message
    message = await messages_collection().find_one({"_id": message_id})
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Verify user is member of chat
    chat = await chats_collection().find_one({"_id": message["chat_id"], "members": {"$in": [current_user]}})
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this message"
        )
    
    # Check if user is in saved_by list
    saved_by = message.get("saved_by", [])
    if isinstance(saved_by, list) and current_user in saved_by:
        # Remove user from saved_by list
        await messages_collection().update_one(
            {"_id": message_id},
            {"$pull": {"saved_by": current_user}}
        )
        return {"status": "unsaved"}
    else:
        return {"status": "already_unsaved"}


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
            "edited_at": datetime.now(timezone.utc),
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
    chat = await chats_collection().find_one({"_id": chat_id, "members": {"$in": [current_user]}})
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


@router.post("/{chat_id}/ban")
async def ban_member(
    chat_id: str,
    ban_data: dict,
    current_user: str = Depends(get_current_user)
):
    """Ban a member from group chat"""
    user_to_ban = ban_data.get("user_id")
    reason = ban_data.get("reason", "")
    
    if not user_to_ban:
        raise HTTPException(status_code=400, detail="User ID to ban is required")
    
    # Check if user_to_ban is current user (can't ban yourself)
    if user_to_ban == current_user:
        raise HTTPException(status_code=400, detail="Cannot ban yourself")
    
    # Verify chat exists and current user is admin
    chat = await chats_collection().find_one({"_id": chat_id})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Validate chat type - only group or channel chats support banning
    chat_type = chat.get("type")
    if chat_type not in ("group", "channel"):
        raise HTTPException(status_code=400, detail="Banning is only supported for group or channel chats")
    
    # Check if current user is admin/owner
    members = chat.get("members", [])
    admins = chat.get("admins", [])
    owner = chat.get("created_by", chat.get("owner"))
    
    is_admin = current_user in admins or current_user == owner
    if not is_admin:
        raise HTTPException(status_code=403, detail="Only admins can ban members")
    
    # Check if user to ban is a member
    if user_to_ban not in members:
        raise HTTPException(status_code=404, detail="User is not a member of this chat")
    
    # Prevent privilege escalation: cannot ban admins or the owner
    if user_to_ban in admins or user_to_ban == owner:
        raise HTTPException(status_code=403, detail="Cannot ban another admin or the chat owner")
    
    # Check if user is already banned
    banned_users = chat.get("banned_users", [])
    if user_to_ban in banned_users:
        raise HTTPException(status_code=400, detail="User is already banned")
    
    # Remove user from members and add to banned_users
    await chats_collection().update_one(
        {"_id": chat_id},
        {
            "$pull": {"members": user_to_ban},
            "$addToSet": {"banned_users": user_to_ban}
        }
    )
    
    logger.info(f"User {user_to_ban} banned from chat {chat_id} by {current_user}. Reason: {reason}")
    
    return {
        "status": "banned",
        "user_id": user_to_ban,
        "chat_id": chat_id,
        "reason": reason
    }


@router.post("/{chat_id}/unban")
async def unban_member(
    chat_id: str,
    unban_data: dict,
    current_user: str = Depends(get_current_user)
):
    """Unban a member from group chat"""
    user_to_unban = unban_data.get("user_id")
    
    if not user_to_unban:
        raise HTTPException(status_code=400, detail="User ID to unban is required")
    
    # Verify chat exists and current user is admin
    chat = await chats_collection().find_one({"_id": chat_id})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Check if current user is admin/owner
    members = chat.get("members", [])
    admins = chat.get("admins", [])
    owner = chat.get("created_by", chat.get("owner"))
    
    is_admin = current_user in admins or current_user == owner
    if not is_admin:
        raise HTTPException(status_code=403, detail="Only admins can unban members")
    
    # Check if user is banned
    banned_users = chat.get("banned_users", [])
    if user_to_unban not in banned_users:
        raise HTTPException(status_code=400, detail="User is not banned")
    
    # Add user back to members and remove from banned_users
    await chats_collection().update_one(
        {"_id": chat_id},
        {
            "$addToSet": {"members": user_to_unban},
            "$pull": {"banned_users": user_to_unban}
        }
    )
    
    logger.info(f"User {user_to_unban} unbanned from chat {chat_id} by {current_user}")
    
    return {
        "status": "unbanned",
        "user_id": user_to_unban,
        "chat_id": chat_id
    }


@router.get("/{chat_id}/banned")
async def get_banned_users(
    chat_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get list of banned users in chat"""
    # Verify chat exists and current user is admin
    chat = await chats_collection().find_one({"_id": chat_id})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Check if current user is admin/owner
    members = chat.get("members", [])
    admins = chat.get("admins", [])
    owner = chat.get("created_by", chat.get("owner"))
    
    is_admin = current_user in admins or current_user == owner
    if not is_admin:
        raise HTTPException(status_code=403, detail="Only admins can view banned users")
    
    return {
        "chat_id": chat_id,
        "banned_users": chat.get("banned_users", [])
    }
