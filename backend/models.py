from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from bson import ObjectId
import re


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")


# Enums and Constants
class ChatType:
    PRIVATE = "private"
    GROUP = "group"
    SUPERGROUP = "supergroup"
    CHANNEL = "channel"
    SECRET = "secret"

class Role:
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    RESTRICTED = "restricted"
    BANNED = "banned"

# ... existing PyObjectId ...
class UserCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        # Remove any HTML tags and prevent XSS
        if not v or not v.strip():
            raise ValueError('Name cannot be empty')
        # Remove HTML tags
        v = re.sub(r'<[^>]*>', '', v)
        # Remove potentially dangerous characters
        v = re.sub(r'[<>"\']', '', v)
        return v.strip()
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not v:
            raise ValueError('Password cannot be empty')
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserInDB(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    name: str
    email: EmailStr
    password_hash: str
    quota_used: int = 0
    quota_limit: int = 42949672960  # 40 GiB default
    created_at: datetime = Field(default_factory=datetime.utcnow)
    permissions: dict = Field(default_factory=lambda: {
        "location": False,
        "camera": False,
        "microphone": False,
        "contacts": False,
        "phone": False,
        "storage": False
    })
    pinned_chats: List[str] = Field(default_factory=list)


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    username: Optional[str] = None
    quota_used: int
    quota_limit: int
    created_at: datetime
    avatar_url: Optional[str] = None
    pinned_chats: List[str] = []


class PasswordChangeRequest(BaseModel):
    """Password change request model"""
    old_password: str
    new_password: str


class EmailChangeRequest(BaseModel):
    """Email change request model"""
    email: EmailStr
    password: str


# Auth Models
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: Optional[str] = None
    token_type: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str


# Password Reset Models
class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class PasswordResetRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class PasswordResetResponse(BaseModel):
    message: str
    success: bool


class PasswordResetResponse(BaseModel):
    message: str
    success: bool


# Permission Models
class ChatPermissions(BaseModel):
    can_send_messages: bool = True
    can_send_media: bool = True
    can_send_polls: bool = True
    can_send_other_messages: bool = True
    can_add_web_page_previews: bool = True
    can_change_info: bool = False
    can_invite_users: bool = True
    can_pin_messages: bool = False

class AdminPermissions(BaseModel):
    can_change_info: bool = False
    can_post_messages: bool = False # Channel only
    can_edit_messages: bool = False # Channel only
    can_delete_messages: bool = False
    can_ban_users: bool = False
    can_invite_users: bool = True
    can_pin_messages: bool = False
    can_promote_members: bool = False

class ChatMember(BaseModel):
    user_id: str
    chat_id: str
    role: str = Role.MEMBER
    joined_at: datetime = Field(default_factory=datetime.utcnow)
    invited_by: Optional[str] = None
    permissions: Optional[AdminPermissions] = None # For admins
    restricted_permissions: Optional[ChatPermissions] = None # For restricted users
    custom_title: Optional[str] = None
    until_date: Optional[datetime] = None # For bans/restrictions

# Chat Models
class ChatCreate(BaseModel):
    type: str = ChatType.PRIVATE
    name: Optional[str] = None
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    member_ids: List[str]
    # For channels/supergroups
    username: Optional[str] = None  # public link



class ChatInDB(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    type: str
    name: Optional[str] = None
    description: Optional[str] = None
    username: Optional[str] = None # For public access
    avatar_url: Optional[str] = None
    members: List[str]
    member_count: int = 0
    admins: List[str] = []
    owner_id: Optional[str] = None
    
    # Settings
    permissions: ChatPermissions = Field(default_factory=ChatPermissions)
    slow_mode_delay: int = 0 # Seconds
    message_auto_delete_time: Optional[int] = None
    has_protected_content: bool = False # No forwarding
    
    # Generic linkage
    linked_chat_id: Optional[str] = None # e.g. Channel <-> Discussion Group
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)



# Message Models
class MessageCreate(BaseModel):
    text: Optional[str] = None
    file_id: Optional[str] = None
    # Optional language code for the message (e.g. "en", "hi")
    language: Optional[str] = None
    
    # Threading
    reply_to_message_id: Optional[str] = None
    
    # Scheduling
    scheduled_at: Optional[datetime] = None
    
    # Silent Check
    disable_notification: bool = False

    
    @field_validator('text')
    @classmethod
    def validate_text(cls, v):
        if v is None:
            return v
        if not v.strip():
            raise ValueError('Message text cannot be empty')
        # Sanitize text to prevent XSS
        # Remove HTML tags
        v = re.sub(r'<[^>]*>', '', v)
        # Remove potentially dangerous characters
        v = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', v)
        # Limit length to prevent DoS
        if len(v) > 10000:
            raise ValueError('Message text too long (max 10000 characters)')
        return v.strip()
    
    @field_validator('language')
    @classmethod
    def validate_language(cls, v):
        if v is None:
            return v
        # Only allow standard language codes
        if not re.match(r'^[a-z]{2}(-[A-Z]{2})?$', v):
            raise ValueError('Invalid language code format')
        return v.lower()


class MessageInDB(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    chat_id: str
    sender_id: str # In channels, this might be the admin
    author_signature: Optional[str] = None # For channels
    
    type: str = "text"  # text, file, service
    text: Optional[str] = None
    file_id: Optional[str] = None
    # Persist language code with the message for UI display / filtering
    language: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Channel specific
    views: int = 0
    
    # Forwarding
    forward_from_chat_id: Optional[str] = None
    forward_from_message_id: Optional[str] = None
    forward_sender_name: Optional[str] = None
    forward_date: Optional[datetime] = None

    # Reply / Threading
    reply_to_message_id: Optional[str] = None
    # For future: thread_id if we want top-level threads

    saved_by: List[str] = []  # List of user IDs who saved this message
    # Reactions: emoji -> [user_id]
    reactions: dict = Field(default_factory=dict)
    # Read receipts: list of {"user_id": str, "read_at": datetime}
    read_by: List[dict] = Field(default_factory=list)
    
    is_pinned: bool = False
    pinned_at: Optional[datetime] = None
    pinned_by: Optional[str] = None
    
    is_edited: bool = False
    edited_at: Optional[datetime] = None
    edit_history: List[dict] = Field(default_factory=list)
    
    is_deleted: bool = False
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[str] = None



# Group / Group Chat Models
class GroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(default="", max_length=500)
    avatar_url: Optional[str] = None
    member_ids: List[str] = Field(default_factory=list)


class GroupUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    avatar_url: Optional[str] = None


class GroupMembersUpdate(BaseModel):
    user_ids: List[str] = Field(default_factory=list)


class GroupMemberRoleUpdate(BaseModel):
    role: str = Field(..., pattern=r"^(admin|member)$")


# Message Ops Models
class MessageEditRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)


class MessageReactionRequest(BaseModel):
    emoji: str = Field(..., min_length=1, max_length=16)


# File Models
class FileInitRequest(BaseModel):
    filename: str
    size: int
    mime: str
    chat_id: str
    checksum: Optional[str] = None


class FileInitResponse(BaseModel):
    upload_id: str
    chunk_size: int
    total_chunks: int
    max_parallel: int
    expires_at: datetime


class ChunkUploadResponse(BaseModel):
    upload_id: str
    chunk_index: int
    status: str = "received"


class FileCompleteResponse(BaseModel):
    file_id: str
    filename: str
    size: int
    checksum: str
    storage_path: str


class FileInDB(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    upload_id: str
    file_uuid: str
    filename: str
    size: int
    mime: str
    owner_id: str
    chat_id: str
    storage_path: str
    checksum: Optional[str] = None
    status: str = "pending"  # pending, completed, failed
    created_at: datetime = Field(default_factory=datetime.utcnow)


class UploadInDB(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    upload_id: str = Field(default_factory=lambda: str(ObjectId()))
    owner_id: str
    filename: str
    size: int
    mime: str
    chat_id: str
    total_chunks: int
    chunk_size: int
    received_chunks: List[int] = []
    checksum: Optional[str] = None
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)
