from datetime import datetime, timedelta
from typing import Optional, List, Dict
from pydantic import (
    BaseModel,
    Field,
    EmailStr,
    field_validator,
    model_validator,
    ConfigDict,
)
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
    SAVED = "saved"


class Role:
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    RESTRICTED = "restricted"
    BANNED = "banned"


# ... existing PyObjectId ...
class UserCreate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    username: Optional[str] = Field(None, max_length=255)  # Frontend sends username
    email: str = Field(..., max_length=255)  # Email field instead of username
    password: str = Field(..., min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_user_data(self):
        # If name is not provided, use part of email before @ as name
        if not self.name and self.email:
            self.name = self.email.split("@")[0].title()
        return self

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return v  # Will be set in model_validator
        if not v or not v.strip():
            raise ValueError("Name cannot be empty")
        # Remove any HTML tags and prevent XSS
        v = re.sub(r"<[^>]*>", "", v)
        # Remove potentially dangerous characters
        v = re.sub(r'[<"\']', "", v)
        return v.strip()

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if not v or not v.strip():
            raise ValueError("Email is required")
        v = v.strip().lower()
        # Email validation - reject emails starting/ending with dots or having consecutive dots
        if not re.match(
            r"^[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]*[a-zA-Z0-9])?@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            v,
        ):
            raise ValueError("Invalid email format")
        # Additional checks
        if v.startswith(".") or v.endswith("."):
            raise ValueError("Invalid email format")
        if ".." in v:
            raise ValueError("Invalid email format")
        # Length check
        if len(v) > 254:
            raise ValueError("Email is too long")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if not v:
            raise ValueError("Password is required")
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        # Check password strength requirements
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        if not (has_upper and has_lower and has_digit):
            raise ValueError("Password must contain uppercase, lowercase, and numbers")
        return v


class UserLogin(BaseModel):
    email: str = Field(..., max_length=255)  # Make email required
    username: Optional[str] = Field(
        None, max_length=255
    )  # Keep username for backward compatibility
    password: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def validate_login_credentials(self):
        # Use email as the primary authentication field
        if not self.email:
            raise ValueError("Email is required for login")
        # Set username to email if not provided for backward compatibility
        if not self.username:
            self.username = self.email
        return self

    @field_validator("email")
    @classmethod
    def validate_login_email(cls, v):
        if v is not None:
            if not v or not isinstance(v, str) or not v.strip():
                raise ValueError("Email cannot be empty")
            v = v.strip().lower()
            # Email validation
            if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", v):
                raise ValueError("Invalid email format")
        return v

    @field_validator("username")
    @classmethod
    def validate_login_username(cls, v):
        if v is not None:
            if not v or not isinstance(v, str) or not v.strip():
                raise ValueError("Username cannot be empty")
            v = v.strip().lower()
            # Email validation for username (since username contains email)
            if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", v):
                raise ValueError("Invalid username format")
        return v

    @model_validator(mode="after")
    def validate_credentials(self):
        if not self.email and not self.username:
            raise ValueError("Either email or username is required")
        # Use email if provided, otherwise use username
        if not self.email:
            self.email = self.username
        return self

    @field_validator("password")
    @classmethod
    def validate_login_password(cls, v):
        if not v:
            raise ValueError("Password cannot be empty")
        return v


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None  # Token expiration time in seconds


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserInDB(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    name: str
    username: str
    password_hash: str
    password_salt: Optional[str] = None  # CRITICAL FIX: Store password salt separately
    bio: Optional[str] = None
    avatar: Optional[str] = None  # Avatar initials like 'JD'
    avatar_url: Optional[str] = None
    quota_used: int = 0
    quota_limit: int = 16106127360  # 15 GiB default
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_online: bool = False
    status: Optional[str] = None  # User custom status
    permissions: dict = Field(
        default_factory=lambda: {
            "location": False,
            "camera": False,
            "microphone": False,
            "storage": False,
        }
    )
    pinned_chats: List[str] = Field(default_factory=list)
    blocked_users: List[str] = Field(default_factory=list)  # List of blocked user IDs
    location: Optional[
        dict
    ] = None  # {'lat': float, 'lng': float, 'updated_at': datetime}


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    username: Optional[str] = ""  # Make optional with default empty string
    bio: Optional[str] = None
    avatar: Optional[str] = None  # Avatar initials like 'JD'
    avatar_url: Optional[str] = None
    quota_used: int
    quota_limit: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_online: bool = False
    status: Optional[str] = None
    pinned_chats: List[str] = Field(default_factory=list)
    is_contact: bool = False  # Whether this user is a contact of the current user


class ProfileUpdate(BaseModel):
    """Profile update request model"""

    name: Optional[str] = Field(None, min_length=2, max_length=100)
    email: Optional[str] = Field(None, max_length=255)
    username: Optional[str] = Field(
        None, min_length=3, max_length=50
    )  # Fixed: min_length must be at least 3
    avatar: Optional[str] = Field(None)  # No length limit - validator handles it
    bio: Optional[str] = Field(None, max_length=500)

    @field_validator("bio")
    @classmethod
    def validate_bio(cls, v):
        if v is None:
            return v  # Bio is optional
        if not v or not v.strip():
            return None  # Empty bio becomes None
        # Strip whitespace first, then validate length
        v = v.strip()
        # Validate length after stripping to prevent whitespace bypass
        if len(v) > 500:
            v = v[:500]  # Truncate if too long
        # Remove potentially dangerous characters
        import re

        v = re.sub(r'[<>"\']', "", v)
        return v

    avatar_url: Optional[str] = Field(
        None, max_length=512
    )  # Increased to accommodate full paths with UUIDs

    @field_validator("avatar_url")
    @classmethod
    def validate_avatar_url(cls, v):
        if v is None:
            return v  # Avatar URL is optional
        if not isinstance(v, str):
            return v
        # Avatar URL should follow pattern: /api/v1/users/avatar/{filename}
        if v and not v.startswith("/api/v1/users/avatar/"):
            raise ValueError("Avatar URL must start with /api/v1/users/avatar/")
        # Prevent directory traversal
        if ".." in v or "\x00" in v:
            raise ValueError("Avatar URL contains invalid characters")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if v is None:
            return None  # Email is optional for profile update
        v = v.strip().lower()
        # Email validation
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", v):
            raise ValueError("Invalid email format")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return None  # Allow None for photo-only updates
        if not v or not v.strip():
            raise ValueError("Name cannot be empty")
        if "\x00" in v:  # Null byte protection
            raise ValueError("Name contains invalid characters")
        v = re.sub(r"<[^>]*>", "", v)
        v = re.sub(r'[<>"\']', "", v)
        cleaned = v.strip()
        if (
            len(cleaned) < 2 and len(cleaned) > 0
        ):  # Only validate if provided with content
            raise ValueError("Name must be at least 2 characters after cleaning")
        return cleaned

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if v is None:
            raise ValueError("Username is required")
        if not v or not v.strip():
            raise ValueError("Username cannot be empty")
        if "\x00" in v:  # Null byte protection
            raise ValueError("Username contains invalid characters")
        if not re.match(
            r"^[a-zA-Z0-9_.-]+$", v
        ):  # Remove underscore since frontend only allows alphanum
            raise ValueError(
                "Username can only contain letters, numbers, dots and hyphens"
            )
        cleaned = v.strip()
        if len(cleaned) < 3:
            raise ValueError("Username must be at least 3 characters")
        return cleaned

    @field_validator("avatar")
    @classmethod
    def validate_avatar(cls, v):
        if v is None:
            return v  # Avatar can be optional
        # FIXED: Always return None to prevent 2-letter avatars
        return None  # Don't allow avatar initials


# Password Reset Models
class PasswordResetRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class ChangePasswordRequest(BaseModel):
    old_password: Optional[str] = Field(
        None, min_length=1, description="Current password (preferred field)"
    )
    current_password: Optional[str] = Field(
        None,
        min_length=1,
        description="Current password (alternative field for compatibility)",
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password (minimum 8 characters)",
    )

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v):
        """Validate new password strength"""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if len(v) > 128:
            raise ValueError("Password must be less than 128 characters long")
        # Add more validation if needed
        return v

    @model_validator(mode="after")
    def validate_password_fields(self):
        """Validate that at least one password field is provided"""
        if not self.old_password and not self.current_password:
            raise ValueError("Either old_password or current_password must be provided")
        return self


class PasswordResetResponse(BaseModel):
    message: str
    success: bool
    token: Optional[str] = None  # Include reset token for direct password reset
    redirect_url: Optional[str] = None  # URL to redirect after successful reset
    expires_in: Optional[int] = None  # Token expiry time in seconds


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
    can_post_messages: bool = False  # Channel only
    can_edit_messages: bool = False  # Channel only
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
    permissions: Optional[AdminPermissions] = None  # For admins
    restricted_permissions: Optional[ChatPermissions] = None  # For restricted users
    custom_title: Optional[str] = None
    until_date: Optional[datetime] = None  # For bans/restrictions


# Chat Models
class ChatCreate(BaseModel):
    type: str = Field(
        default=ChatType.PRIVATE,
        description="Chat type: private, group, supergroup, channel, secret, saved",
    )
    name: Optional[str] = None
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    member_ids: List[str]
    # For channels/supergroups
    username: Optional[str] = None  # public link

    @field_validator("type")
    @classmethod
    def validate_type(cls, v):
        valid_types = [
            ChatType.PRIVATE,
            ChatType.GROUP,
            ChatType.SUPERGROUP,
            ChatType.CHANNEL,
            ChatType.SECRET,
            ChatType.SAVED,
        ]

        # Backward compatibility: accept 'direct' as 'private'
        if v == "direct":
            v = ChatType.PRIVATE

        if v not in valid_types:
            raise ValueError(
                f"Invalid chat type. Must be one of: {', '.join(valid_types)}"
            )
        return v


class ChatInDB(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    type: str
    name: Optional[str] = None
    description: Optional[str] = None
    username: Optional[str] = None  # For public access
    avatar_url: Optional[str] = None
    members: List[str]
    member_count: int = 0
    admins: List[str] = Field(default_factory=list)
    owner_id: Optional[str] = None

    # Settings
    permissions: ChatPermissions = Field(default_factory=ChatPermissions)
    slow_mode_delay: int = 0  # Seconds
    message_auto_delete_time: Optional[int] = None
    has_protected_content: bool = False  # No forwarding

    # Generic linkage
    linked_chat_id: Optional[str] = None  # e.g. Channel <-> Discussion Group

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

    @field_validator("text")
    @classmethod
    def validate_text(cls, v):
        if v is None:
            return v
        if not v.strip():
            raise ValueError("Message text cannot be empty")
        # Sanitize text to prevent XSS
        # Remove HTML tags
        v = re.sub(r"<[^>]*>", "", v)
        # Remove potentially dangerous characters
        v = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", v)
        # Limit length to prevent DoS
        if len(v) > 10000:
            raise ValueError("Message text too long (max 10000 characters)")
        return v.strip()

    @field_validator("language")
    @classmethod
    def validate_language(cls, v):
        if v is None:
            return v
        # Only allow standard language codes
        if not re.match(r"^[a-z]{2}(-[A-Z]{2})?$", v):
            raise ValueError("Invalid language code format")
        return v.lower()


class MessageInDB(BaseModel):
    """
    WhatsApp-style metadata-only message model.
    Server stores ONLY metadata, never message content.
    Message bodies and files are stored on user devices only.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    chat_id: str
    sender_id: str  # In channels, this might be the admin
    author_signature: Optional[str] = None  # For channels

    # WHATSAPP ARCHITECTURE: Type and size metadata ONLY
    type: str = "text"  # text, file, service - metadata only
    # NEVER store message body - user device stores actual content
    text: Optional[str] = Field(
        None, max_length=100
    )  # Only first 100 chars for search, not full content
    file_id: Optional[str] = None  # Reference to S3 metadata, not content
    file_size: Optional[int] = None  # Size metadata only
    file_type: Optional[str] = None  # MIME type metadata only

    # Metadata fields only
    created_at: datetime = Field(default_factory=datetime.utcnow)
    language: Optional[str] = None  # Language code metadata

    # Channel metadata
    views: int = 0

    # Forwarding metadata (no content)
    forward_from_chat_id: Optional[str] = None
    forward_from_message_id: Optional[str] = None
    forward_sender_name: Optional[str] = None  # Display name only
    forward_date: Optional[datetime] = None

    # Reply metadata (no content)
    reply_to_message_id: Optional[str] = None

    # Interaction metadata
    saved_by: List[str] = Field(default_factory=list)  # User IDs only
    reactions: dict = Field(default_factory=dict)  # Emoji -> user_id list
    read_by: List[dict] = Field(default_factory=list)  # Receipt metadata only

    # Status metadata
    is_pinned: bool = False
    pinned_at: Optional[datetime] = None
    pinned_by: Optional[str] = None

    is_edited: bool = False
    edited_at: Optional[datetime] = None
    edit_history: List[dict] = Field(default_factory=list)  # Edit metadata only

    is_deleted: bool = False
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[str] = None

    # WhatsApp compliance: TTL for automatic cleanup
    expires_at: Optional[datetime] = None  # Auto-expiration time


# ============================================================================
# WHATSAPP-LIKE MESSAGE HISTORY SYSTEM
# ============================================================================


class MessageHistoryRequest(BaseModel):
    """Request for message history sync"""

    chat_id: str = Field(..., description="Chat ID to sync")
    device_id: str = Field(..., description="Device ID requesting sync")
    limit: int = Field(
        default=50, ge=1, le=1000, description="Number of messages to fetch"
    )
    before_message_id: Optional[str] = Field(
        None, description="Get messages before this ID"
    )
    after_message_id: Optional[str] = Field(
        None, description="Get messages after this ID"
    )
    include_deleted: bool = Field(default=False, description="Include deleted messages")
    device_sync_token: Optional[str] = Field(
        None, description="Device sync token for incremental sync"
    )


class MessageHistoryResponse(BaseModel):
    """Response with message history"""

    chat_id: str
    messages: List[dict]  # Message metadata only
    total_count: int
    has_more: bool
    next_before_id: Optional[str] = None
    next_after_id: Optional[str] = None
    sync_token: Optional[str] = None  # For incremental sync
    device_id: str
    synced_at: datetime = Field(default_factory=datetime.utcnow)


class ConversationMetadata(BaseModel):
    """WhatsApp-style conversation metadata"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str  # Owner of this conversation metadata
    chat_id: str
    device_id: str  # Device-specific metadata

    # Last message metadata (no content)
    last_message_id: Optional[str] = None
    last_message_timestamp: Optional[datetime] = None
    last_message_type: Optional[str] = None  # text, file, service
    last_message_sender: Optional[str] = None

    # Unread counts (metadata only)
    unread_count: int = 0
    unread_mentions: int = 0

    # Conversation state
    is_pinned: bool = False
    is_muted: bool = False
    is_archived: bool = False

    # Sync metadata
    last_sync_timestamp: Optional[datetime] = None
    sync_token: Optional[str] = None
    device_sync_position: Optional[str] = None

    # Relationship metadata
    contact_frequency_score: float = 0.0  # Interaction frequency
    last_interaction: Optional[datetime] = None

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class RelationshipGraph(BaseModel):
    """User-to-user relationship graph data"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_a_id: str
    user_b_id: str

    # Interaction metrics
    message_count: int = 0
    last_interaction: Optional[datetime] = None
    interaction_frequency: float = 0.0  # Messages per day

    # Relationship type
    relationship_type: str = "contact"  # contact, frequent, blocked
    relationship_strength: float = 0.0  # 0.0 to 1.0

    # Group memberships
    shared_groups: List[str] = Field(default_factory=list)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class DeviceSyncState(BaseModel):
    """Multi-device sync state management"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str
    device_id: str

    # Sync position tracking
    last_synced_message_id: Optional[str] = None
    last_synced_timestamp: Optional[datetime] = None
    sync_cursor: Optional[str] = None

    # Device capabilities
    supports_e2ee: bool = True
    supports_media: bool = True
    supports_voice: bool = False

    # Sync status
    is_syncing: bool = False
    sync_progress: float = 0.0  # 0.0 to 1.0
    last_sync_duration: Optional[int] = None  # milliseconds

    # Device metadata
    device_name: Optional[str] = None
    device_type: str = "unknown"  # mobile, desktop, web
    app_version: Optional[str] = None

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class MessageDeliveryReceipt(BaseModel):
    """WhatsApp-style delivery receipt"""

    message_id: str
    chat_id: str
    recipient_user_id: str
    recipient_device_id: str
    sender_user_id: str

    # Receipt type and timestamp
    receipt_type: str  # delivered, read
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Device metadata
    device_type: Optional[str] = None
    app_version: Optional[str] = None


class MessageStatusUpdate(BaseModel):
    """Message status update for real-time sync"""

    message_id: str
    chat_id: str
    sender_id: str

    # Status states
    status: str  # sent, delivered, read, failed
    device_states: Dict[str, str] = Field(default_factory=dict)  # device_id -> status

    # Timestamps
    created_at: datetime
    sent_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None

    # Error information
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0


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
    user_ids: Optional[List[str]] = Field(default=None)


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
    mime_type: str
    chat_id: str
    receiver_id: Optional[str] = None
    checksum: Optional[str] = None


class FileInitResponse(BaseModel):
    uploadId: str  # camelCase for frontend consistency
    upload_id: Optional[str] = None
    chunk_size: int
    total_chunks: int
    expires_in: int  # Duration in seconds
    max_parallel: int = 4  # Default max parallel chunks
    upload_token: Optional[str] = None  # Long-lived token for large file uploads
    upload_url: Optional[str] = None  # Ephemeral S3 presigned URL


class ChunkUploadResponse(BaseModel):
    upload_id: str
    chunk_index: int
    status: str = "received"


class FileCompleteResponse(BaseModel):
    file_id: str
    filename: str
    size: int
    checksum: str
    storage_path: Optional[str] = None


class FileDownloadRequest(BaseModel):
    file_id: str


class FileDownloadResponse(BaseModel):
    download_url: str
    file_id: str
    filename: str
    size: int
    mime_type: str
    expires_in: int


class FileDeliveryAckRequest(BaseModel):
    file_id: str


class FileInDB(BaseModel):
    """
    WhatsApp-style metadata-only file model.
    Server stores ONLY file metadata, never file content.
    Files are stored directly in S3 with 24h TTL auto-delete.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    upload_id: str
    file_uuid: str
    filename: str
    size: int
    mime: str  # MIME type metadata only
    owner_id: str
    chat_id: str

    # WHATSAPP ARCHITECTURE: S3 metadata only, no local storage
    s3_key: Optional[str] = None  # S3 object key (metadata only)
    s3_bucket: Optional[str] = None  # S3 bucket name (metadata only)
    s3_url: Optional[str] = None  # Temporary presigned URL (metadata only)

    # File metadata (never content)
    checksum: Optional[str] = None  # Integrity check metadata
    status: str = "pending"  # pending, completed, failed - processing status only

    # WhatsApp compliance: Auto-expiration
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None  # S3 TTL auto-delete time
    downloaded_at: Optional[datetime] = None  # Download tracking
    acknowledged_at: Optional[datetime] = None  # Receiver ACK time


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
    received_chunks: List[int] = Field(default_factory=list)
    checksum: Optional[str] = None
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)


class UserSearchResponse(BaseModel):
    """Enhanced user search response"""

    id: str
    name: str
    username: str
    avatar_url: Optional[str] = None
    is_online: bool = False
    last_seen: Optional[datetime] = None
    status: Optional[str] = None


class UserPublic(BaseModel):
    """Public user information for API responses"""

    id: str
    name: str
    username: str
    avatar_url: Optional[str] = None
    is_online: bool = False
    last_seen: Optional[datetime] = None
    status: Optional[str] = None


# QR Code Models for Multi-Device Connection
class QRCodeSession(BaseModel):
    """QR Code session for connecting devices to same account"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str  # The user who initiated QR code
    session_code: str  # Unique 6-8 digit code for verification
    qr_code_data: str  # Base64 encoded QR code image
    device_type: str  # 'mobile', 'web', 'desktop'
    device_name: Optional[str] = None  # Custom device name
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime  # QR code expires after 5 minutes
    is_verified: bool = False
    verified_at: Optional[datetime] = None
    verified_from: Optional[str] = None  # Device that verified the code
    status: str = "pending"  # pending, verified, expired, cancelled


class QRCodeRequest(BaseModel):
    """Request to generate QR code"""

    device_type: str = Field(..., description="Type of device: mobile, web, or desktop")
    device_name: Optional[str] = Field(
        None, max_length=100, description="Custom device name"
    )

    @field_validator("device_type")
    @classmethod
    def validate_device_type(cls, v):
        allowed_types = ["mobile", "web", "desktop"]
        if v.lower() not in allowed_types:
            raise ValueError(f'device_type must be one of: {", ".join(allowed_types)}')
        return v.lower()

    @field_validator("device_name")
    @classmethod
    def validate_device_name(cls, v):
        if v and len(v.strip()) == 0:
            raise ValueError("device_name cannot be empty if provided")
        # Remove any HTML tags and prevent XSS
        if v:
            import re

            v = re.sub(r"<[^>]*>", "", v)
        return v.strip() if v else v


class QRCodeResponse(BaseModel):
    """Response with QR code data"""

    session_id: str = Field(..., min_length=32, max_length=128)
    session_code: str = Field(..., min_length=6, max_length=6)
    qr_code_data: str = Field(
        ..., min_length=100, max_length=100000
    )  # Base64 encoded image
    device_type: str = Field(..., max_length=20)
    expires_in_seconds: int = Field(..., gt=0, le=3600)  # Max 1 hour
    verification_url: str = Field(
        ..., max_length=500
    )  # URL for devices to verify the code

    @field_validator("qr_code_data")
    @classmethod
    def validate_qr_code_data(cls, v):
        if not v.startswith("data:image/"):
            raise ValueError("qr_code_data must be a valid base64 image")
        return v


class VerifyQRCodeRequest(BaseModel):
    """Request to verify QR code"""

    session_id: str = Field(..., min_length=32, max_length=128)
    session_code: str = Field(..., min_length=6, max_length=6)
    device_info: Optional[str] = Field(None, max_length=500)

    @field_validator("session_code")
    @classmethod
    def validate_session_code(cls, v):
        if not v.isdigit():
            raise ValueError("session_code must be numeric")
        return v

    @field_validator("device_info")
    @classmethod
    def validate_device_info(cls, v):
        if v:
            # Remove any HTML tags and prevent XSS
            import re

            v = re.sub(r"<[^>]*>", "", v)
            v = v.strip()
        return v


class VerifyQRCodeResponse(BaseModel):
    """Response after QR code verification"""

    success: bool
    message: str
    auth_token: Optional[str] = None
    user_id: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    """Password change request model"""

    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=6, max_length=128)

    @field_validator("old_password")
    @classmethod
    def validate_old_password(cls, v):
        if not v or not v.strip():
            raise ValueError("Old password cannot be empty")
        return v

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v):
        if not v or not v.strip():
            raise ValueError("New password cannot be empty")
        if len(v) < 6:
            raise ValueError("New password must be at least 6 characters")
        return v


class EmailVerificationRequest(BaseModel):
    """Email verification request model"""

    email: str = Field(..., description="Email address to verify")
    code: str = Field(..., min_length=6, max_length=6, description="Verification code")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if not v or not v.strip():
            raise ValueError("Email is required")
        v = v.strip().lower()
        # Basic email validation
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", v):
            raise ValueError("Invalid email format")
        return v


class EmailChangeRequest(BaseModel):
    """Email change request model"""

    email: Optional[str] = Field(None, description="New email address")
    current_password: str = Field(
        ..., min_length=1, description="Current password for verification"
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if v is not None:
            v = v.strip().lower()
            # Basic email validation
            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", v):
                raise ValueError("Invalid email format")
        return v


class TokenData(BaseModel):
    """Token data extracted from JWT payload"""

    user_id: str
    token_type: str
    jti: Optional[str] = None  # JWT ID for token revocation
    payload: dict = Field(
        default_factory=dict
    )  # Full JWT payload for additional token validation


# Contact Management Models
class ContactAddRequest(BaseModel):
    """Request to add a contact"""

    user_id: Optional[str] = None  # Add by user ID
    username: Optional[str] = None  # Add by username
    display_name: Optional[str] = None  # Custom display name for the contact

    @field_validator("user_id", "username")
    @classmethod
    def validate_identifier(cls, v, info):
        # At least one identifier must be provided
        if info.field_name in ["user_id", "username"]:
            return v
        return v

    def get_identifier(self) -> tuple:
        """Returns (field_name, value) for the provided identifier"""
        if self.user_id:
            return ("user_id", self.user_id)
        elif self.username:
            return ("username", self.username)
        else:
            raise ValueError("Either user_id or username must be provided")


class ContactResponse(BaseModel):
    """Response model for contact operations"""

    message: str
    contact_id: str
    contact_name: str
    display_name: Optional[str] = None


# ============================================================================
# E2EE (End-to-End Encryption) Models with Signal Protocol
# ============================================================================


class DeviceType:
    """Device type constants"""

    PHONE = "phone"
    WEB = "web"
    DESKTOP = "desktop"
    TABLET = "tablet"


class Device(BaseModel):
    """User device registration for multi-device support"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str  # Owner of the device
    device_id: str = Field(
        ..., min_length=16, max_length=256
    )  # Unique device identifier
    device_type: str = Field(..., max_length=20)  # phone, web, desktop, tablet
    device_name: Optional[str] = Field(
        None, max_length=100
    )  # User-friendly device name
    platform: Optional[str] = Field(
        None, max_length=50
    )  # iOS, Android, Web, Windows, macOS, Linux
    app_version: Optional[str] = Field(None, max_length=20)  # App version

    # Device trust status
    is_trusted: bool = False  # Must be verified via QR code or confirmation
    is_primary: bool = False  # Primary device has special privileges
    is_active: bool = True  # Device is active/inactive

    # E2EE: Device keys
    identity_key_public: str = Field(
        ..., min_length=80, max_length=10000
    )  # Base64 encoded DH public key
    signed_prekey_id: int = Field(..., ge=0, le=2147483647)  # Prekey ID
    signed_prekey_public: str = Field(
        ..., min_length=80, max_length=10000
    )  # Base64 encoded DH public key
    signed_prekey_signature: Optional[str] = Field(
        None, max_length=10000
    )  # Signature of prekey

    # Session management
    last_activity: Optional[datetime] = None
    last_ip: Optional[str] = None  # For security audits
    session_count: int = 0  # Number of active sessions

    # Device lifecycle
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    verified_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None  # Session expiration


class DeviceSession(BaseModel):
    """Encrypted session for a device"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    device_id: str  # Associated device
    user_id: str  # Session owner
    session_id: str = Field(
        ..., min_length=32, max_length=256
    )  # Unique session identifier

    # E2EE: Session keys
    root_key: str = Field(
        ..., min_length=32, max_length=10000
    )  # Base64 encoded root key (never sent over network)
    chain_key_sending: str = Field(
        ..., min_length=32, max_length=10000
    )  # For sending messages
    chain_key_receiving: str = Field(
        ..., min_length=32, max_length=10000
    )  # For receiving messages
    message_keys_counter: int = 0  # Message counter for replay protection

    # Session state
    is_active: bool = True
    key_version: int = 1  # For key rotation

    # Session metadata
    initiated_by: str  # user_id or device_id that initiated
    peer_device_id: Optional[str] = None  # For 1-to-1 sessions with specific device

    # Session lifecycle
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: Optional[datetime] = None
    expires_at: Optional[datetime] = None  # Session expiration for inactive sessions


class IdentityKey(BaseModel):
    """User's identity key pair (stored encrypted on user device, only public key on server)"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str
    device_id: str

    # Public key stored on server (encrypted)
    identity_key_public: str = Field(
        ..., min_length=80, max_length=10000
    )  # Base64 encoded
    identity_key_fingerprint: str = Field(
        ..., min_length=32, max_length=256
    )  # SHA256 fingerprint

    # Key lifecycle
    created_at: datetime = Field(default_factory=datetime.utcnow)
    key_version: int = 1  # For future key rotation
    is_active: bool = True


class PreKey(BaseModel):
    """One-Time Pre Keys for Signal Protocol (generated per device)"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str
    device_id: str

    prekey_id: int = Field(
        ..., ge=0, le=2147483647
    )  # Max 2^31-1 unique prekeys per device
    prekey_public: str = Field(
        ..., min_length=80, max_length=10000
    )  # Base64 encoded DH public

    # One-time tracking
    usage_count: int = 0  # How many times this prekey has been used
    max_usage: int = 1  # Typically 1 for one-time keys
    is_available: bool = True  # Available for new sessions

    # Key lifecycle
    created_at: datetime = Field(default_factory=datetime.utcnow)
    used_at: Optional[datetime] = None  # When this prekey was last used
    expires_at: Optional[datetime] = None  # Prekeys expire after 30 days


class SignedPreKey(BaseModel):
    """Signed Pre Key (long-term, rotated weekly)"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str
    device_id: str

    signed_prekey_id: int = Field(..., ge=0, le=2147483647)  # Unique signed prekey ID
    signed_prekey_public: str = Field(
        ..., min_length=80, max_length=10000
    )  # Base64 encoded DH public
    signature: str = Field(
        ..., min_length=80, max_length=10000
    )  # Signed with identity key

    # Signed prekey lifecycle (~7 day rotation)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    valid_until: datetime  # When to rotate (typically 7 days)
    is_current: bool = True  # The current signed prekey in use
    previous_version: Optional[int] = None  # Version of previously signed prekey


class EncryptedMessage(BaseModel):
    """Message encrypted with E2EE (Signal Protocol)"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    chat_id: str
    sender_id: str
    sender_device_id: str

    # E2EE: Encrypted payload (user device decrypts with session key)
    ciphertext: str = Field(
        ..., min_length=100, max_length=1000000
    )  # Base64 encoded encrypted message

    # Encryption metadata (server can read this)
    message_key_counter: int  # For replay protection and ordering
    session_id: str  # Reference to encryption session
    key_version: int = 1  # For future encryption algorithm updates

    # Message type (not content)
    message_type: str = "text"  # text, file, service, etc.

    # Delivery tracking (server-level metadata only)
    delivery_status: str = "pending"  # pending, delivered, read, deleted
    delivery_timestamp: Optional[datetime] = None
    read_timestamp: Optional[datetime] = None

    # Message lifecycle (ephemeral storage)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None  # Auto-delete timestamp
    ttl_seconds: int = 3600  # Default 1 hour TTL

    # Multi-device delivery tracking
    recipient_devices: List[dict] = Field(
        default_factory=list
    )  # [{device_id, status, timestamp}, ...]

    # Forward secrecy: Session ratcheting
    last_chain_key_index: int = 0  # For ratchet tracking


class E2EEBundleKey(BaseModel):
    """Bundle of public keys sent to new contacts (for session initiation)"""

    model_config = ConfigDict(populate_by_name=True)

    user_id: str
    device_id: str

    # Public keys for initial session setup (safe to send over network)
    identity_key: str = Field(..., min_length=80, max_length=10000)  # Base64
    signed_prekey_id: int = Field(..., ge=0)
    signed_prekey: str = Field(..., min_length=80, max_length=10000)  # Base64
    signed_prekey_signature: str = Field(..., min_length=80, max_length=10000)  # Base64
    one_time_prekey_id: Optional[int] = Field(None, ge=0)
    one_time_prekey: Optional[str] = Field(
        None, min_length=80, max_length=10000
    )  # Base64

    device_name: Optional[str] = None
    device_platform: Optional[str] = None


class KeyExchangeRequest(BaseModel):
    """Request to exchange keys for establishing E2EE session with a contact"""

    contact_id: str = Field(..., min_length=16, max_length=256)  # Target contact/user
    contact_device_id: Optional[str] = None  # Target device (if multi-device)

    # Own public key bundle for the contact to use
    local_identity_key: str = Field(..., min_length=80, max_length=10000)  # Base64
    local_device_id: str = Field(..., max_length=256)


class KeyExchangeResponse(BaseModel):
    """Response with contact's public key bundle for session initiation"""

    contact_id: str
    contact_device_id: str

    # Contact's keys for establishing session
    identity_key: str = Field(..., min_length=80, max_length=10000)  # Base64
    signed_prekey_id: int = Field(..., ge=0)
    signed_prekey: str = Field(..., min_length=80, max_length=10000)  # Base64
    signed_prekey_signature: str = Field(..., min_length=80, max_length=10000)
    one_time_prekey_id: Optional[int] = Field(None, ge=0)
    one_time_prekey: Optional[str] = Field(None, min_length=80, max_length=10000)

    # Discovery info
    devices: List[dict] = Field(
        default_factory=list
    )  # [{device_id, device_type, device_name}, ...]
    device_count: int = 0


class MessageDeliveryStatus(BaseModel):
    """Delivery status update for encrypted messages"""

    class Status(str):
        PENDING = "pending"
        SENT = "sent"
        DELIVERED = "delivered"
        READ = "read"
        DELETED = "deleted"
        FAILED = "failed"

    message_id: str
    device_id: str  # Device that changed status
    new_status: str = Field(
        ..., description="One of: pending, sent, delivered, read, deleted, failed"
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None  # Error message if status is failed


class ReplayProtectionData(BaseModel):
    """Data for protecting against replay attacks"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str
    device_id: str
    session_id: str

    # Replay protection tracking
    highest_message_counter: int = 0  # Highest message counter seen
    message_counter_history: Dict[str, int] = Field(
        default_factory=dict
    )  # Per-session counters
    duplicate_detection_window: int = 1024  # Sliding window for duplicates

    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class DevicePublicKeyBundle(BaseModel):
    """Public keys that a device publishes for others to download"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str
    device_id: str

    # Public key bundle (safe to distribute)
    identity_key: str = Field(..., min_length=80, max_length=10000)
    identity_key_fingerprint: str = Field(..., min_length=32, max_length=256)
    signed_prekey_id: int
    signed_prekey: str = Field(..., min_length=80, max_length=10000)
    signed_prekey_signature: str = Field(..., min_length=80, max_length=10000)

    # One-time prekeys available
    available_one_time_prekeys: int = 0
    one_time_prekeys: List[dict] = Field(
        default_factory=list
    )  # [{id, key}, ...] (limited)

    # Publishing metadata
    published_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_current: bool = True


class DeviceSession(BaseModel):
    """
    Encryption session between two devices (per-device-pair).

    CRITICAL FOR WHATSAPP ARCHITECTURE:
    - One session per (user_device, contact_device) pair
    - Each message = chain ratchet advance
    - DH ratchet on new ephemeral keys (optional)
    - Forward secrecy: delete message keys after sending
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    session_id: str = Field(..., min_length=32)

    # Session participants
    user_id: str
    device_id: str
    contact_user_id: str
    contact_device_id: str

    # Encryption state
    root_key_b64: str = Field(..., min_length=40)
    chain_key_send_b64: Optional[str] = None
    chain_key_recv_b64: Optional[str] = None
    dh_send_public_b64: Optional[str] = None
    dh_recv_public_b64: Optional[str] = None

    # Message counters
    sending_counter: int = 0
    receiving_counter: int = 0
    prev_chain_counter: int = 0  # For skipped message keys

    # Session state
    is_active: bool = True
    is_initiator: bool = False
    initialized_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    dh_ratchet_count: int = 0

    # Lifecycle
    expires_at: Optional[datetime] = None  # TTL for inactive sessions
    deleted_at: Optional[datetime] = None  # Mark for deletion (eventual consistency)


class EncryptedMessage(BaseModel):
    """
    Message in transit (encrypted, server-side, ephemeral).

    WHATSAPP ARCHITECTURE:
    - Server stores only ciphertext (never plaintext)
    - Only recipient devices can decrypt
    - Auto-delete after TTL (default 1 hour)
    - Separate ciphertext per recipient device
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    message_id: str = Field(..., min_length=32)

    # Message participants
    sender_user_id: str
    sender_device_id: str
    recipient_user_id: str
    recipient_device_id: str

    # Message encryption
    ciphertext_b64: str = Field(..., min_length=100)  # Encrypted payload
    iv_b64: str = Field(..., min_length=16)
    tag_b64: str = Field(..., min_length=24)
    message_counter: int  # For replay protection
    ephemeral_key_b64: Optional[str] = None  # Sender's DH ephemeral key

    # Message metadata (minimal)
    message_type: str = Field(default="text")  # "text", "image", "file", "group_update"
    is_group: bool = False

    # Delivery tracking
    sent_at: datetime = Field(default_factory=datetime.utcnow)
    received_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    deleted_at: Optional[
        datetime
    ] = None  # Deletion marker (message still stored until TTL)

    # TTL (ephemeral - critical for WhatsApp model)
    ttl_seconds: int = 3600  # 1 hour default
    expires_at: Optional[datetime] = None  # Auto-delete after this


class MessageDeliveryReceipt(BaseModel):
    """Per-device delivery receipt for message tracking."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    message_id: str
    chat_id: str
    recipient_user_id: str
    recipient_device_id: str
    sender_user_id: str

    # Receipt type and timestamp
    receipt_type: str  # delivered, read
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Device metadata
    device_type: Optional[str] = None
    app_version: Optional[str] = None


# ============================================================================
# WHATSAPP-LIKE MESSAGE HISTORY SYSTEM
# ============================================================================


class PersistentMessage(BaseModel):
    """WhatsApp-style persistent encrypted message storage"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    message_id: str = Field(..., min_length=8)  # Reduced for testing
    chat_id: str

    # Message participants
    sender_id: str
    receiver_id: str

    # Encrypted payload (NEVER store plaintext)
    encrypted_payload: str = Field(..., min_length=20)  # Reduced for testing
    encryption_version: int = 1

    # Message metadata (server-readable only)
    message_type: str = "text"  # text, image, video, voice, document
    content_hash: Optional[str] = None  # SHA-256 for integrity
    file_size: Optional[int] = None
    mime_type: Optional[str] = None

    # Timestamps (critical for sync)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    delivered_at: Optional[datetime] = None
    read_at: Optional[datetime] = None

    # Message state
    delivery_state: str = "pending"  # pending, sent, delivered, read
    is_deleted: bool = False
    deleted_at: Optional[datetime] = None

    # Multi-device tracking
    device_deliveries: Dict[str, datetime] = Field(default_factory=dict)
    device_reads: Dict[str, datetime] = Field(default_factory=dict)

    # Retention policy
    expires_at: Optional[datetime] = None  # Auto-expiration
    retention_days: int = 30

    # Reply threading (metadata only)
    reply_to_message_id: Optional[str] = None

    # Forward tracking (metadata only)
    forward_count: int = 0
    forward_from_message_id: Optional[str] = None

    # Edit tracking
    edit_count: int = 0
    last_edit_at: Optional[datetime] = None

    # Reaction tracking (metadata only)
    reactions: Dict[str, List[str]] = Field(default_factory=dict)

    # Message ordering
    message_counter: int = 0  # Sequential per chat

    # Indexing fields
    sender_receiver_pair: str = ""
    chat_timestamp: float = 0.0

    @model_validator(mode="after")
    def create_indexing_fields(self):
        if self.sender_id and self.receiver_id:
            self.sender_receiver_pair = f"{self.sender_id}:{self.receiver_id}"
        self.chat_timestamp = self.created_at.timestamp()
        return self


class ConversationHistory(BaseModel):
    """WhatsApp-style conversation summary for chat list"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str  # Owner of this summary
    chat_id: str

    # Last message metadata (no content)
    last_message_id: Optional[str] = None
    last_message_timestamp: Optional[datetime] = None
    last_message_type: Optional[str] = None
    last_message_sender: Optional[str] = None

    # Unread counts
    unread_count: int = 0
    unread_mentions: int = 0

    # Message counts
    total_messages: int = 0
    sent_messages: int = 0
    received_messages: int = 0

    # Media counts
    text_messages: int = 0
    image_messages: int = 0
    video_messages: int = 0
    voice_messages: int = 0
    document_messages: int = 0

    # Conversation state
    is_pinned: bool = False
    is_muted: bool = False
    is_archived: bool = False

    # Sync state
    last_sync_timestamp: Optional[datetime] = None
    sync_cursor: Optional[str] = None
    needs_sync: bool = True

    # Relationship metrics
    interaction_frequency: float = 0.0  # Messages per day
    last_interaction: Optional[datetime] = None
    relationship_strength: float = 0.0

    # Privacy settings
    disappearing_messages: bool = False
    disappearing_timer: int = 0

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class DeviceSyncState(BaseModel):
    """Multi-device message synchronization state"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str
    device_id: str

    # Sync position
    last_synced_message_id: Optional[str] = None
    last_synced_timestamp: Optional[datetime] = None
    sync_cursor: Optional[str] = None

    # Sync status
    is_syncing: bool = False
    sync_progress: float = 0.0
    last_sync_duration: Optional[int] = None  # milliseconds
    sync_error: Optional[str] = None

    # Device capabilities
    max_history_days: int = 30
    supports_media_sync: bool = True

    # Sync preferences
    auto_sync_enabled: bool = True
    sync_wifi_only: bool = False

    # Sync statistics
    total_messages_synced: int = 0
    last_sync_message_count: int = 0

    # Device metadata
    device_name: Optional[str] = None
    device_type: str = "unknown"
    app_version: Optional[str] = None

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class UserRelationship(BaseModel):
    """User-to-user relationship for graph analytics"""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_a_id: str
    user_b_id: str

    # Communication metrics
    total_messages: int = 0
    messages_last_7_days: int = 0
    messages_last_30_days: int = 0

    # Response patterns
    average_response_time: Optional[float] = None
    response_rate: float = 0.0

    # Relationship classification
    relationship_type: str = "contact"  # contact, frequent, close
    relationship_strength: float = 0.0
    trust_score: float = 0.0

    # Interaction metadata
    first_interaction: Optional[datetime] = None
    last_interaction: Optional[datetime] = None

    # Privacy settings
    is_blocked: bool = False
    is_muted: bool = False

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class MessageHistoryRequest(BaseModel):
    """Request for message history sync"""

    chat_id: str = Field(..., description="Chat ID to sync")
    device_id: str = Field(..., description="Device ID requesting sync")
    limit: int = Field(default=50, ge=1, le=1000)
    before_message_id: Optional[str] = None
    after_message_id: Optional[str] = None
    include_deleted: bool = Field(default=False)
    sync_token: Optional[str] = None


class MessageHistoryResponse(BaseModel):
    """Response with message history"""

    chat_id: str
    messages: List[dict]  # Message metadata only
    total_count: int
    has_more: bool
    next_before_id: Optional[str] = None
    next_after_id: Optional[str] = None
    sync_token: Optional[str] = None
    device_id: str
    synced_at: datetime = Field(default_factory=datetime.utcnow)
    device_id: str
    receipt_type: str = Field(..., description="sent, delivered, read, failed")
    receipt_timestamp: datetime = Field(default_factory=datetime.utcnow)
    error_reason: Optional[str] = None


class E2EEBackup(BaseModel):
    """
    Encrypted backup (optional, user-initiated).

    WHATSAPP BACKUP MODEL:
    - User generates backup key (not sent to server)
    - Server stores encrypted backup blob (unintelligible)
    - User keeps backup key in Keychain/Keystore
    - Restore: user provides backup key → server returns encrypted blob
    - Only user can decrypt (server has zero knowledge)
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    backup_id: str = Field(..., min_length=32)
    user_id: str

    # Backup content (encrypted)
    encrypted_backup_b64: str = Field(..., min_length=1000)
    backup_iv_b64: str = Field(..., min_length=16)
    backup_tag_b64: str = Field(..., min_length=24)
    backup_key_salt_b64: str = Field(..., min_length=16)  # For backup key derivation

    # Backup metadata
    content_hash_sha256: str = Field(..., min_length=64)  # For integrity verification
    backup_size_bytes: int
    device_id_backed_from: str  # Which device created this

    # Lifecycle
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    last_restored: Optional[datetime] = None

    # Retention
    auto_delete_after_days: int = 30
    is_active: bool = True


class AbuseReport(BaseModel):
    """Abuse report for moderation."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    report_id: str = Field(..., min_length=32)

    # Report details
    reporter_user_id: str
    reported_user_id: str
    report_type: str = Field(
        ..., description="spam, harassment, hate, explicit, impersonation"
    )
    report_reason_text: Optional[str] = Field(None, max_length=1000)

    # Context
    message_id: Optional[str] = None  # Specific message being reported
    related_messages: List[str] = Field(default_factory=list)

    # Status
    status: str = Field(
        default="pending"
    )  # "pending", "reviewed", "actioned", "dismissed"
    action_taken: Optional[
        str
    ] = None  # "warning", "shadow_ban", "suspension", "removal"
    moderator_notes: Optional[str] = None

    # Lifecycle
    created_at: datetime = Field(default_factory=datetime.utcnow)
    reviewed_at: Optional[datetime] = None
    action_timestamp: Optional[datetime] = None


class AbuseScoreCard(BaseModel):
    """
    Abuse scoring for user (anomaly detection).

    ATTACK PREVENTION:
    - Track message velocity (messages/minute)
    - Track unique recipient count
    - Track content patterns (spam keywords)
    - Score accumulates → triggers actions (shadow ban, suspension)
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str

    # Scoring metrics
    total_abuse_score: float = 0.0  # 0-1.0 scale
    spam_score: float = 0.0
    harassment_score: float = 0.0
    violation_score: float = 0.0

    # Velocity metrics
    messages_last_hour: int = 0
    messages_last_day: int = 0
    unique_recipients_last_day: int = 0

    # Incident tracking
    reports_received: int = 0
    actions_taken: List[str] = Field(default_factory=list)

    # Thresholds
    is_flagged: bool = False  # Needs review
    is_shadow_banned: bool = False  # Messages not delivered
    is_suspended: bool = False  # Account suspended

    # Lifecycle
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    last_incident: Optional[datetime] = None
    last_action: Optional[datetime] = None


class UserDeviceList(BaseModel):
    """
    Device list published by user (eventually consistent across devices).

    WHATSAPP ARCHITECTURE:
    - Primary device is source of truth
    - Creates signed device list
    - Broadcasts to all linked devices
    - Each device verifies signature
    - Used for group encryption (which devices to target)
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str

    # Device list content
    devices: List[Dict] = Field(
        ...
    )  # [{device_id, identity_key_fingerprint, is_primary}, ...]
    device_list_version: int  # Incremented on each update

    # Signature
    signed_by_device: str  # Primary device ID
    signature_b64: str = Field(..., min_length=80)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_current: bool = True


# ==================== GROUP ENCRYPTION (SIGNAL SENDER KEYS) ====================


class SenderKey(BaseModel):
    """
    Sender Key for group chat encryption (Signal Protocol).

    WHATSAPP GROUP ENCRYPTION:
    - Each group member has a sender key (not shared, only sender knows it)
    - Sender derives per-device sub-keys for each group member device
    - Reduces key material: O(1) per sender instead of O(recipients)
    - Group message → encrypt once with sender key → per-device re-encryption

    STORAGE:
    - Redis with TTL (ephemeral)
    - Key: sender_key:{group_id}:{sender_device_id}
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    group_id: str = Field(..., description="Group chat ID")
    sender_user_id: str = Field(..., description="Who creates messages")
    sender_device_id: str = Field(..., description="Which device")

    # Sender Key Material
    seed_b64: str = Field(..., description="Seed for deriving per-device keys")
    sender_key_id: int = Field(..., ge=0, description="Sender key version counter")
    sender_chain_key_b64: str = Field(
        ..., description="Current chain key for re-encryption"
    )
    sender_signing_key_b64: str = Field(
        ..., description="For signing messages in group"
    )

    # Recipient Device Subkeys (derived from sender key)
    recipient_keys: Dict[str, Dict] = Field(
        default_factory=dict
    )  # {recipient_device_id: {key_b64, counter}}

    # State
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None

    # TTL for Redis
    expires_at: datetime = Field(
        default_factory=lambda: datetime.utcnow() + timedelta(days=30)
    )


class GroupMessageState(BaseModel):
    """
    Group chat encryption state (shared by all members).

    WHATSAPP GROUP ENCRYPTION:
    - All group members have this group state
    - Contains all current sender keys (one per group member)
    - Version number prevents rollback attacks
    - Signed by group admin

    STORAGE:
    - Redis + MongoDB backup
    - Key: group_state:{group_id}
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    group_id: str = Field(..., description="Group chat ID")

    # Group Sender Keys (one per group member)
    sender_keys: Dict[str, Dict] = Field(
        default_factory=dict,
        description="{sender_user_id:{sender_device_id: sender_key_b64}}",
    )

    # Version & Authorization
    group_state_version: int = Field(default=1, description="Prevents rollback attacks")
    signed_by_user: str = Field(
        ..., description="Admin user ID who authorized this state"
    )
    signature_b64: str = Field(..., description="Admin signature over sender keys")

    # Group Metadata
    group_members: List[str] = Field(
        default_factory=list, description="User IDs in group"
    )
    group_admins: List[str] = Field(default_factory=list, description="Admin user IDs")

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ChatSequenceState(BaseModel):
    """
    Per-chat message sequence number (strict ordering).

    WHATSAPP MESSAGE ORDERING:
    - Each chat has monotonic sequence number
    - Message counter: incremented for every message in that chat
    - Prevents message reordering attacks
    - Detects missing/duplicate messages

    STORAGE:
    - MongoDB (persistent per chat)
    - Updated atomically on each message
    - Key: {chat_id}
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    chat_id: str = Field(..., description="Chat/conversation ID")

    # Sequence Tracking
    next_sequence_number: int = Field(
        default=1, description="Next message sequence number"
    )
    last_message_timestamp: Optional[datetime] = None
    last_message_id: Optional[str] = None

    # Gap Detection
    highest_sequence_seen: int = Field(
        default=0, description="Highest sequence number seen"
    )
    missing_sequences: List[int] = Field(
        default_factory=list, description="Detected gaps"
    )

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ==================== PRESENCE & TYPING ====================


class UserPresence(BaseModel):
    """
    User online/offline presence state.

    WHATSAPP PRESENCE:
    - Minimal metadata (just online/offline)
    - Privacy controls: show last seen only to contacts
    - Typing indicator is separate
    - Ephemeral (Redis only)

    STORAGE:
    - Redis only (ephemeral)
    - TTL: 5 minutes (expires if no heartbeat)
    - Key: presence:{user_id}:{device_id}
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str = Field(..., description="User ID")
    device_id: str = Field(..., description="Device ID")

    # Presence State
    status: str = Field(..., pattern="^(online|offline|away)$")
    last_seen_at: datetime = Field(
        default_factory=datetime.utcnow, description="Last activity time"
    )

    # Privacy Controls
    show_last_seen: bool = Field(default=True, description="Allow showing last seen")

    # Metadata
    app_version: Optional[str] = None
    platform: Optional[str] = Field(None, pattern="^(ios|android|web|desktop)$")

    # TTL Tracking
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.utcnow() + timedelta(minutes=5)
    )


class TypingIndicator(BaseModel):
    """
    Typing state for real-time indicator.

    WHATSAPP TYPING:
    - User is typing in specific chat
    - Ephemeral (disappears after 3 minutes)
    - Sent via WebSocket + Redis pub/sub
    - No server processing (only relay)

    STORAGE:
    - Redis only (ephemeral)
    - TTL: 3 minutes
    - Key: typing:{chat_id}:{user_id}:{device_id}
    - Pub/Sub: typing:{chat_id}
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    chat_id: str = Field(..., description="Chat where typing")
    user_id: str = Field(..., description="User typing")
    device_id: str = Field(..., description="Device typing")

    # Typing State
    is_typing: bool = Field(default=True)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.utcnow() + timedelta(minutes=3)
    )


# ==================== PUSH NOTIFICATIONS ====================


class PushNotification(BaseModel):
    """
    Offline push notification queue.

    WHATSAPP PUSH FLOW:
    - Message arrives for offline device
    - Server queues push notification
    - Device comes online → receives notification
    - Collapse key: only latest notification per chat
    - TTL: expires after 30 days

    STORAGE:
    - Redis queue + MongoDB for durable replay
    - Key: push_queue:{user_id}:{device_id}
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str = Field(..., description="Target user")
    device_id: str = Field(..., description="Target device")

    # Notification Content
    chat_id: str = Field(..., description="Chat this notification is for")
    message_id: str = Field(..., description="Message that triggered notification")
    sender_user_id: str = Field(..., description="Who sent the message")

    # Payload (encrypted client-side key material only)
    payload_b64: Optional[str] = Field(
        None, description="Encrypted payload (minimal metadata)"
    )
    collapse_key: str = Field(..., description="Notification collapse group")

    # State
    delivered: bool = Field(default=False)
    delivered_at: Optional[datetime] = None

    # TTL
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.utcnow() + timedelta(days=30)
    )


# ==================== MESSAGE DELIVERY STATE MACHINE ====================


class MessageDeliveryState(BaseModel):
    """
    Per-device message delivery state machine (WhatsApp ticks model).

    WHATSAPP DELIVERY STATES:
    - ⏳ pending: Not yet sent to server
    - ✓ sent: Server received
    - ✓✓ delivered: Recipient device received
    - ✓✓ read: Recipient opened chat

    STORAGE:
    - Redis for real-time state
    - MongoDB snapshot every 24h
    - Key: delivery:{message_id}:{recipient_device_id}
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    message_id: str = Field(...)
    sender_user_id: str = Field(...)
    sender_device_id: str = Field(...)
    recipient_user_id: str = Field(...)
    recipient_device_id: str = Field(...)

    # State Machine
    state: str = Field(
        ...,
        pattern="^(pending|sent|delivered|read|failed)$",
        description="Current state",
    )

    # Timestamps for Each State
    pending_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    sent_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None

    # Retry Info (if failed)
    retry_count: int = Field(default=0)
    last_retry_at: Optional[datetime] = None
    failure_reason: Optional[str] = None

    # TTL
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.utcnow() + timedelta(days=7)
    )


# ==================== BACKGROUND WORKER STATE ====================


class BackgroundWorkerState(BaseModel):
    """
    Track background job state for idempotency.

    WHATSAPP BACKEND:
    - Message fanout workers
    - Retry workers   - Typing indicator cleanup
    - Group key distribution

    STORAGE:
    - Redis for coordination
    - MongoDB for audit trail
    - Key: worker:{job_id}
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    job_id: str = Field(
        default_factory=lambda: str(ObjectId()), description="Unique job ID"
    )
    job_type: str = Field(
        ...,
        pattern="^(fanout|retry|typing_cleanup|group_key_distribution|message_history_sync|metadata_aggregation|relationship_graph_update)$",
    )

    # Job Parameters
    parameters: Dict = Field(default_factory=dict, description="Job-specific params")

    # State
    status: str = Field(..., pattern="^(pending|running|completed|failed|cancelled)$")
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Results
    result: Optional[Dict] = None
    error: Optional[str] = None

    # Retry
    attempt_count: int = Field(default=0)
    next_retry_at: Optional[datetime] = None

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ==================== WHATSAPP-LIKE MESSAGE HISTORY & METADATA ====================


class PersistentMessageHistory(BaseModel):
    """
    Persistent encrypted message database (WhatsApp-like).

    ARCHITECTURE:
    - Stores encrypted message blobs (plaintext never decrypted at backend)
    - Tracks delivery state: pending → sent → delivered → read
    - Soft-delete semantics (deleted_at timestamp, not permanent removal)
    - Configurable retention (30-90 days by default)
    - Indexed by conversation_id, sender_id, receiver_id, created_at
    - TTL index for automatic cleanup after retention_until

    IDENTITY MODEL (Phone-free):
    - Uses UserID + JWT for authentication
    - No phone numbers or contact syncing
    - Device verification required for multi-device sync

    STORAGE:
    - Primary: MongoDB (persistent encrypted history)
    - Cache: Redis (real-time delivery coordination)
    """

    model_config = ConfigDict(populate_by_name=True)

    # Unique identifier
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    message_id: str = Field(default_factory=lambda: str(ObjectId()))

    # Conversation & Participants (no phone numbers, UserID only)
    conversation_id: str = Field(..., description="Unique per participant pair/group")
    sender_id: str = Field(..., description="Sender UserID (phone-free)")
    receiver_id: str = Field(..., description="Receiver UserID (phone-free)")

    # Message Content (encrypted)
    encrypted_blob: bytes = Field(
        ..., description="Encrypted message content (backend never decrypts)"
    )
    blob_hash: str = Field(
        ..., description="SHA256 hash of encrypted blob for integrity verification"
    )

    # Device Information (multi-device support)
    sender_device_id: str = Field(..., description="Device key ID of sender")
    receiver_device_ids: List[str] = Field(
        default_factory=list, description="Target device IDs for receiver"
    )

    # Message Metadata
    message_type: str = Field(
        default="text", description="text, image, video, audio, file, contact"
    )
    file_size: Optional[int] = None
    media_mime_type: Optional[str] = None

    # Delivery State (WhatsApp-style double/triple ticks)
    delivery_state: str = Field(
        default="pending", description="pending → sent → delivered → read"
    )

    # Timestamps for Each State
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Message creation time"
    )
    sent_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None

    # Soft-Delete (not permanent removal)
    deleted_at: Optional[datetime] = None
    is_deleted: bool = Field(default=False)

    # Retention Policy
    retention_until: datetime = Field(
        default_factory=lambda: datetime.utcnow() + timedelta(days=90),
        description="Auto-delete after this timestamp",
    )

    # Retry Information
    retry_count: int = Field(default=0)
    last_retry_at: Optional[datetime] = None
    failure_reason: Optional[str] = None

    # Group Message Tracking
    is_group_message: bool = Field(default=False)
    group_id: Optional[str] = None

    # Edit & Forward History
    is_edited: bool = Field(default=False)
    edited_at: Optional[datetime] = None
    reply_to_message_id: Optional[str] = None

    # TTL Index (MongoDB: automatic cleanup)
    ttl_seconds: int = Field(default=7776000)


class ConversationMetadataTracker(BaseModel):
    """
    Metadata about conversations (WhatsApp-like).
    Only metadata is collected; message plaintext remains encrypted.

    METADATA COLLECTED:
    - Who talked to whom (sender_id → receiver_id)
    - Frequency of interaction (message count, last interaction)
    - Timestamps of each interaction
    - Delivery/read event counts
    - Device participation
    - Conversation status (active, archived, muted)

    PRIVACY:
    - No access to message plaintext
    - Only aggregated statistics
    - Soft-delete for archived conversations
    """

    model_config = ConfigDict(populate_by_name=True)

    # Unique identifier
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    conversation_id: str = Field(json_schema_extra={"unique": True})

    # Participants (phone-free, UserID only)
    user1_id: str = Field(...)
    user2_id: str = Field(...)
    is_group: bool = Field(default=False)
    group_id: Optional[str] = None

    # Interaction Statistics
    message_count: int = Field(default=0)
    unread_count: int = Field(default=0)

    # Frequency Metrics
    messages_sent_by_user1: int = Field(default=0)
    messages_sent_by_user2: int = Field(default=0)
    last_interaction_at: datetime = Field(default_factory=datetime.utcnow)
    last_message_sender: Optional[str] = None
    last_message_preview: Optional[str] = Field(None, max_length=100)

    # Delivery & Read Events
    delivered_count: int = Field(default=0)
    read_count: int = Field(default=0)
    undelivered_count: int = Field(default=0)

    # Device Participation (multi-device)
    active_devices_user1: List[str] = Field(default_factory=list)
    active_devices_user2: List[str] = Field(default_factory=list)

    # Conversation Status
    is_pinned: bool = Field(default=False)
    is_muted: bool = Field(default=False)
    is_archived: bool = Field(default=False)
    archived_at: Optional[datetime] = None
    is_deleted: bool = Field(default=False)
    deleted_at: Optional[datetime] = None

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_sync_at: Optional[datetime] = None


class UserRelationshipGraph(BaseModel):
    """
    Relationship graph derived from metadata (WhatsApp-like).
    Tracks user-to-user communication strength and patterns
    purely at the metadata layer (no message content access).

    METRICS:
    - Communication strength (frequency + recency weighted score)
    - Last interaction time
    - Active conversation count
    - Total message exchange
    - Interaction patterns (who initiates more)
    """

    model_config = ConfigDict(populate_by_name=True)

    # Unique identifier
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str = Field(...)
    contact_user_id: str = Field(...)

    # Communication Strength Score (0-100)
    strength_score: float = Field(default=0.0, ge=0.0, le=100.0)

    # Frequency Metrics
    total_messages: int = Field(default=0)
    messages_initiated_by_user: int = Field(default=0)
    messages_received_by_user: int = Field(default=0)

    # Temporal Metrics
    first_interaction_at: datetime = Field(default_factory=datetime.utcnow)
    last_interaction_at: datetime = Field(default_factory=datetime.utcnow)
    interaction_days: int = Field(default=0)

    # Activity Pattern
    avg_response_time_minutes: float = Field(default=0.0)
    interaction_frequency_per_day: float = Field(default=0.0)

    # Interaction Status
    is_blocked: bool = Field(default=False)
    is_pinned: bool = Field(default=False)
    is_archived: bool = Field(default=False)
    is_deleted: bool = Field(default=False)
    deleted_at: Optional[datetime] = None

    # Update tracking
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_score_calculated_at: datetime = Field(default_factory=datetime.utcnow)


class DeviceMessageSync(BaseModel):
    """
    Multi-device history synchronization (WhatsApp-like).
    When a new device is added after verification, it receives full encrypted history.
    """

    model_config = ConfigDict(populate_by_name=True)

    # Unique identifier
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    device_sync_id: str = Field(default_factory=lambda: str(ObjectId()))

    # Device Information
    user_id: str = Field(...)
    device_id: str = Field(...)
    sender_device_id: str = Field(...)

    # Sync Progress
    sync_state: str = Field(
        default="pending",
        description="pending → verifying → syncing → completed → failed",
    )

    # Message Range
    sync_from_timestamp: datetime = Field(
        default_factory=lambda: datetime.utcnow() - timedelta(days=90)
    )
    sync_until_timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Progress Tracking
    total_messages_to_sync: int = Field(default=0)
    messages_synced: int = Field(default=0)
    sync_progress_percent: float = Field(default=0.0)

    # Batch Processing
    batch_size: int = Field(default=100)
    current_batch: int = Field(default=0)
    batches_completed: int = Field(default=0)

    # Error Tracking
    failed_batches: List[int] = Field(default_factory=list)
    last_error: Optional[str] = None

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_sync_update_at: datetime = Field(default_factory=datetime.utcnow)

    # Retry Information
    retry_count: int = Field(default=0)
    next_retry_at: Optional[datetime] = None


class MessageRetentionPolicy(BaseModel):
    """
    Configurable message retention and metadata retention policies.

    RETENTION TIERS:
    - Message blobs: Soft-delete after 90 days (configurable)
    - Metadata: Keep indefinitely (conversation history)
    - Delivery events: Keep for 30 days for analytics
    - Soft-delete grace period: 7 days (hard-delete after grace period)
    """

    model_config = ConfigDict(populate_by_name=True)

    # Unique identifier
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    policy_name: str = Field(...)

    # Message Retention
    message_retention_days: int = Field(default=90, ge=1, le=365)

    # Metadata Retention
    metadata_retention_days: int = Field(default=365, ge=1, le=3650)

    # Delivery Event Retention
    delivery_event_retention_days: int = Field(default=30, ge=1, le=90)

    # Soft-Delete Grace Period
    soft_delete_grace_period_days: int = Field(default=7, ge=1, le=30)

    # Policy Flags
    enable_message_history: bool = Field(default=True)
    enable_metadata_collection: bool = Field(default=True)
    enable_relationship_graph: bool = Field(default=True)
    enable_multi_device_sync: bool = Field(default=True)

    # Metadata Collection
    collect_delivery_events: bool = Field(default=True)
    collect_read_events: bool = Field(default=True)
    collect_typing_indicators: bool = Field(default=False)

    # Device Sync Settings
    max_devices_per_user: int = Field(default=4, ge=1, le=10)
    sync_full_history_on_new_device: bool = Field(default=True)
    sync_messages_older_than_days: int = Field(default=90)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True)


class MultiDeviceState(BaseModel):
    """
    Track active devices for each user (WhatsApp-like).
    Supports up to 4 devices per user with session synchronization.
    """

    model_config = ConfigDict(populate_by_name=True)

    # Unique identifier
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")

    # User and Devices
    user_id: str = Field(...)
    active_devices: Dict[str, Dict] = Field(default_factory=dict)
    primary_device_id: Optional[str] = None

    # Device Count
    device_count: int = Field(default=0)
    max_devices_allowed: int = Field(default=4)

    # Sync State
    last_multi_device_sync_at: datetime = Field(default_factory=datetime.utcnow)
    requiring_sync_count: int = Field(default=0)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
