from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, Field, EmailStr, field_validator, model_validator, ConfigDict
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
    
    @model_validator(mode='after')
    def validate_user_data(self):
        # If name is not provided, use part of email before @ as name
        if not self.name and self.email:
            self.name = self.email.split('@')[0].title()
        return self
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return v  # Will be set in model_validator
        if not v or not v.strip():
            raise ValueError('Name cannot be empty')
        # Remove any HTML tags and prevent XSS
        v = re.sub(r'<[^>]*>', '', v)
        # Remove potentially dangerous characters
        v = re.sub(r'[<"\']', '', v)
        return v.strip()
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not v or not v.strip():
            raise ValueError('Email is required')
        v = v.strip().lower()
        # Email validation - reject emails starting/ending with dots or having consecutive dots
        if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]*[a-zA-Z0-9])?@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError('Invalid email format')
        # Additional checks
        if v.startswith('.') or v.endswith('.'):
            raise ValueError('Invalid email format')
        if '..' in v:
            raise ValueError('Invalid email format')
        # Length check
        if len(v) > 254:
            raise ValueError('Email is too long')
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not v:
            raise ValueError('Password is required')
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        # Check password strength requirements
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        if not (has_upper and has_lower and has_digit):
            raise ValueError('Password must contain uppercase, lowercase, and numbers')
        return v
    
class UserLogin(BaseModel):
    email: Optional[str] = Field(None, max_length=255)
    username: Optional[str] = Field(None, max_length=255)
    password: str = Field(..., min_length=1)
    
    @field_validator('email')
    @classmethod
    def validate_login_email(cls, v):
        if v is not None:
            if not v or not isinstance(v, str) or not v.strip():
                raise ValueError('Email cannot be empty')
            v = v.strip().lower()
            # Email validation
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
                raise ValueError('Invalid email format')
        return v
    
    @field_validator('username')
    @classmethod
    def validate_login_username(cls, v):
        if v is not None:
            if not v or not isinstance(v, str) or not v.strip():
                raise ValueError('Username cannot be empty')
            v = v.strip().lower()
            # Email validation for username (since username contains email)
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
                raise ValueError('Invalid username format')
        return v
    
    @model_validator(mode='after')
    def validate_credentials(self):
        if not self.email and not self.username:
            raise ValueError('Either email or username is required')
        # Use email if provided, otherwise use username
        if not self.email:
            self.email = self.username
        return self
    
    @field_validator('password')
    @classmethod
    def validate_login_password(cls, v):
        if not v:
            raise ValueError('Password cannot be empty')
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
    permissions: dict = Field(default_factory=lambda: {
        "location": False,
        "camera": False,
        "microphone": False,
        "storage": False
    })
    pinned_chats: List[str] = Field(default_factory=list)
    blocked_users: List[str] = Field(default_factory=list)  # List of blocked user IDs
    location: Optional[dict] = None  # {'lat': float, 'lng': float, 'updated_at': datetime}


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
    username: Optional[str] = Field(None, min_length=3, max_length=50)  # Fixed: min_length must be at least 3
    avatar: Optional[str] = Field(None)  # No length limit - validator handles it
    bio: Optional[str] = Field(None, max_length=500)
    
    @field_validator('bio')
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
        v = re.sub(r'[<>"\']', '', v)
        return v
    
    avatar_url: Optional[str] = Field(None, max_length=512)  # Increased to accommodate full paths with UUIDs
    
    @field_validator('avatar_url')
    @classmethod
    def validate_avatar_url(cls, v):
        if v is None:
            return v  # Avatar URL is optional
        if not isinstance(v, str):
            return v
        # Avatar URL should follow pattern: /api/v1/users/avatar/{filename}
        if v and not v.startswith('/api/v1/users/avatar/'):
            raise ValueError('Avatar URL must start with /api/v1/users/avatar/')
        # Prevent directory traversal
        if '..' in v or '\x00' in v:
            raise ValueError('Avatar URL contains invalid characters')
        return v
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if v is None:
            return None  # Email is optional for profile update
        v = v.strip().lower()
        # Email validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError('Invalid email format')
        return v
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return None  # Allow None for photo-only updates
        if not v or not v.strip():
            raise ValueError('Name cannot be empty')
        if '\x00' in v:  # Null byte protection
            raise ValueError('Name contains invalid characters')
        v = re.sub(r'<[^>]*>', '', v)
        v = re.sub(r'[<>"\']', '', v)
        cleaned = v.strip()
        if len(cleaned) < 2 and len(cleaned) > 0:  # Only validate if provided with content
            raise ValueError('Name must be at least 2 characters after cleaning')
        return cleaned
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if v is None:
            raise ValueError('Username is required')
        if not v or not v.strip():
            raise ValueError('Username cannot be empty')
        if '\x00' in v:  # Null byte protection
            raise ValueError('Username contains invalid characters')
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):  # Remove underscore since frontend only allows alphanum
            raise ValueError('Username can only contain letters, numbers, dots and hyphens')
        cleaned = v.strip()
        if len(cleaned) < 3:
            raise ValueError('Username must be at least 3 characters')
        return cleaned
    
    @field_validator('avatar')
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
    old_password: Optional[str] = Field(None, min_length=1, description="Current password (preferred field)")
    current_password: Optional[str] = Field(None, min_length=1, description="Current password (alternative field for compatibility)")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password (minimum 8 characters)")
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        """Validate new password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if len(v) > 128:
            raise ValueError('Password must be less than 128 characters long')
        # Add more validation if needed
        return v
    
    @model_validator(mode='after')
    def validate_password_fields(self):
        """Validate that at least one password field is provided"""
        if not self.old_password and not self.current_password:
            raise ValueError('Either old_password or current_password must be provided')
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
    type: str = Field(default=ChatType.PRIVATE, description="Chat type: private, group, supergroup, channel, secret, saved")
    name: Optional[str] = None
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    member_ids: List[str]
    # For channels/supergroups
    username: Optional[str] = None  # public link
    
    @field_validator('type')
    @classmethod
    def validate_type(cls, v):
        valid_types = [ChatType.PRIVATE, ChatType.GROUP, ChatType.SUPERGROUP, 
                     ChatType.CHANNEL, ChatType.SECRET, ChatType.SAVED]
        
        # Backward compatibility: accept 'direct' as 'private'
        if v == 'direct':
            v = ChatType.PRIVATE
            
        if v not in valid_types:
            raise ValueError(f"Invalid chat type. Must be one of: {', '.join(valid_types)}")
        return v



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
    admins: List[str] = Field(default_factory=list)
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
    text: Optional[str] = Field(None, max_length=100)  # Only first 100 chars for search, not full content
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
    device_name: Optional[str] = Field(None, max_length=100, description="Custom device name")
    
    @field_validator('device_type')
    @classmethod
    def validate_device_type(cls, v):
        allowed_types = ['mobile', 'web', 'desktop']
        if v.lower() not in allowed_types:
            raise ValueError(f'device_type must be one of: {", ".join(allowed_types)}')
        return v.lower()
    
    @field_validator('device_name')
    @classmethod
    def validate_device_name(cls, v):
        if v and len(v.strip()) == 0:
            raise ValueError('device_name cannot be empty if provided')
        # Remove any HTML tags and prevent XSS
        if v:
            import re
            v = re.sub(r'<[^>]*>', '', v)
        return v.strip() if v else v


class QRCodeResponse(BaseModel):
    """Response with QR code data"""
    session_id: str = Field(..., min_length=32, max_length=128)
    session_code: str = Field(..., min_length=6, max_length=6)
    qr_code_data: str = Field(..., min_length=100, max_length=100000)  # Base64 encoded image
    device_type: str = Field(..., max_length=20)
    expires_in_seconds: int = Field(..., gt=0, le=3600)  # Max 1 hour
    verification_url: str = Field(..., max_length=500)  # URL for devices to verify the code
    
    @field_validator('qr_code_data')
    @classmethod
    def validate_qr_code_data(cls, v):
        if not v.startswith('data:image/'):
            raise ValueError('qr_code_data must be a valid base64 image')
        return v


class VerifyQRCodeRequest(BaseModel):
    """Request to verify QR code"""
    session_id: str = Field(..., min_length=32, max_length=128)
    session_code: str = Field(..., min_length=6, max_length=6)
    device_info: Optional[str] = Field(None, max_length=500)
    
    @field_validator('session_code')
    @classmethod
    def validate_session_code(cls, v):
        if not v.isdigit():
            raise ValueError('session_code must be numeric')
        return v
    
    @field_validator('device_info')
    @classmethod
    def validate_device_info(cls, v):
        if v:
            # Remove any HTML tags and prevent XSS
            import re
            v = re.sub(r'<[^>]*>', '', v)
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
    
    @field_validator('old_password')
    @classmethod
    def validate_old_password(cls, v):
        if not v or not v.strip():
            raise ValueError('Old password cannot be empty')
        return v
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        if not v or not v.strip():
            raise ValueError('New password cannot be empty')
        if len(v) < 6:
            raise ValueError('New password must be at least 6 characters')
        return v


class EmailVerificationRequest(BaseModel):
    """Email verification request model"""
    email: str = Field(..., description="Email address to verify")
    code: str = Field(..., min_length=6, max_length=6, description="Verification code")
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not v or not v.strip():
            raise ValueError('Email is required')
        v = v.strip().lower()
        # Basic email validation
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', v):
            raise ValueError('Invalid email format')
        return v


class EmailChangeRequest(BaseModel):
    """Email change request model"""
    email: Optional[str] = Field(None, description="New email address")
    current_password: str = Field(..., min_length=1, description="Current password for verification")
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if v is not None:
            v = v.strip().lower()
            # Basic email validation
            if not re.match(r'^[^@]+@[^@]+\.[^@]+$', v):
                raise ValueError('Invalid email format')
        return v


class TokenData(BaseModel):
    """Token data extracted from JWT payload"""
    user_id: str
    token_type: str
    jti: Optional[str] = None  # JWT ID for token revocation
    payload: dict = Field(default_factory=dict)  # Full JWT payload for additional token validation


# Contact Management Models
class ContactAddRequest(BaseModel):
    """Request to add a contact"""
    user_id: Optional[str] = None  # Add by user ID
    username: Optional[str] = None  # Add by username
    display_name: Optional[str] = None  # Custom display name for the contact
    
    @field_validator('user_id', 'username')
    @classmethod
    def validate_identifier(cls, v, info):
        # At least one identifier must be provided
        if info.field_name in ['user_id', 'username']:
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
    device_id: str = Field(..., min_length=16, max_length=256)  # Unique device identifier
    device_type: str = Field(..., max_length=20)  # phone, web, desktop, tablet
    device_name: Optional[str] = Field(None, max_length=100)  # User-friendly device name
    platform: Optional[str] = Field(None, max_length=50)  # iOS, Android, Web, Windows, macOS, Linux
    app_version: Optional[str] = Field(None, max_length=20)  # App version
    
    # Device trust status
    is_trusted: bool = False  # Must be verified via QR code or confirmation
    is_primary: bool = False  # Primary device has special privileges
    is_active: bool = True  # Device is active/inactive
    
    # E2EE: Device keys
    identity_key_public: str = Field(..., min_length=80, max_length=10000)  # Base64 encoded DH public key
    signed_prekey_id: int = Field(..., ge=0, le=2147483647)  # Prekey ID
    signed_prekey_public: str = Field(..., min_length=80, max_length=10000)  # Base64 encoded DH public key
    signed_prekey_signature: Optional[str] = Field(None, max_length=10000)  # Signature of prekey
    
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
    session_id: str = Field(..., min_length=32, max_length=256)  # Unique session identifier
    
    # E2EE: Session keys
    root_key: str = Field(..., min_length=32, max_length=10000)  # Base64 encoded root key (never sent over network)
    chain_key_sending: str = Field(..., min_length=32, max_length=10000)  # For sending messages
    chain_key_receiving: str = Field(..., min_length=32, max_length=10000)  # For receiving messages
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
    identity_key_public: str = Field(..., min_length=80, max_length=10000)  # Base64 encoded
    identity_key_fingerprint: str = Field(..., min_length=32, max_length=256)  # SHA256 fingerprint
    
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
    
    prekey_id: int = Field(..., ge=0, le=2147483647)  # Max 2^31-1 unique prekeys per device
    prekey_public: str = Field(..., min_length=80, max_length=10000)  # Base64 encoded DH public
    
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
    signed_prekey_public: str = Field(..., min_length=80, max_length=10000)  # Base64 encoded DH public
    signature: str = Field(..., min_length=80, max_length=10000)  # Signed with identity key
    
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
    ciphertext: str = Field(..., min_length=100, max_length=1000000)  # Base64 encoded encrypted message
    
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
    recipient_devices: List[dict] = Field(default_factory=list)  # [{device_id, status, timestamp}, ...]
    
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
    one_time_prekey: Optional[str] = Field(None, min_length=80, max_length=10000)  # Base64
    
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
    devices: List[dict] = Field(default_factory=list)  # [{device_id, device_type, device_name}, ...]
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
    new_status: str = Field(..., description="One of: pending, sent, delivered, read, deleted, failed")
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
    message_counter_history: Dict[str, int] = Field(default_factory=dict)  # Per-session counters
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
    one_time_prekeys: List[dict] = Field(default_factory=list)  # [{id, key}, ...] (limited)
    
    # Publishing metadata
    published_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_current: bool = True

