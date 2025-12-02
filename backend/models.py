from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId


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


# User Models
class UserCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserInDB(BaseModel):
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

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    quota_used: int
    quota_limit: int
    created_at: datetime


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


# Chat Models
class ChatCreate(BaseModel):
    type: str = "private"  # private or group
    name: Optional[str] = None
    member_ids: List[str]


class ChatInDB(BaseModel):
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    type: str
    name: Optional[str] = None
    members: List[str]
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True


# Message Models
class MessageCreate(BaseModel):
    text: Optional[str] = None
    file_id: Optional[str] = None
    # Optional language code for the message (e.g. "en", "hi")
    language: Optional[str] = None


class MessageInDB(BaseModel):
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    chat_id: str
    sender_id: str
    type: str = "text"  # text or file
    text: Optional[str] = None
    file_id: Optional[str] = None
    # Persist language code with the message for UI display / filtering
    language: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    saved_by: List[str] = []  # List of user IDs who saved this message

    class Config:
        populate_by_name = True


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

    class Config:
        populate_by_name = True


class UploadInDB(BaseModel):
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

    class Config:
        populate_by_name = True
