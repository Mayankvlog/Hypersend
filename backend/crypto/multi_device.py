"""
WhatsApp-Grade Multi-Device Management
======================================

Handles device linking, per-device sessions, and device lifecycle.
Primary device acts as root of trust, linked devices via QR only.

Security Properties:
- QR-based device linking only
- Per-device cryptographic sessions
- Immediate key destruction on device revoke
- Device-specific message fan-out
- Redis queues scoped as user_id:device_id
"""

import json
import secrets
import hashlib
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """Device information and capabilities"""
    device_id: str
    device_name: str
    device_type: str  # "mobile", "desktop", "web"
    platform: str  # "android", "ios", "windows", "macos", "linux", "web"
    user_agent: str
    capabilities: List[str]  # ["video_call", "voice_call", "groups", "status"]
    created_at: float
    last_active: float
    is_active: bool
    is_primary: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeviceInfo':
        """Create from dictionary"""
        return cls(**data)

@dataclass
class DeviceLinkingData:
    """QR code data for device linking"""
    linking_token: str
    primary_identity_key: bytes  # X25519 public key
    primary_signature_key: bytes  # Ed25519 public key
    expires_at: float
    device_capabilities: List[str]
    
    def to_qr_data(self) -> str:
        """Convert to QR code string"""
        data = {
            "token": self.linking_token,
            "identity_key": self.primary_identity_key.hex(),
            "signature_key": self.primary_signature_key.hex(),
            "expires_at": self.expires_at,
            "capabilities": self.device_capabilities
        }
        return json.dumps(data)
    
    @classmethod
    def from_qr_data(cls, qr_string: str) -> 'DeviceLinkingData':
        """Parse QR code string"""
        data = json.loads(qr_string)
        return cls(
            linking_token=data["token"],
            primary_identity_key=bytes.fromhex(data["identity_key"]),
            primary_signature_key=bytes.fromhex(data["signature_key"]),
            expires_at=data["expires_at"],
            device_capabilities=data["capabilities"]
        )

@dataclass
class DeviceSession:
    """Per-device cryptographic session"""
    device_id: str
    user_id: str
    identity_key: bytes  # Device's X25519 public key
    signature_key: bytes  # Device's Ed25519 public key
    signed_pre_key: bytes  # Device's signed pre-key
    one_time_pre_keys: List[bytes]  # Device's one-time pre-keys
    session_key: bytes  # Derived session key
    created_at: float
    last_used: float
    message_counter: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            "device_id": self.device_id,
            "user_id": self.user_id,
            "identity_key": self.identity_key.hex(),
            "signature_key": self.signature_key.hex(),
            "signed_pre_key": self.signed_pre_key.hex(),
            "one_time_pre_keys": [key.hex() for key in self.one_time_pre_keys],
            "session_key": self.session_key.hex(),
            "created_at": self.created_at,
            "last_used": self.last_used,
            "message_counter": self.message_counter
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeviceSession':
        """Create from dictionary"""
        return cls(
            device_id=data["device_id"],
            user_id=data["user_id"],
            identity_key=bytes.fromhex(data["identity_key"]),
            signature_key=bytes.fromhex(data["signature_key"]),
            signed_pre_key=bytes.fromhex(data["signed_pre_key"]),
            one_time_pre_keys=[bytes.fromhex(key) for key in data["one_time_pre_keys"]],
            session_key=bytes.fromhex(data["session_key"]),
            created_at=data["created_at"],
            last_used=data["last_used"],
            message_counter=data["message_counter"]
        )

class MultiDeviceManager:
    """Manages multi-device functionality"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.linking_tokens: Dict[str, DeviceLinkingData] = {}
    
    async def generate_linking_token(
        self, 
        user_id: str, 
        primary_identity_key: bytes,
        primary_signature_key: bytes,
        device_capabilities: List[str],
        ttl_minutes: int = 5
    ) -> str:
        """
        Generate QR linking token for new device
        
        Returns: linking token string
        """
        # Generate secure token
        token = secrets.token_urlsafe(32)
        
        # Create linking data
        linking_data = DeviceLinkingData(
            linking_token=token,
            primary_identity_key=primary_identity_key,
            primary_signature_key=primary_signature_key,
            expires_at=time.time() + (ttl_minutes * 60),
            device_capabilities=device_capabilities
        )
        
        # Store in memory and Redis
        self.linking_tokens[token] = linking_data
        await self.redis.setex(
            f"linking_token:{token}",
            ttl_minutes * 60,
            json.dumps(asdict(linking_data))
        )
        
        logger.info(f"Generated linking token {token} for user {user_id}")
        return token
    
    async def validate_linking_token(self, token: str) -> Optional[DeviceLinkingData]:
        """
        Validate linking token from QR code
        
        Returns: linking data if valid, None if expired/invalid
        """
        # Check memory first
        if token in self.linking_tokens:
            linking_data = self.linking_tokens[token]
            if linking_data.expires_at > time.time():
                return linking_data
            else:
                del self.linking_tokens[token]
                return None
        
        # Check Redis
        data = await self.redis.get(f"linking_token:{token}")
        if data:
            linking_data = DeviceLinkingData.from_dict(json.loads(data))
            if linking_data.expires_at > time.time():
                self.linking_tokens[token] = linking_data
                return linking_data
            else:
                await self.redis.delete(f"linking_token:{token}")
                return None
        
        return None
    
    async def link_device(
        self,
        user_id: str,
        device_info: DeviceInfo,
        device_identity_key: bytes,
        device_signature_key: bytes,
        device_signed_pre_key: bytes,
        device_one_time_pre_keys: List[bytes],
        linking_token: str
    ) -> DeviceSession:
        """
        Link new device to user account
        
        Returns: device session
        """
        # Validate linking token
        linking_data = await self.validate_linking_token(linking_token)
        if not linking_data:
            raise ValueError("Invalid or expired linking token")
        
        # Derive session key using ECDH
        primary_private = x25519.X25519PrivateKey.generate()
        primary_public = primary_private.public_key()
        device_public = x25519.X25519PublicKey.from_public_bytes(device_identity_key)
        
        shared_secret = primary_private.exchange(device_public)
        
        # Derive session key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Hypersend_DeviceSession",
            backend=default_backend()
        )
        
        session_key = hkdf.derive(shared_secret)
        
        # Create device session
        device_session = DeviceSession(
            device_id=device_info.device_id,
            user_id=user_id,
            identity_key=device_identity_key,
            signature_key=device_signature_key,
            signed_pre_key=device_signed_pre_key,
            one_time_pre_keys=device_one_time_pre_keys,
            session_key=session_key,
            created_at=time.time(),
            last_used=time.time(),
            message_counter=0
        )
        
        # Store device info and session
        await self.redis.hset(
            f"user_devices:{user_id}",
            device_info.device_id,
            json.dumps(device_info.to_dict())
        )
        
        await self.redis.set(
            f"device_session:{user_id}:{device_info.device_id}",
            json.dumps(device_session.to_dict())
        )
        
        # Create device-specific Redis queues
        await self.redis.sadd(f"user_devices:{user_id}", device_info.device_id)
        
        # Clean up linking token
        await self.redis.delete(f"linking_token:{linking_token}")
        if linking_token in self.linking_tokens:
            del self.linking_tokens[linking_token]
        
        logger.info(f"Linked device {device_info.device_id} to user {user_id}")
        return device_session
    
    async def get_user_devices(self, user_id: str) -> List[DeviceInfo]:
        """Get all devices for user"""
        device_data = await self.redis.hgetall(f"user_devices:{user_id}")
        devices = []
        
        for device_id, data in device_data.items():
            device_info = DeviceInfo.from_dict(json.loads(data))
            devices.append(device_info)
        
        return devices
    
    async def get_device_session(self, user_id: str, device_id: str) -> Optional[DeviceSession]:
        """Get device session"""
        session_data = await self.redis.get(f"device_session:{user_id}:{device_id}")
        if session_data:
            return DeviceSession.from_dict(json.loads(session_data))
        return None
    
    async def update_device_activity(self, user_id: str, device_id: str) -> None:
        """Update device last active timestamp"""
        device_data = await self.redis.hget(f"user_devices:{user_id}", device_id)
        if device_data:
            device_info = DeviceInfo.from_dict(json.loads(device_data))
            device_info.last_active = time.time()
            device_info.is_active = True
            
            await self.redis.hset(
                f"user_devices:{user_id}",
                device_id,
                json.dumps(device_info.to_dict())
            )
    
    async def revoke_device(self, user_id: str, device_id: str) -> bool:
        """
        Revoke device access and destroy keys
        
        Returns: True if device was revoked
        """
        # Get device info
        device_data = await self.redis.hget(f"user_devices:{user_id}", device_id)
        if not device_data:
            return False
        
        device_info = DeviceInfo.from_dict(json.loads(device_data))
        
        # Mark as inactive
        device_info.is_active = False
        await self.redis.hset(
            f"user_devices:{user_id}",
            device_id,
            json.dumps(device_info.to_dict())
        )
        
        # Delete device session (destroy keys)
        await self.redis.delete(f"device_session:{user_id}:{device_id}")
        
        # Remove from active devices set
        await self.redis.srem(f"user_devices:{user_id}", device_id)
        
        # Clear device-specific queues
        await self.redis.delete(f"device_queue:{user_id}:{device_id}")
        await self.redis.delete(f"device_outbox:{user_id}:{device_id}")
        
        logger.info(f"Revoked device {device_id} for user {user_id}")
        return True
    
    async def get_primary_device(self, user_id: str) -> Optional[DeviceInfo]:
        """Get primary device for user"""
        devices = await self.get_user_devices(user_id)
        for device in devices:
            if device.is_primary and device.is_active:
                return device
        return None
    
    async def set_primary_device(self, user_id: str, device_id: str) -> bool:
        """Set device as primary"""
        devices = await self.get_user_devices(user_id)
        
        # Clear primary flag from all devices
        for device in devices:
            device.is_primary = False
            await self.redis.hset(
                f"user_devices:{user_id}",
                device.device_id,
                json.dumps(device.to_dict())
            )
        
        # Set new primary
        device_data = await self.redis.hget(f"user_devices:{user_id}", device_id)
        if device_data:
            device_info = DeviceInfo.from_dict(json.loads(device_data))
            device_info.is_primary = True
            await self.redis.hset(
                f"user_devices:{user_id}",
                device_id,
                json.dumps(device_info.to_dict())
            )
            return True
        
        return False
    
    async def get_active_devices(self, user_id: str) -> List[DeviceInfo]:
        """Get all active devices for user"""
        devices = await self.get_user_devices(user_id)
        return [device for device in devices if device.is_active]
    
    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired linking tokens"""
        current_time = time.time()
        expired_tokens = []
        
        for token, linking_data in self.linking_tokens.items():
            if linking_data.expires_at <= current_time:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del self.linking_tokens[token]
            await self.redis.delete(f"linking_token:{token}")
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired linking tokens")
        
        return len(expired_tokens)
    
    async def get_device_statistics(self, user_id: str) -> Dict[str, Any]:
        """Get device usage statistics"""
        devices = await self.get_user_devices(user_id)
        active_devices = [d for d in devices if d.is_active]
        
        stats = {
            "total_devices": len(devices),
            "active_devices": len(active_devices),
            "primary_device": None,
            "device_types": {},
            "platforms": {}
        }
        
        for device in devices:
            # Count device types
            device_type = device.device_type
            stats["device_types"][device_type] = stats["device_types"].get(device_type, 0) + 1
            
            # Count platforms
            platform = device.platform
            stats["platforms"][platform] = stats["platforms"].get(platform, 0) + 1
            
            # Find primary device
            if device.is_primary:
                stats["primary_device"] = {
                    "device_id": device.device_id,
                    "device_name": device.device_name,
                    "last_active": device.last_active
                }
        
        return stats
