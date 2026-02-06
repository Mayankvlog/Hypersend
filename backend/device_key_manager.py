"""
Device Key Management Module
Handles device registration, multi-device support, key distribution, and session management.

ARCHITECTURE:
- Each user can have multiple trusted devices (phone, web, desktop, etc.)
- Each device has unique key material (identity key, signed prekey, one-time prekeys)
- Devices synchronize securely via end-to-end encryption
- Primary device acts as the "source of truth" for user data
"""

import logging
import secrets
import base64
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from bson import ObjectId

from e2ee_crypto import (
    SignalProtocolKeyManager,
    DoubleRatchet,
    generate_fingerprint
)

logger = logging.getLogger(__name__)


class DeviceKeyManager:
    """Manages cryptographic keys for devices."""
    
    def __init__(self, db=None):
        """
        Initialize device key manager.
        
        Args:
            db: Database connection for storing keys
        """
        self.db = db
    
    async def register_device(
        self,
        user_id: str,
        device_id: str,
        device_type: str,
        device_name: Optional[str] = None,
        platform: Optional[str] = None,
        app_version: Optional[str] = None,
        is_primary: bool = False
    ) -> Dict:
        """
        Register new device and generate initial keys.
        
        Args:
            user_id: User ID
            device_id: Unique device identifier
            device_type: 'phone', 'web', 'desktop', 'tablet'
            device_name: User-friendly device name
            platform: iOS, Android, Web, Windows, macOS, Linux
            app_version: Application version
            is_primary: Whether this is the primary device
            
        Returns:
            Device registration data with public keys
        """
        try:
            logger.info(f"Registering device {device_id} for user {user_id}")
            
            # Generate identity key pair (stored encrypted on device, public on server)
            identity_priv_b64, identity_pub_b64 = SignalProtocolKeyManager.generate_identity_key_pair()
            
            # Generate identity key fingerprint for verification
            identity_fingerprint = generate_fingerprint(identity_pub_b64)
            
            # Generate signed prekey
            signed_prekey_data = SignalProtocolKeyManager.generate_signed_prekey_pair(identity_priv_b64)
            
            # Generate initial batch of one-time prekeys
            one_time_prekeys = SignalProtocolKeyManager.generate_one_time_prekeys(100)
            
            device_doc = {
                "_id": str(ObjectId()),
                "user_id": user_id,
                "device_id": device_id,
                "device_type": device_type.lower(),
                "device_name": device_name or f"{device_type} Device",
                "platform": platform,
                "app_version": app_version,
                
                # E2EE: Public keys
                "identity_key_public": identity_pub_b64,
                "identity_key_fingerprint": identity_fingerprint,
                "signed_prekey_id": signed_prekey_data['signed_prekey_id'],
                "signed_prekey_public": signed_prekey_data['public_key_b64'],
                "signed_prekey_signature": signed_prekey_data['signature_b64'],
                
                # Status
                "is_trusted": False,  # Must be verified via QR code
                "is_primary": is_primary,
                "is_active": True,
                
                # Session management
                "session_count": 0,
                "last_activity": datetime.now(timezone.utc),
                "last_ip": None,
                
                # Lifecycle
                "registered_at": datetime.now(timezone.utc),
                "verified_at": None,
                "last_seen": None,
                "expires_at": None
            }
            
            # Store device (would use db.devices collection)
            # await db.devices.insert_one(device_doc)
            
            # Store one-time prekeys separately
            prekey_docs = []
            for prekey in one_time_prekeys:
                prekey_doc = {
                    "_id": str(ObjectId()),
                    "user_id": user_id,
                    "device_id": device_id,
                    "prekey_id": prekey['prekey_id'],
                    "prekey_public": prekey['public_key_b64'],
                    "usage_count": 0,
                    "max_usage": 1,
                    "is_available": True,
                    "created_at": datetime.now(timezone.utc),
                    "used_at": None,
                    "expires_at": datetime.now(timezone.utc) + timedelta(days=30)
                }
                prekey_docs.append(prekey_doc)
            
            # await db.prekeys.insert_many(prekey_docs)
            
            logger.info(f"Device registered successfully: {device_id}")
            
            return {
                "device_id": device_id,
                "user_id": user_id,
                "identity_key_public": identity_pub_b64,
                "identity_key_fingerprint": identity_fingerprint,
                "signed_prekey_id": signed_prekey_data['signed_prekey_id'],
                "signed_prekey_public": signed_prekey_data['public_key_b64'],
                "one_time_prekeys_generated": len(one_time_prekeys),
                "is_primary": is_primary,
                "status": "registered_awaiting_verification"
            }
        except Exception as e:
            logger.error(f"Device registration failed: {e}")
            raise
    
    async def verify_device(self, user_id: str, device_id: str) -> Dict:
        """
        Verify and trust a device (after QR code scan or confirmation).
        
        Args:
            user_id: User ID
            device_id: Device ID to verify
            
        Returns:
            Verification result
        """
        try:
            logger.info(f"Verifying device {device_id} for user {user_id}")
            
            # Update device status to trusted
            # await db.devices.update_one(
            #     {"user_id": user_id, "device_id": device_id},
            #     {"$set": {
            #         "is_trusted": True,
            #         "verified_at": datetime.now(timezone.utc)
            #     }}
            # )
            
            logger.info(f"Device verified: {device_id}")
            
            return {
                "device_id": device_id,
                "is_trusted": True,
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "status": "verified"
            }
        except Exception as e:
            logger.error(f"Device verification failed: {e}")
            raise
    
    async def list_user_devices(self, user_id: str) -> List[Dict]:
        """
        List all devices for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of device information (without private keys)
        """
        try:
            # devices = await db.devices.find({"user_id": user_id}).to_list(None)
            devices = []  # Placeholder
            
            return [
                {
                    "device_id": d.get("device_id"),
                    "device_type": d.get("device_type"),
                    "device_name": d.get("device_name"),
                    "platform": d.get("platform"),
                    "is_trusted": d.get("is_trusted", False),
                    "is_primary": d.get("is_primary", False),
                    "is_active": d.get("is_active", True),
                    "last_seen": d.get("last_seen"),
                    "registered_at": d.get("registered_at")
                }
                for d in devices
            ]
        except Exception as e:
            logger.error(f"Failed to list devices: {e}")
            raise
    
    async def session_exists_for_user_device(
        self,
        user_id: str,
        device_id: str
    ) -> bool:
        """Check if encryption session exists for device."""
        # await db.device_sessions.find_one({
        #     "user_id": user_id,
        #     "device_id": device_id,
        #     "is_active": True
        # })
        return False  # Placeholder
    
    async def create_device_session(
        self,
        user_id: str,
        device_id: str,
        contact_device_id: str,
        root_key_b64: str
    ) -> Dict:
        """
        Create encryption session between two devices.
        
        Args:
            user_id: Session owner
            device_id: Local device
            contact_device_id: Remote device
            root_key_b64: Derived root key
            
        Returns:
            Session information
        """
        try:
            session_id = f"{device_id}-{contact_device_id}-{secrets.token_hex(16)}"
            
            # Initialize Double Ratchet
            ratchet = DoubleRatchet(root_key_b64)
            chain_key_sending = ratchet.create_sending_chain_key()
            chain_key_receiving = ratchet.create_receiving_chain_key("") # Will be updated with peer key
            
            session_doc = {
                "_id": str(ObjectId()),
                "user_id": user_id,
                "device_id": device_id,
                "session_id": session_id,
                
                "root_key": root_key_b64,
                "chain_key_sending": chain_key_sending,
                "chain_key_receiving": chain_key_receiving,
                "message_keys_counter": 0,
                
                "is_active": True,
                "key_version": 1,
                
                "initiated_by": device_id,
                "peer_device_id": contact_device_id,
                
                "created_at": datetime.now(timezone.utc),
                "last_activity": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(days=30)
            }
            
            # await db.device_sessions.insert_one(session_doc)
            
            logger.info(f"Session created: {session_id}")
            
            return {
                "session_id": session_id,
                "device_id": device_id,
                "peer_device_id": contact_device_id,
                "status": "initialized"
            }
        except Exception as e:
            logger.error(f"Session creation failed: {e}")
            raise


class KeyDistributionService:
    """Distributes public keys for new sessions (never sends private keys)."""
    
    async def get_user_key_bundle(
        self,
        user_id: str,
        device_id: Optional[str] = None
    ) -> Dict:
        """
        Get public key bundle for user (or specific device).
        
        Returns only public keys for session initiation.
        """
        try:
            # If device_id specified, get that device
            # Otherwise get primary device
            
            bundle = {
                "user_id": user_id,
                "device_id": device_id,
                "identity_key": "base64_public_key",  # Placeholder
                "identity_key_fingerprint": "fingerprint",
                "signed_prekey_id": 123,
                "signed_prekey": "base64_public_key",
                "signed_prekey_signature": "base64_signature",
                "one_time_prekey_id": 456,
                "one_time_prekey": "base64_public_key"
            }
            
            return bundle
        except Exception as e:
            logger.error(f"Failed to get key bundle: {e}")
            raise
    
    async def get_one_time_prekey(
        self,
        user_id: str,
        device_id: str
    ) -> Optional[Dict]:
        """
        Get next available one-time prekey for device.
        
        Returns:
            One-time prekey dict or None if none available
        """
        try:
            # Query for next available prekey
            # prekey = await db.prekeys.find_one_and_update(
            #     {
            #         "user_id": user_id,
            #         "device_id": device_id,
            #         "is_available": True,
            #         "expires_at": {"$gt": datetime.now(timezone.utc)}
            #     },
            #     {"$set": {"is_available": False, "usage_count": 1, "used_at": datetime.now(timezone.utc)}}
            # )
            
            return None  # Placeholder
        except Exception as e:
            logger.error(f"Failed to get one-time prekey: {e}")
            raise


class MultiDeviceMessageFanOut:
    """
    Fan-out encrypted messages to all user's devices.
    
    Each device receives the message encrypted with its own session key.
    """
    
    async def fan_out_to_devices(
        self,
        sender_user_id: str,
        message_recipient_user_id: str,
        encrypted_message: str,
        devices: List[str]
    ) -> Dict:
        """
        Send encrypted message to all recipient's devices.
        
        Args:
            sender_user_id: Message sender
            message_recipient_user_id: Message recipient
            encrypted_message: Already encrypted message payload
            devices: List of device IDs to send to
            
        Returns:
            Delivery status per device
        """
        try:
            delivery_status = {}
            
            for device_id in devices:
                # For each device, encrypt message with device's session key
                # This is Double Ratchet advance per device
                
                delivery_status[device_id] = {
                    "device_id": device_id,
                    "status": "pending",
                    "sent_at": datetime.now(timezone.utc)
                    # Will be updated to "delivered" when device ACKs
                }
            
            return {
                "message_id": "msg_id",
                "recipient_user_id": message_recipient_user_id,
                "devices_targeted": len(devices),
                "delivery_status": delivery_status
            }
        except Exception as e:
            logger.error(f"Fan-out failed: {e}")
            raise


async def generate_qr_code_for_device_linking(
    user_id: str,
    device_type: str
) -> Tuple[str, str, str]:
    """
    Generate QR code for linking new device to user account.
    
    Args:
        user_id: User ID
        device_type: Type of device to link
        
    Returns:
        (session_id, session_code, qr_code_data_base64)
    """
    try:
        session_id = secrets.token_urlsafe(32)
        session_code = str(secrets.randbelow(1000000)).zfill(6)  # 6-digit code
        
        # QR code contains session_id + session_code + user_id
        qr_data = f"hypersend://device-link?user={user_id}&session={session_id}&code={session_code}"
        
        # In real implementation, generate actual QR code image
        # For now, return base64 placeholder
        qr_code_b64 = base64.b64encode(qr_data.encode()).decode()
        
        logger.info(f"QR code generated for user {user_id}")
        
        return session_id, session_code, qr_code_b64
    except Exception as e:
        logger.error(f"Failed to generate QR code: {e}")
        raise
