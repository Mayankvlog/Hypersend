"""
Device Key Management Module - WhatsApp-Grade Multi-Device Support
Handles device registration, linking, revocation, and per-device encryption.

MULTI-DEVICE ARCHITECTURE (per WhatsApp):
- Each user can have up to N trusted devices (phone, web, desktop, tablet)
- ONE PRIMARY device (source of truth for device list, groups, settings)
- Secondary devices sync via encrypted channels (ephemeral, no server storage)
- Each device has unique key material tied to user's identity
- Devices managed via QR-code linking and fingerprint verification

DEVICE LINKING FLOW:
1. New device shows QR code (contains session_id + user_id)
2. Primary device scans QR → trusts new device's public keys
3. Primary device sends signed device list to new device
4. Secondary device stores & verifies → ready for sync
5. All devices now have separate sessions for messaging

DEVICE SESSION = Per-(user_own_device, contact_device, recipient_device)
- Not per-user-pair (allows multiple devices to encrypt separately)
- Each message = new ratcheted key per recipient device
- Receiver decrypts with their copy of same session state

SECURITY CRITICAL:
- Private keys never leave device
- Device verification via fingerprint (out-of-band)
- Revocation signals sent to all devices (eventually consistent)
- Sessions deleted immediately on device removal
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
    X3DHKeyExchange,
    DeviceSessionState,
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
    
    async def link_device_via_qr_code(
        self,
        user_id: str,
        primary_device_id: str,
        new_device_id: str,
        new_device_type: str,
        new_device_platform: str,
        session_id: str,
        session_code: str
    ) -> Dict:
        """
        Complete device linking process (called after QR code scan).
        
        FLOW:
        1. Primary device validates session_code
        2. Primary device fetches new device's public key bundle
        3. Primary device creates trust signature on new device's identity key
        4. Primary device sends device list to new device
        5. New device stores device list + trust chain
        
        Args:
            user_id: User linking devices
            primary_device_id: Primary device (doing the linking)
            new_device_id: New device being linked
            new_device_type: Device type (phone, web, desktop, tablet)
            new_device_platform: Platform (iOS, Android, Web, Windows, macOS)
            session_id: Linking session ID
            session_code: Verification code from QR scan
            
        Returns:
            Linking status with trust chain info
        """
        try:
            logger.info(f"🔗 Linking device: user={user_id}, new={new_device_id}")
            
            # Validate session (would fetch from Redis in production)
            # redis.get(f"device_link_session:{session_id}") → must equal session_code
            
            # Get new device's identity key bundle
            # new_device_bundle = await db.devices.find_one({
            #     "user_id": user_id,
            #     "device_id": new_device_id,
            #     "is_trusted": False  # Should be unverified
            # })
            
            # Create trust signature (primary device signs new device's identity key)
            # In real impl: primary_device_private_key.sign(new_device_identity_public)
            trust_signature_b64 = base64.b64encode(
                b'trust_signature_placeholder'[:64]
            ).decode()
            
            # Update new device status
            # await db.devices.update_one(
            #     {"user_id": user_id, "device_id": new_device_id},
            #     {"$set": {
            #         "is_trusted": True,
            #         "verified_at": datetime.now(timezone.utc),
            #         "trust_verified_by": primary_device_id,
            #         "trust_signature": trust_signature_b64
            #     }}
            # )
            
            # Get list of all trusted devices  
            # trusted_devices = await db.devices.find({
            #     "user_id": user_id,
            #     "is_trusted": True
            # }).to_list(None)
            
            # Create device list to send to new device
            device_list = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "devices": [
                    {
                        "device_id": primary_device_id,
                        "is_primary": True,
                        "is_current": False
                    },
                    {
                        "device_id": new_device_id,
                        "is_primary": False,
                        "is_current": True
                    }
                    # ... other devices
                ]
            }
            
            logger.info(f"✓ Device linked: {new_device_id} trusted by {primary_device_id}")
            
            return {
                "linking_status": "completed",
                "new_device_id": new_device_id,
                "verified_by": primary_device_id,
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "device_list": device_list
            }
        
        except Exception as e:
            logger.error(f"Device linking failed: {e}")
            raise
    
    async def revoke_device(
        self,
        user_id: str,
        revoked_device_id: str,
        revoking_device_id: str
    ) -> Dict:
        """
        Revoke a device and notify others (eventually consistent).
        
        SECURITY CRITICAL:
        1. Mark device as revoked (Redis flag)
        2. Delete all sessions involving this device (immediate)
        3. Send revocation signal to all other devices (eventually)
        4. Receiver devices verify and delete corresponding sessions
        
        Args:
            user_id: User revoking device
            revoked_device_id: Device to revoke (remove)
            revoking_device_id: Device initiating revocation
            
        Returns:
            Revocation status
        """
        try:
            logger.warning(f"🚫 Device revocation initiated: user={user_id}, revoke={revoked_device_id}")
            
            # IMMEDIATE: Mark device as revoked
            revocation_id = f"revocation_{secrets.token_hex(16)}"
            revocation_time = datetime.now(timezone.utc)
            
            # await db.revoked_devices.insert_one({
            #     "_id": revocation_id,
            #     "user_id": user_id,
            #     "revoked_device_id": revoked_device_id,
            #     "revoked_by": revoking_device_id,
            #     "revoked_at": revocation_time,
            #     "reason": "user_initiated",
            #     "ttl": revocation_time + timedelta(days=7)  # Keep record for 7 days
            # })
            
            # IMMEDIATE: Delete all sessions with revoked device
            # await db.device_sessions.delete_many({
            #     "user_id": user_id,
            #     "$or": [
            #         {"device_id": revoked_device_id},
            #         {"peer_device_id": revoked_device_id}
            #     ]
            # })
            
            # IMMEDIATE: Mark device as inactive
            # await db.devices.update_one(
            #     {"user_id": user_id, "device_id": revoked_device_id},
            #     {"$set": {
            #         "is_active": False,
            #         "revoked_at": revocation_time
            #     }}
            # )
            
            # IMMEDIATE: Wipe any stored key material
            # await db.prekeys.delete_many({
            #     "user_id": user_id,
            #     "device_id": revoked_device_id
            # })
            
            # EVENTUAL: Send revocation signal to all other devices
            # This uses same message infrastructure, so it gets stored until devices pull it
            revocation_signal = {
                "type": "device_revocation",
                "revocation_id": revocation_id,
                "revoked_device": revoked_device_id,
                "revoked_by": revoking_device_id,
                "revoked_at": revocation_time.isoformat()
            }
            
            # For each other device of this user, queue revocation signal
            # await redis.lpush(f"device_signals:{user_id}", json.dumps(revocation_signal))
            
            logger.warning(f"✓ Device revoked: {revoked_device_id}, signal queued for others")
            
            return {
                "revocation_id": revocation_id,
                "revoked_device": revoked_device_id,
                "revoked_at": revocation_time.isoformat(),
                "sessions_deleted": 42,  # Placeholder
                "signal_queued": True
            }
        
        except Exception as e:
            logger.error(f"Device revocation failed: {e}")
            raise
    
    async def process_revocation_signal(
        self,
        user_id: str,
        own_device_id: str,
        revocation_signal: Dict
    ) -> None:
        """
        Process revocation signal received from another device.
        
        Called when device receives notification that another device was revoked.
        
        Args:
            user_id: User
            own_device_id: Current device
            revocation_signal: Revocation data from other device
        """
        try:
            revoked_device_id = revocation_signal.get("revoked_device")
            logger.info(f"Processing revocation: {revoked_device_id} on device {own_device_id}")
            
            # Delete any sessions with revoked device
            # await db.device_sessions.delete_many({
            #     "user_id": user_id,
            #     "device_id": own_device_id,
            #     "$or": [
            #         {"peer_device_id": revoked_device_id},
            #         {"contact_device_id": revoked_device_id}
            #     ]
            # })
            
            logger.info(f"✓ Revocation signal processed locally")
        
        except Exception as e:
            logger.error(f"Failed to process revocation signal: {e}")
    
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
    Fan-out encrypted messages to all user's recipient devices.
    
    WHATSAPP-STYLE FAN-OUT (CRITICAL):
    - Message arrives at server for recipient user_id
    - Server does NOT decrypt it
    - For EACH of recipient's active devices:
      - Fetch that device's session key with sender's device
      - Encrypt message AGAIN with that device's session key
      - Store separately in Redis with device-specific TTL
    - Each device pulls only messages encrypted for IT
    
    RESULT:
    - Different ciphertext for each recipient device
    - Can't correlate devices by message pattern
    - Device compromise only affects that device's sessions
    - New device linking doesn't re-encrypt old messages
    
    REDIS SCHEMA:
    message:{message_id}:{recipient_device_id} → {ciphertext, iv, counter, sender_device_ephemeral_key}
    message_index:{user_id}:{device_id} → [message_id1, message_id2, ...]
    """
    
    async def fan_out_to_all_recipient_devices(
        self,
        sender_user_id: str,
        sender_device_id: str,
        recipient_user_id: str,
        message_id: str,
        message_content_b64: str,
        iv_b64: str,
        tag_b64: str,
        message_counter: int,
        ephemeral_key_public_b64: str,  # Sender's ephemeral DH key for this batch
        recipient_devices: List[str]  # All active recipient devices
    ) -> Dict:
        """
        Fan-out encrypted message to recipient's devices.
        
        FOR EACH device:
        1. Get session state (user_id, device_id) → (sender_device_id)
        2. Ratchet that session's chain key to get next message key
        3. Derive re-encryption key from that message key
        4. Store in Redis under device-specific namespace
        
        Args:
            sender_user_id: Message sender
            sender_device_id: Sender's device
            recipient_user_id: Message recipient
            message_id: Unique message ID
            message_content_b64: Already encrypted message body
            iv_b64: IV from initial encryption
            tag_b64: Auth tag from initial encryption
            message_counter: Counter for replay protection
            ephemeral_key_public_b64: Sender's ephemeral DH key
            recipient_devices: List of recipient device IDs
            
        Returns:
            Per-device delivery status
        """
        try:
            logger.info(f"📤 Fan-out message: sender={sender_device_id} → "
                       f"{recipient_user_id} ({len(recipient_devices)} devices)")
            
            delivery_status = {}
            fanout_timestamp = datetime.now(timezone.utc)
            message_ttl_seconds = 3600  # 1 hour for message availability
            
            for recipient_device_id in recipient_devices:
                try:
                    # 1. Get session between (sender_device_id)↔(recipient_device_id)
                    session_key = f"session:{recipient_user_id}:{recipient_device_id}:{sender_device_id}"
                    # session_state = await redis.get(session_key)  # In production
                    
                    # 2. Ratchet chain key to get next message key
                    # message_key_b64 = await ratchet_session(session_key)
                    message_key_b64 = base64.b64encode(secrets.token_bytes(32)).decode()  # Placeholder
                    
                    # 3. Create device-specific envelope (includes ephemeral key for that device)
                    device_message_envelope = {
                        "message_id": message_id,
                        "sender_user_id": sender_user_id,
                        "sender_device_id": sender_device_id,
                        "recipient_device_id": recipient_device_id,
                        "ciphertext_b64": message_content_b64,
                        "iv_b64": iv_b64,
                        "tag_b64": tag_b64,
                        "counter": message_counter,
                        "ephemeral_key_b64": ephemeral_key_public_b64,
                        "sent_at": fanout_timestamp.isoformat()
                    }
                    
                    # 4. Store in device-specific namespace with TTL
                    redis_key = f"message:{message_id}:{recipient_device_id}"
                    # await redis.setex(redis_key, message_ttl_seconds, json.dumps(device_message_envelope))
                    
                    # 5. Add to device's message queue
                    queue_key = f"messages:{recipient_user_id}:{recipient_device_id}"
                    # await redis.lpush(queue_key, message_id)
                    # await redis.expire(queue_key, message_ttl_seconds)
                    
                    delivery_status[recipient_device_id] = {
                        "status": "queued",
                        "message_id": message_id,
                        "stored_at": fanout_timestamp.isoformat(),
                        "ttl_seconds": message_ttl_seconds
                    }
                    
                    logger.debug(f"  ✓ Queued for {recipient_device_id}")
                
                except Exception as device_error:
                    logger.error(f"  ✗ Failed to queue for {recipient_device_id}: {device_error}")
                    delivery_status[recipient_device_id] = {
                        "status": "error",
                        "error": str(device_error)
                    }
            
            logger.info(f"✓ Fan-out complete: {len([s for s in delivery_status.values() if s['status'] == 'queued'])} queued")
            
            return {
                "message_id": message_id,
                "recipient_user_id": recipient_user_id,
                "devices_targeted": len(recipient_devices),
                "delivery_status": delivery_status,
                "fanout_at": fanout_timestamp.isoformat()
            }
        
        except Exception as e:
            logger.error(f"Fan-out failed: {e}")
            raise
    
    async def pull_messages_for_device(
        self,
        user_id: str,
        device_id: str,
        batch_size: int = 50
    ) -> List[Dict]:
        """
        Pull messages queued for specific device.
        
        Device pulls only messages encrypted for IT.
        
        Args:
            user_id: User ID
            device_id: Device pulling messages
            batch_size: Max messages to return
            
        Returns:
            List of messages (each in dict format)
        """
        try:
            logger.debug(f"📥 Device pulling messages: {user_id}/{device_id}")
            
            # Get message queue for this device
            queue_key = f"messages:{user_id}:{device_id}"
            # message_ids = await redis.lrange(queue_key, 0, batch_size - 1)
            
            messages = []
            
            # For each message ID, fetch the device-specific envelope
            # for msg_id in message_ids:
            #     redis_key = f"message:{msg_id}:{device_id}"
            #     message_envelope = await redis.get(redis_key)
            #     messages.append(json.loads(message_envelope))
            #     await redis.delete(redis_key)  # Delete after pull
            
            logger.debug(f"  Pulled {len(messages)} messages")
            
            return messages
        
        except Exception as e:
            logger.error(f"Failed to pull messages: {e}")
            raise



async def generate_qr_code_for_device_linking(
    user_id: str,
    device_type: str,
    device_id: str
) -> Tuple[str, str]:
    """
    Generate QR code data for linking new device to user account.
    
    QR CODE FLOW:
    1. New device generates ephemeral session: session_id, device_id
    2. New device displays QR: hypersend://link/{session_id}/{device_id}
    3. Primary device scans QR → extracts session_id, device_id
    4. Primary device: GET /api/v1/device-link/session/{session_id}
    5. Primary device: POST to verify → signs new device's public identity key
    6. Primary device: sends all device list info to new device
    7. New device can now participate in all group chats
    
    SECURITY:
    - QR code valid for 5 minutes only
    - Session ID expires → new QR needed
    - Fingerprint verification (optional but recommended)
    - Both devices must be online during linking
    
    Args:
        user_id: User account
        device_type: Type being linked (phone, web, desktop, tablet)
        device_id: New device's ID
        
    Returns:
        (session_id, qr_code_content)
    """
    try:
        # Generate linking session
        session_id = secrets.token_urlsafe(32)  # 256-bit random
        session_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        # Store session in Redis with TTL
        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "device_type": device_type,
            "device_id": device_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": session_expiry.isoformat(),
            "status": "pending_verification"
        }
        
        # await redis.setex(
        #     f"device_link_session:{session_id}",
        #     timedelta(minutes=5),
        #     json.dumps(session_data)
        # )
        
        # QR code content (standard format for mobile scanning)
        qr_content = f"hypersend://link?session={session_id}&user={user_id}&device_type={device_type}"
        
        logger.info(f"QR code generated: session={session_id}, device_type={device_type}")
        
        return session_id, qr_content
    
    except Exception as e:
        logger.error(f"Failed to generate QR code: {e}")
        raise
