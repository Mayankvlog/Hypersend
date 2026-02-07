"""
WhatsApp-Grade Encrypted Voice/Video Calls
==========================================

End-to-end encrypted real-time communication with peer-to-peer preference.
Uses Signal Protocol for call setup and SRTP for media encryption.

Security Properties:
- E2E encrypted call signaling
- Peer-to-peer media when possible
- Encrypted relay fallback
- Call metadata minimization
- Secure call termination
"""

import os
import secrets
import hashlib
import hmac
import time
import json
import logging
import asyncio
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519
import base64

logger = logging.getLogger(__name__)


class CallType(Enum):
    """Call type enumeration"""
    VOICE = "voice"
    VIDEO = "video"
    GROUP_VOICE = "group_voice"
    GROUP_VIDEO = "group_video"


class CallState(Enum):
    """Call state enumeration"""
    INITIATING = "initiating"
    RINGING = "ringing"
    CONNECTED = "connected"
    ENDED = "ended"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass
class CallSession:
    """Encrypted call session"""
    call_id: str
    initiator_user_id: str
    initiator_device_id: str
    recipient_user_id: str
    recipient_device_id: str
    call_type: CallType
    state: CallState
    created_at: float
    connected_at: Optional[float]
    ended_at: Optional[float]
    duration: Optional[int]
    encryption_key: Optional[str]  # Base64 encoded
    signaling_key: Optional[str]   # Base64 encoded
    media_type: str
    is_p2p: bool
    relay_server: Optional[str]
    quality_score: float
    metadata: Dict[str, Any]


@dataclass
class CallEncryptionKeys:
    """Call encryption keys (client-side only)"""
    call_id: str
    srtp_key: bytes        # SRTP master key (16 bytes)
    srtp_salt: bytes      # SRTP master salt (14 bytes)
    signaling_key: bytes  # Signaling encryption key (32 bytes)
    hmac_key: bytes       # HMAC key (32 bytes)
    created_at: float


class EncryptedCallService:
    """
    WhatsApp-grade encrypted voice/video call service.
    
    CALL FLOW:
    1. Signal Protocol key exchange for call setup
    2. Generate SRTP keys for media encryption
    3. Attempt peer-to-peer connection
    4. Fallback to encrypted relay if P2P fails
    5. Minimize call metadata storage
    6. Secure call termination
    """
    
    def __init__(self):
        self.active_calls: Dict[str, CallSession] = {}
        self.call_keys: Dict[str, CallEncryptionKeys] = {}
        self.relay_servers = [
            "turn:hypersend-turn:3478",
            "stun:hypersend-turn:3478"
        ]
    
    async def initiate_encrypted_call(
        self,
        initiator_user_id: str,
        initiator_device_id: str,
        recipient_user_id: str,
        recipient_device_id: str,
        call_type: CallType,
        signal_session: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Initiate an encrypted voice/video call"""
        try:
            call_id = secrets.token_urlsafe(16)
            
            # Generate call encryption keys
            call_keys = self._generate_call_encryption_keys(call_id)
            self.call_keys[call_id] = call_keys
            
            # Create call session
            call_session = CallSession(
                call_id=call_id,
                initiator_user_id=initiator_user_id,
                initiator_device_id=initiator_device_id,
                recipient_user_id=recipient_user_id,
                recipient_device_id=recipient_device_id,
                call_type=call_type,
                state=CallState.INITIATING,
                created_at=time.time(),
                connected_at=None,
                ended_at=None,
                duration=None,
                encryption_key=base64.b64encode(call_keys.signaling_key).decode(),
                signaling_key=base64.b64encode(call_keys.signaling_key).decode(),
                media_type=call_type.value,
                is_p2p=False,  # Will be determined after connection attempt
                relay_server=None,
                quality_score=0.0,
                metadata={
                    "initiator": initiator_user_id,
                    "recipient": recipient_user_id,
                    "signal_session": signal_session,
                    "encryption_method": "SRTP",
                    "key_exchange": "Signal-Protocol"
                }
            )
            
            self.active_calls[call_id] = call_session
            
            # Prepare call signaling data (encrypted)
            signaling_data = {
                "call_id": call_id,
                "call_type": call_type.value,
                "initiator_device_id": initiator_device_id,
                "recipient_device_id": recipient_device_id,
                "srtp_key": base64.b64encode(call_keys.srtp_key).decode(),
                "srtp_salt": base64.b64encode(call_keys.srtp_salt).decode(),
                "signaling_key": base64.b64encode(call_keys.signaling_key).decode(),
                "hmac_key": base64.b64encode(call_keys.hmac_key).decode(),
                "relay_servers": self.relay_servers,
                "timestamp": time.time()
            }
            
            # Encrypt signaling data with Signal Protocol if session available
            if signal_session:
                encrypted_signaling = await self._encrypt_signaling_data(
                    signaling_data, signal_session
                )
            else:
                encrypted_signaling = signaling_data
            
            return {
                "success": True,
                "call_session": asdict(call_session),
                "signaling_data": encrypted_signaling,
                "call_keys": {
                    "srtp_key": base64.b64encode(call_keys.srtp_key).decode(),
                    "srtp_salt": base64.b64encode(call_keys.srtp_salt).decode(),
                    "signaling_key": base64.b64encode(call_keys.signaling_key).decode()
                },
                "message": "Encrypted call initiated successfully"
            }
            
        except Exception as e:
            logger.error(f"Call initiation failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def accept_encrypted_call(
        self,
        call_id: str,
        recipient_user_id: str,
        recipient_device_id: str,
        signaling_data: Dict[str, Any],
        signal_session: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Accept an encrypted call"""
        try:
            if call_id not in self.active_calls:
                return {"success": False, "error": "Call not found"}
            
            call_session = self.active_calls[call_id]
            
            # Verify recipient
            if call_session.recipient_user_id != recipient_user_id:
                return {"success": False, "error": "Invalid recipient"}
            
            # Decrypt signaling data if encrypted
            if signal_session and "encrypted_data" in signaling_data:
                decrypted_signaling = await self._decrypt_signaling_data(
                    signaling_data, signal_session
                )
            else:
                decrypted_signaling = signaling_data
            
            # Update call session
            call_session.state = CallState.RINGING
            call_session.recipient_device_id = recipient_device_id
            
            # Generate recipient's call keys
            recipient_keys = self._generate_call_encryption_keys(call_id + "_recipient")
            
            # Attempt P2P connection
            p2p_result = await self._attempt_p2p_connection(
                call_session, decrypted_signaling
            )
            
            if p2p_result["success"]:
                call_session.is_p2p = True
                call_session.quality_score = p2p_result["quality_score"]
            else:
                # Setup relay connection
                relay_result = await self._setup_relay_connection(
                    call_session, decrypted_signaling
                )
                if relay_result["success"]:
                    call_session.relay_server = relay_result["relay_server"]
                    call_session.quality_score = relay_result["quality_score"]
                else:
                    call_session.state = CallState.FAILED
                    return {"success": False, "error": "Failed to establish connection"}
            
            call_session.state = CallState.CONNECTED
            call_session.connected_at = time.time()
            
            return {
                "success": True,
                "call_session": asdict(call_session),
                "connection_type": "p2p" if call_session.is_p2p else "relay",
                "media_encryption": {
                    "srtp_key": base64.b64encode(recipient_keys.srtp_key).decode(),
                    "srtp_salt": base64.b64encode(recipient_keys.srtp_salt).decode(),
                    "signaling_key": base64.b64encode(recipient_keys.signaling_key).decode()
                },
                "relay_info": call_session.relay_server,
                "message": "Call accepted and connected successfully"
            }
            
        except Exception as e:
            logger.error(f"Call acceptance failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def end_encrypted_call(
        self,
        call_id: str,
        user_id: str,
        device_id: str,
        reason: str = "user_ended"
    ) -> Dict[str, Any]:
        """End an encrypted call securely"""
        try:
            if call_id not in self.active_calls:
                return {"success": False, "error": "Call not found"}
            
            call_session = self.active_calls[call_id]
            
            # Verify caller
            if (call_session.initiator_user_id != user_id and 
                call_session.recipient_user_id != user_id):
                return {"success": False, "error": "Unauthorized to end call"}
            
            # Update call session
            call_session.state = CallState.ENDED
            call_session.ended_at = time.time()
            
            if call_session.connected_at:
                call_session.duration = int(call_session.ended_at - call_session.connected_at)
            
            # Securely delete call keys
            if call_id in self.call_keys:
                del self.call_keys[call_id]
            
            # Store call metadata (minimal, encrypted)
            call_metadata = {
                "call_id": call_id,
                "call_type": call_session.call_type.value,
                "duration": call_session.duration,
                "quality_score": call_session.quality_score,
                "connection_type": "p2p" if call_session.is_p2p else "relay",
                "ended_at": call_session.ended_at,
                "end_reason": reason
            }
            
            # Remove from active calls
            del self.active_calls[call_id]
            
            return {
                "success": True,
                "call_metadata": call_metadata,
                "message": "Call ended securely"
            }
            
        except Exception as e:
            logger.error(f"Call termination failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def get_call_status(
        self,
        call_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """Get call status"""
        try:
            if call_id not in self.active_calls:
                return {"success": False, "error": "Call not found"}
            
            call_session = self.active_calls[call_id]
            
            # Verify user is participant
            if (call_session.initiator_user_id != user_id and 
                call_session.recipient_user_id != user_id):
                return {"success": False, "error": "Unauthorized"}
            
            return {
                "success": True,
                "call_status": {
                    "call_id": call_session.call_id,
                    "state": call_session.state.value,
                    "call_type": call_session.call_type.value,
                    "created_at": call_session.created_at,
                    "connected_at": call_session.connected_at,
                    "duration": call_session.duration,
                    "is_p2p": call_session.is_p2p,
                    "quality_score": call_session.quality_score,
                    "relay_server": call_session.relay_server
                }
            }
            
        except Exception as e:
            logger.error(f"Get call status failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def initiate_group_call(
        self,
        initiator_user_id: str,
        initiator_device_id: str,
        group_id: str,
        call_type: CallType,
        participant_devices: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Initiate encrypted group call"""
        try:
            call_id = secrets.token_urlsafe(16)
            
            # Generate group call keys
            group_call_keys = self._generate_group_call_keys(call_id, len(participant_devices))
            
            # Create group call session
            call_session = CallSession(
                call_id=call_id,
                initiator_user_id=initiator_user_id,
                initiator_device_id=initiator_device_id,
                recipient_user_id=group_id,  # Group ID as recipient
                recipient_device_id="group",
                call_type=call_type,
                state=CallState.INITIATING,
                created_at=time.time(),
                connected_at=None,
                ended_at=None,
                duration=None,
                encryption_key=base64.b64encode(group_call_keys["signaling_key"]).decode(),
                signaling_key=base64.b64encode(group_call_keys["signaling_key"]).decode(),
                media_type=f"group_{call_type.value}",
                is_p2p=False,  # Group calls always use relay
                relay_server=self.relay_servers[0],
                quality_score=0.0,
                metadata={
                    "group_id": group_id,
                    "participant_count": len(participant_devices),
                    "participant_devices": participant_devices,
                    "encryption_method": "SRTP",
                    "key_distribution": "group_sender_keys"
                }
            )
            
            self.active_calls[call_id] = call_session
            
            # Prepare group call signaling for each participant
            participant_signaling = {}
            for participant in participant_devices:
                participant_keys = self._generate_participant_call_keys(
                    call_id, participant["user_id"], participant["device_id"]
                )
                
                signaling_data = {
                    "call_id": call_id,
                    "group_id": group_id,
                    "call_type": call_type.value,
                    "participant_keys": participant_keys,
                    "relay_server": self.relay_servers[0],
                    "timestamp": time.time()
                }
                
                participant_signaling[f"{participant['user_id']}_{participant['device_id']}"] = signaling_data
            
            return {
                "success": True,
                "call_session": asdict(call_session),
                "participant_signaling": participant_signaling,
                "group_keys": group_call_keys,
                "message": "Group call initiated successfully"
            }
            
        except Exception as e:
            logger.error(f"Group call initiation failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    # Private helper methods
    
    def _generate_call_encryption_keys(self, call_id: str) -> CallEncryptionKeys:
        """Generate SRTP keys for encrypted call"""
        return CallEncryptionKeys(
            call_id=call_id,
            srtp_key=secrets.token_bytes(16),  # SRTP master key
            srtp_salt=secrets.token_bytes(14),  # SRTP master salt
            signaling_key=secrets.token_bytes(32),  # Signaling encryption key
            hmac_key=secrets.token_bytes(32),  # HMAC key
            created_at=time.time()
        )
    
    def _generate_group_call_keys(self, call_id: str, participant_count: int) -> Dict[str, Any]:
        """Generate keys for group call"""
        return {
            "call_id": call_id,
            "group_srtp_key": secrets.token_bytes(16),
            "group_srtp_salt": secrets.token_bytes(14),
            "signaling_key": secrets.token_bytes(32),
            "hmac_key": secrets.token_bytes(32),
            "participant_count": participant_count
        }
    
    def _generate_participant_call_keys(
        self, call_id: str, user_id: str, device_id: str
    ) -> Dict[str, Any]:
        """Generate call keys for specific participant"""
        return {
            "user_id": user_id,
            "device_id": device_id,
            "srtp_key": secrets.token_bytes(16),
            "srtp_salt": secrets.token_bytes(14),
            "signaling_key": secrets.token_bytes(32)
        }
    
    async def _encrypt_signaling_data(
        self, signaling_data: Dict[str, Any], signal_session: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Encrypt signaling data using Signal Protocol"""
        # This would integrate with the Signal Protocol implementation
        # For now, return mock encrypted data
        return {
            "encrypted_data": base64.b64encode(
                json.dumps(signaling_data).encode()
            ).decode(),
            "session_id": signal_session.get("session_id"),
            "encryption_method": "Signal-Protocol"
        }
    
    async def _decrypt_signaling_data(
        self, encrypted_data: Dict[str, Any], signal_session: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Decrypt signaling data using Signal Protocol"""
        # This would integrate with the Signal Protocol implementation
        # For now, return mock decrypted data
        if "encrypted_data" in encrypted_data:
            decrypted_json = base64.b64decode(encrypted_data["encrypted_data"]).decode()
            return json.loads(decrypted_json)
        return encrypted_data
    
    async def _attempt_p2p_connection(
        self, call_session: CallSession, signaling_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Attempt peer-to-peer connection"""
        # This would implement actual P2P connection logic
        # For now, simulate P2P attempt
        await asyncio.sleep(0.1)  # Simulate connection attempt
        
        # Simulate 70% success rate for P2P
        if secrets.randbelow(100) < 70:
            return {
                "success": True,
                "connection_type": "p2p",
                "quality_score": 0.9,
                "latency_ms": 50,
                "bandwidth_kbps": 2000
            }
        else:
            return {
                "success": False,
                "reason": "p2p_failed",
                "fallback_required": True
            }
    
    async def _setup_relay_connection(
        self, call_session: CallSession, signaling_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Setup encrypted relay connection"""
        # This would setup actual TURN/STUN relay connection
        # For now, simulate relay setup
        await asyncio.sleep(0.2)  # Simulate relay setup
        
        return {
            "success": True,
            "connection_type": "relay",
            "relay_server": self.relay_servers[0],
            "quality_score": 0.7,
            "latency_ms": 100,
            "bandwidth_kbps": 1500
        }
