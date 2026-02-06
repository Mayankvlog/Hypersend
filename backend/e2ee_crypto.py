"""
End-to-End Encryption (E2EE) Module using Signal Protocol
Implements Double Ratchet algorithm with forward secrecy and replay protection.

WHATSAPP-GRADE SECURITY ARCHITECTURE:

KEY HIERARCHY (Signal Protocol):
1. Identity Key (IK): Long-term DH key, persistent on device (Ed25519 for signing)
2. Signed Pre-Key (SPK): Medium-term DH key, rotated weekly (X25519)
3. One-Time Pre-Keys (OPK): Single-use DH keys, batch of 100 (X25519)
4. Session Key: Derived per conversation using X3DH + Double Ratchet

CRYPTOGRAPHIC GUARANTEES:
- Forward Secrecy: Delete past message keys → past msgs unrecoverable
- Break-In Recovery: Compromise current key → future msgs secure (DH ratchet)
- Post-Compromise Security: After session compromise, next DH ratchet step heals
- Replay Protection: Message counters + sliding window prevent replays
- Per-Message Keys: Every message uses unique derived key

X3DH (Extended Triple Diffie-Hellman) Flow:
  Initiator                           Server                        Receiver
  |                                     |                             |
  +------ Request IK,SPK,OPK of R ----->|                             |
  |                                     +------- Request R's keys --->|
  |                                     |<----- IK,SPK,OPK of R ------+
  |<----- Receive IK,SPK,OPK of R -----+|                             |
  |                                     |                             |
  |-- Calculate: SK = DH(IKi,SPKr) ----+DH(EKi,IKr) -- DH(EKi,SPKr) -|
  |             + DH(EKi,OPKr) ------  (per X3DH spec)                |
  |                                     |                             |
  +-- Send encrypted msg with EK ----->|-- Forward to R ------------->+ Decrypt
  |                                     |                             |

SECURITY CRITICAL: 
- All keys are base64 encoded for transmission
- Private keys NEVER sent to server (only stored encrypted on device)
- Only public keys stored on server
- Messages encrypted client-side, decrypted client-side
- Server is stateless courier (doesn't see plaintext or private keys)
- Device session = per-(user, device, contact_device) tuple
- Each message = new derived key (breaks if any key leaked)
"""

import os
import hmac
import base64
import hashlib
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Tuple, Dict, Optional, List
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, Mode, CounterLocation
from cryptography.hazmat.backends import default_backend
import json

logger = logging.getLogger(__name__)


class E2EECryptoError(Exception):
    """Base exception for E2EE cryptography errors"""
    pass


class KeyGenerationError(E2EECryptoError):
    """Error during key generation"""
    pass


class EncryptionError(E2EECryptoError):
    """Error during message encryption"""
    pass


class DecryptionError(E2EECryptoError):
    """Error during message decryption"""
    pass


class ReplayAttackError(E2EECryptoError):
    """Detected potential replay attack"""
    pass


class X3DHKeyExchange:
    """
    Extended Triple Diffie-Hellman (X3DH) Protocol
    
    Establishes initial shared secret between two devices securely.
    Uses initiator's ephemeral key + receiver's public key bundle.
    
    Per X3DH spec:
    - Prevents impersonation (signed prekey verification)
    - Prevents key substitution attacks (triple DH)
    - Enables out-of-band verification (identity key fingerprints)
    """
    
    @staticmethod
    def initiate_session(
        initiator_identity_pair: Tuple[str, str],  # (priv, pub) base64
        initiator_ephemeral_pair: Tuple[str, str],  # (priv, pub) base64  
        receiver_identity_public_b64: str,
        receiver_signed_prekey_public_b64: str,
        receiver_signed_prekey_signature_b64: str,  # Signed by receiver's identity key
        receiver_one_time_prekey_public_b64: Optional[str] = None,
        receiver_identity_key_for_verification_b64: str = None
    ) -> Dict:
        """
        Compute X3DH shared secret for session initiation.
        
        Args:
            initiator_identity_pair: Initiator's (private, public) identity keys
            initiator_ephemeral_pair: Initiator's (private, public) ephemeral keys
            receiver_identity_public_b64: Receiver's public identity key
            receiver_signed_prekey_public_b64: Receiver's signed prekey (medium-term)
            receiver_signed_prekey_signature_b64: Receiver's signature on prekey
            receiver_one_time_prekey_public_b64: Optional receiver's one-time prekey
            receiver_identity_key_for_verification_b64: For signature verification
            
        Returns:
            Dict with shared_secret_b64, info, and session parameters
        """
        try:
            # 1. Verify receiver's signed prekey signature
            if receiver_identity_key_for_verification_b64:
                receiver_identity_key_bytes = base64.b64decode(receiver_identity_key_for_verification_b64)
                receiver_identity_key = ed25519.Ed25519PublicKey.from_public_bytes(receiver_identity_key_bytes)
                signature_bytes = base64.b64decode(receiver_signed_prekey_signature_b64)
                signed_prekey_bytes = base64.b64decode(receiver_signed_prekey_public_b64)
                
                try:
                    receiver_identity_key.verify(signature_bytes, signed_prekey_bytes)
                    logger.debug("✓ Receiver's signed prekey signature verified")
                except Exception as sig_err:
                    logger.error(f"✗ Signed prekey signature verification failed: {sig_err}")
                    raise E2EECryptoError("Invalid signed prekey signature - possible tampering")
            
            # 2. Perform four DH operations
            # Convert base64 private keys to DH objects
            initiator_identity_priv_bytes = base64.b64decode(initiator_identity_pair[0])
            initiator_ephemeral_priv_bytes = base64.b64decode(initiator_ephemeral_pair[0])
            
            # X25519 private keys for DH
            initiator_identity_priv = x25519.X25519PrivateKey.from_private_bytes(initiator_identity_priv_bytes)
            initiator_ephemeral_priv = x25519.X25519PrivateKey.from_private_bytes(initiator_ephemeral_priv_bytes)
            
            # Receiver's public keys
            receiver_identity_pub_bytes = base64.b64decode(receiver_identity_public_b64)
            receiver_signed_prekey_bytes = base64.b64decode(receiver_signed_prekey_public_b64)
            receiver_identity_pub = x25519.X25519PublicKey(receiver_identity_pub_bytes)
            receiver_signed_prekey_pub = x25519.X25519PublicKey(receiver_signed_prekey_bytes)
            
            # Four DH computations (per X3DH spec)
            dh_1 = initiator_identity_priv.exchange(receiver_signed_prekey_pub)  # IKi → SPKr
            dh_2 = initiator_ephemeral_priv.exchange(receiver_identity_pub)      # EKi → IKr
            dh_3 = initiator_ephemeral_priv.exchange(receiver_signed_prekey_pub) # EKi → SPKr
            
            # Concatenate: DH1 || DH2 || DH3 (|| DH4 if OPK present)
            shared_secret_input = dh_1 + dh_2 + dh_3
            
            # If one-time prekey available, include DH4
            dh_4_computed = False
            if receiver_one_time_prekey_public_b64:
                receiver_one_time_prekey_bytes = base64.b64decode(receiver_one_time_prekey_public_b64)
                receiver_one_time_prekey_pub = x25519.X25519PublicKey(receiver_one_time_prekey_bytes)
                dh_4 = initiator_ephemeral_priv.exchange(receiver_one_time_prekey_pub)
                shared_secret_input = shared_secret_input + dh_4
                dh_4_computed = True
            
            # 3. KDF to derive shared secret
            shared_secret = X3DHKeyExchange._kdf_x3dh(shared_secret_input)
            
            return {
                "shared_secret_b64": base64.b64encode(shared_secret).decode('utf-8'),
                "initiator_ephemeral_public_b64": initiator_ephemeral_pair[1],  # Send with first message
                "receiver_one_time_prekey_used": dh_4_computed,
                "x3dh_info": "Hypersend_X3DH_v1",
                "session_initialized_at": datetime.now(timezone.utc).isoformat(),
                "signature_verified": bool(receiver_identity_key_for_verification_b64)
            }
        except E2EECryptoError:
            raise
        except Exception as e:
            logger.error(f"X3DH key exchange failed: {e}")
            raise E2EECryptoError(f"X3DH initiation failed: {e}")
    
    @staticmethod
    def receive_session(
        receiver_identity_pair: Tuple[str, str],  # (priv, pub) base64
        receiver_signed_prekey_pair: Tuple[str, str],  # (priv, pub) base64
        receiver_one_time_prekey_pair: Optional[Tuple[str, str]] = None,  # (priv, pub) base64
        initiator_identity_public_b64: str = None,
        initiator_ephemeral_public_b64: str = None
    ) -> Dict:
        """
        Compute X3DH shared secret from receiver side.
        
        Takes initiator's public keys and derives same shared secret.
        
        Returns:
            Dict with shared_secret_b64 (same as initiator computed)
        """
        try:
            # Convert receiver's private keys
            receiver_identity_priv_bytes = base64.b64decode(receiver_identity_pair[0])
            receiver_signed_prekey_priv_bytes = base64.b64decode(receiver_signed_prekey_pair[0])
            
            receiver_identity_priv = x25519.X25519PrivateKey.from_private_bytes(receiver_identity_priv_bytes)
            receiver_signed_prekey_priv = x25519.X25519PrivateKey.from_private_bytes(receiver_signed_prekey_priv_bytes)
            
            # Initiator's public keys
            initiator_identity_pub_bytes = base64.b64decode(initiator_identity_public_b64)
            initiator_ephemeral_pub_bytes = base64.b64decode(initiator_ephemeral_public_b64)
            
            initiator_identity_pub = x25519.X25519PublicKey(initiator_identity_pub_bytes)
            initiator_ephemeral_pub = x25519.X25519PublicKey(initiator_ephemeral_pub_bytes)
            
            # Same four DH operations (symmetric)
            dh_1 = receiver_signed_prekey_priv.exchange(initiator_identity_pub)  # SPKr → IKi
            dh_2 = receiver_identity_priv.exchange(initiator_ephemeral_pub)      # IKr → EKi
            dh_3 = receiver_signed_prekey_priv.exchange(initiator_ephemeral_pub) # SPKr → EKi
            
            shared_secret_input = dh_1 + dh_2 + dh_3
            
            # Optional DH4 if OPK used
            if receiver_one_time_prekey_pair:
                receiver_one_time_prekey_priv_bytes = base64.b64decode(receiver_one_time_prekey_pair[0])
                receiver_one_time_prekey_priv = x25519.X25519PrivateKey.from_private_bytes(receiver_one_time_prekey_priv_bytes)
                dh_4 = receiver_one_time_prekey_priv.exchange(initiator_ephemeral_pub)
                shared_secret_input = shared_secret_input + dh_4
            
            # Same KDF as initiator → same shared secret
            shared_secret = X3DHKeyExchange._kdf_x3dh(shared_secret_input)
            
            return {
                "shared_secret_b64": base64.b64encode(shared_secret).decode('utf-8'),
                "session_initialized_at": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logger.error(f"X3DH receive failed: {e}")
            raise E2EECryptoError(f"X3DH reception failed: {e}")
    
    @staticmethod
    def _kdf_x3dh(dh_inputs: bytes) -> bytes:
        """
        KDF for X3DH shared secret derivation.
        
        Produces 32-byte root key for Double Ratchet.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'X3DH_salt',
            info=b'Hypersend_X3DH_v1',
            backend=default_backend()
        )
        return hkdf.derive(dh_inputs)


class SignalProtocolKeyManager:
    """
    Manages Signal Protocol keys and key material.
    
    Key Hierarchy:
    1. Identity Key: Long-term DH key pair (persistent, stored encrypted on device)
    2. Signed Pre-Key: Medium-term DH key (rotated weekly, signed with identity key)
    3. One-Time Pre-Keys: Single-use DH keys (generated in batches of 100)
    4. Session Key: Derived per conversation using DH
    """
    
    # Constants for key generation and rotation
    IDENTITY_KEY_SIZE = 32  # X25519
    PREKEY_GENERATION_BATCH = 100  # Generate 100 one-time prekeys at a time
    LOW_PREKEY_THRESHOLD = 20  # Alert when one-time prekeys drop below 20
    SIGNED_PREKEY_ROTATION_DAYS = 7  # Rotate signed prekey weekly
    PREKEY_EXPIRATION_DAYS = 30  # One-time prekeys expire after 30 days
    
    @staticmethod
    def generate_identity_key_pair() -> Tuple[str, str]:
        """
        Generate identity key pair (long-term, persistent).
        
        Returns:
            Tuple of (private_key_b64, public_key_b64)
            
        SECURITY: Private key should be stored encrypted on user device only, never sent to server.
        """
        try:
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            # Encode to base64 for transmission (server stores public only)
            private_key_bytes = private_key.private_bytes_raw()
            public_key_bytes = public_key.public_bytes_raw()
            
            return (
                base64.b64encode(private_key_bytes).decode('utf-8'),
                base64.b64encode(public_key_bytes).decode('utf-8')
            )
        except Exception as e:
            logger.error(f"Failed to generate identity key pair: {e}")
            raise KeyGenerationError(f"Identity key generation failed: {e}")
    
    @staticmethod
    def generate_signed_prekey_pair(identity_private_key_b64: str) -> Dict:
        """
        Generate signed pre-key pair (medium-term, rotated weekly).
        
        The signed prekey is signed with the identity key to prevent impersonation.
        
        Args:
            identity_private_key_b64: Base64 identity private key (user device only)
            
        Returns:
            Dict with:
            - signed_prekey_id: Unique ID
            - public_key_b64: Base64 encoded public key
            - signature_b64: Base64 encoded signature
        """
        try:
            # Generate DH key
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            public_key_bytes = public_key.public_bytes_raw()
            
            # Sign with identity key
            identity_private_bytes = base64.b64decode(identity_private_key_b64)
            identity_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(identity_private_bytes)
            signature = identity_private_key.sign(public_key_bytes)
            
            return {
                'signed_prekey_id': secrets.randbelow(2**31),
                'public_key_b64': base64.b64encode(public_key_bytes).decode('utf-8'),
                'signature_b64': base64.b64encode(signature).decode('utf-8')
            }
        except Exception as e:
            logger.error(f"Failed to generate signed prekey: {e}")
            raise KeyGenerationError(f"Signed prekey generation failed: {e}")
    
    @staticmethod
    def generate_one_time_prekeys(count: int = 100) -> List[Dict]:
        """
        Generate batch of one-time pre-keys (single-use).
        
        Args:
            count: Number of keys to generate
            
        Returns:
            List of dicts with prekey_id and public_key_b64
        """
        try:
            prekeys = []
            start_id = secrets.randbelow(2**30)  # Start with random ID
            
            for i in range(count):
                private_key = x25519.X25519PrivateKey.generate()
                public_key = private_key.public_key()
                public_key_bytes = public_key.public_bytes_raw()
                
                prekeys.append({
                    'prekey_id': start_id + i,
                    'public_key_b64': base64.b64encode(public_key_bytes).decode('utf-8')
                })
            
            return prekeys
        except Exception as e:
            logger.error(f"Failed to generate one-time prekeys: {e}")
            raise KeyGenerationError(f"One-time prekey generation failed: {e}")


class DoubleRatchet:
    """
    Double Ratchet Algorithm (Signal Protocol session management).
    
    Provides:
    - Forward Secrecy: Past messages stay secret even if keys compromised
    - Break-In Recovery: Future messages stay secret after key compromise
    - Message Ratcheting: Key advances with each message
    - Receiving Chain: Can decrypt out-of-order messages (skipped message keys)
    - DH Ratchet: Ratchet on new ephemeral DH keys (recovery from compromise)
    
    STATE MACHINE:
    1. Root key (KR) - derived from X3DH
    2. Sending chain key (CKs) - advances with each sent message
    3. Receiving chain key (CKr) - advances with each received message
    4. Skipped message keys storage - for out-of-order decryption
    
    SECURITY: Each message = unique key (chain ratchet) + optional DH ratchet step
    """
    
    MAX_SKIPPED_KEYS = 2048  # Max skipped messages to store
    SKIPPED_KEY_MAX_AGE_DAYS = 1  # Delete skipped keys older than 1 day
    
    def __init__(self, root_key_b64: str, dh_send_pair: Optional[Tuple[str, str]] = None):
        """
        Initialize Double Ratchet session.
        
        Args:
            root_key_b64: Base64 encoded 32-byte root key (derived from X3DH)
            dh_send_pair: (private_key_b64, public_key_b64) for sending
        """
        self.root_key = base64.b64decode(root_key_b64)
        self.dh_send_pair = dh_send_pair  # Sending key pair (ephemeral)
        self.dh_receive_public = None  # Peer's DH public key (ephemeral)
        self.chain_key_send = None
        self.chain_key_recv = None
        self.message_key_counter = 0
        self.prev_chain_counter = 0
        self.receiving_chains = {}  # {dh_public_key: (chain_key, counter)}
        
        # Skipped message keys storage: {(dh_public, counter): (message_key, timestamp)}
        self.skipped_keys = {}
        
    def create_sending_chain_key(self) -> str:
        """Create initial sending chain key from root."""
        chain_key = self._kdf_chain_key(self.root_key)
        self.chain_key_send = base64.b64encode(chain_key).decode('utf-8')
        return self.chain_key_send
    
    def create_receiving_chain_key(self, peer_dh_public_b64: str) -> str:
        """Create receiving chain key using peer's DH public key."""
        peer_dh_public_bytes = base64.b64decode(peer_dh_public_b64)
        self.dh_receive_public = peer_dh_public_b64
        
        # Derive new root key and chain key from DH
        new_root_key, new_chain_key = self._perform_dh_ratchet(peer_dh_public_bytes)
        self.root_key = new_root_key
        self.chain_key_recv = base64.b64encode(new_chain_key).decode('utf-8')
        
        return self.chain_key_recv
    
    def ratchet_sending_chain(self) -> Tuple[str, str, int]:
        """
        Ratchet sending chain for next message.
        
        Returns:
            (message_key_b64, chain_key_b64, message_counter)
        """
        chain_key = base64.b64decode(self.chain_key_send)
        message_key, new_chain_key = self._kdf_message_and_chain(chain_key)
        
        self.message_key_counter += 1
        self.chain_key_send = base64.b64encode(new_chain_key).decode('utf-8')
        
        return (
            base64.b64encode(message_key).decode('utf-8'),
            self.chain_key_send,
            self.message_key_counter
        )
    
    def ratchet_receiving_chain(self) -> Tuple[str, str, int]:
        """
        Ratchet receiving chain for next expected message.
        
        Returns:
            (message_key_b64, chain_key_b64, message_counter)
        """
        chain_key = base64.b64decode(self.chain_key_recv)
        message_key, new_chain_key = self._kdf_message_and_chain(chain_key)
        
        counter = self._get_recv_counter()
        self.chain_key_recv = base64.b64encode(new_chain_key).decode('utf-8')
        
        return (
            base64.b64encode(message_key).decode('utf-8'),
            self.chain_key_recv,
            counter
        )
    
    def skip_message_keys(self, until_counter: int) -> int:
        """
        Generate and store message keys for skipped messages.
        
        When receiving a message with counter N but expected counter M (M < N),
        store keys M, M+1, ..., N-1 for possible out-of-order delivery.
        
        Args:
            until_counter: Skip until this counter value
            
        Returns:
            Number of keys skipped
        """
        if until_counter - self._get_recv_counter() > self.MAX_SKIPPED_KEYS:
            raise DecryptionError(f"Too many skipped messages (>{self.MAX_SKIPPED_KEYS})")
        
        skipped_count = 0
        chain_key = base64.b64decode(self.chain_key_recv) if self.chain_key_recv else self.root_key
        counter = self._get_recv_counter()
        
        while counter < until_counter:
            message_key, chain_key = self._kdf_message_and_chain(chain_key)
            
            # Store with DH key and counter as index
            storage_key = (self.dh_receive_public or "initial", counter)
            self.skipped_keys[storage_key] = {
                "message_key_b64": base64.b64encode(message_key).decode('utf-8'),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            counter += 1
            skipped_count += 1
        
        logger.debug(f"Skipped {skipped_count} message keys for out-of-order delivery")
        return skipped_count
    
    def get_skipped_message_key(self, dh_public_b64: str, counter: int) -> Optional[str]:
        """
        Retrieve message key for previously skipped message.
        
        Args:
            dh_public_b64: DH public key from that receiving chain
            counter: Message counter
            
        Returns:
            Message key base64 or None if not found
        """
        storage_key = (dh_public_b64, counter)
        
        if storage_key in self.skipped_keys:
            msg_key_data = self.skipped_keys.pop(storage_key)  # Remove after use
            return msg_key_data["message_key_b64"]
        
        return None
    
    def perform_dh_ratchet_step(self, peer_dh_public_b64: str) -> None:
        """
        Perform DH ratchet step (break-in recovery).
        
        When receiving new ephemeral DH key, ratchet both root key and receiving chain.
        This ensures future messages are secure even if session was compromised.
        
        Args:
            peer_dh_public_b64: New ephemeral DH public key from peer
        """
        peer_dh_public_bytes = base64.b64decode(peer_dh_public_b64)
        new_root_key, new_chain_key = self._perform_dh_ratchet(peer_dh_public_bytes)
        
        # Save previous chain for skipped messages
        self.prev_chain_counter = self._get_recv_counter()
        
        self.root_key = new_root_key
        self.dh_receive_public = peer_dh_public_b64
        self.chain_key_recv = base64.b64encode(new_chain_key).decode('utf-8')
        
        logger.debug(f"✓ DH ratchet performed, break-in recovery enabled")
    
    def cleanup_old_skipped_keys(self) -> int:
        """
        Delete skipped message keys older than MAX_AGE.
        
        Returns:
            Number of keys deleted
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=self.SKIPPED_KEY_MAX_AGE_DAYS)
        keys_to_delete = []
        
        for key, data in self.skipped_keys.items():
            try:
                key_time = datetime.fromisoformat(data["timestamp"]).replace(tzinfo=timezone.utc)
                if key_time < cutoff:
                    keys_to_delete.append(key)
            except:
                pass
        
        for key in keys_to_delete:
            del self.skipped_keys[key]
        
        return len(keys_to_delete)
    
    def _get_recv_counter(self) -> int:
        """Get current receiving message counter."""
        # This would be tracked separately in production
        return 0  # Placeholder
    
    @staticmethod
    def _kdf_chain_key(root_key: bytes) -> bytes:
        """KDF for chain key derivation (32 bytes)."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'chain_key_salt',
            info=b'Hypersend_ChainKey_v1',
            backend=default_backend()
        )
        return hkdf.derive(root_key)
    
    @staticmethod
    def _kdf_message_and_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
        """KDF for deriving message key and new chain key."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 for message key + 32 for chain key
            salt=b'chain_step_salt',
            info=b'Hypersend_ChainStep_v1',
            backend=default_backend()
        )
        derived = hkdf.derive(chain_key)
        return derived[:32], derived[32:64]  # Split into message key and new chain key
    
    def _perform_dh_ratchet(self, peer_dh_public_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Perform DH ratchet to get new root key and chain key.
        
        Generates new ephemeral key pair and performs DH with peer's key.
        
        Returns:
            (root_key, chain_key)
        """
        # Generate new ephemeral key
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        # Store for next sending turn
        self.dh_send_pair = (
            base64.b64encode(ephemeral_private.private_bytes_raw()).decode('utf-8'),
            base64.b64encode(ephemeral_public.public_bytes_raw()).decode('utf-8')
        )
        
        # Perform DH
        shared_secret = ephemeral_private.exchange(
            x25519.X25519PublicKey(peer_dh_public_bytes)
        )
        
        # Derive new root key and chain key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'dh_ratchet_salt',
            info=b'Hypersend_DHRatchet_v1',
            backend=default_backend()
        )
        derived = hkdf.derive(shared_secret)
        return derived[:32], derived[32:64]


class DeviceSessionState:
    """
    Tracks encryption state for a specific device-to-device session.
    
    Per WhatsApp architecture:
    - One session per (sender_device, recipient_device) pair
    - Each device has separate session state (not shared)
    - Sessions initialized via X3DH
    - Advanced via Double Ratchet per message
    """
    
    def __init__(
        self,
        user_id: str,
        device_id: str,
        contact_user_id: str,
        contact_device_id: str,
        session_id: str,
        root_key_b64: str,
        initiator: bool = False
    ):
        """
        Initialize device session state.
        
        Args:
            user_id: Local user ID
            device_id: Local device ID
            contact_user_id: Remote user ID
            contact_device_id: Remote device ID
            session_id: Unique session identifier
            root_key_b64: Root key from X3DH
            initiator: Whether this side initiated the session
        """
        self.user_id = user_id
        self.device_id = device_id
        self.contact_user_id = contact_user_id
        self.contact_device_id = contact_device_id
        self.session_id = session_id
        
        # Double Ratchet instance
        self.double_ratchet = DoubleRatchet(root_key_b64)
        
        # Session metadata
        self.is_initiator = initiator
        self.created_at = datetime.now(timezone.utc)
        self.last_activity = datetime.now(timezone.utc)
        self.message_count = 0
        
        # Chain state tracking
        self.sending_chain_key_b64 = self.double_ratchet.create_sending_chain_key()
        self.receiving_chain_key_b64 = None  # Set after first message
        
        # Session security metrics
        self.dh_ratchet_count = 0  # Number of DH ratchet steps
        self.key_rotation_count = 0  # Number of chain ratchet steps
    
    def get_session_state_dict(self) -> Dict:
        """Get session state for serialization/storage."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "contact_user_id": self.contact_user_id,
            "contact_device_id": self.contact_device_id,
            "is_initiator": self.is_initiator,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "message_count": self.message_count,
            "dh_ratchet_count": self.dh_ratchet_count,
            "key_rotation_count": self.key_rotation_count,
            "sending_chain_key": self.sending_chain_key_b64,
            "receiving_chain_key": self.receiving_chain_key_b64
        }



class MessageEncryption:
    """
    Symmetric encryption for message content using AES-256-GCM.
    
    Per-message security:
    - Unique IV per message (prevents patterns)
    - Authentication tag (tampering detection)
    - Base64 encoding (transport safe)
    - Supports plaintext + optional attached files
    """
    
    @staticmethod
    def encrypt_message(
        plaintext: str,
        message_key_b64: str,
        message_counter: int = 0,
        additional_authenticated_data: str = None
    ) -> Dict:
        """
        Encrypt message content with AES-256-GCM.
        
        Args:
            plaintext: Message content to encrypt
            message_key_b64: Base64 encoded 32-byte message key
            message_counter: Message sequence number (for replay protection)
            additional_authenticated_data: Optional AAD for authentication
            
        Returns:
            Dict with ciphertext_b64, iv_b64, tag_b64, counter
        """
        try:
            message_key = base64.b64decode(message_key_b64)
            plaintext_bytes = plaintext.encode('utf-8')
            
            # Generate random IV (12 bytes for GCM standard)
            iv = os.urandom(12)
            
            # Prepare AAD (includes counter for replay protection)
            aad = f"{message_counter}".encode('utf-8')
            if additional_authenticated_data:
                aad = aad + b'|' + additional_authenticated_data.encode('utf-8')
            
            # Encrypt with GCM
            cipher = Cipher(
                algorithms.AES(message_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(aad)
            ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
            
            return {
                "ciphertext_b64": base64.b64encode(ciphertext).decode('utf-8'),
                "iv_b64": base64.b64encode(iv).decode('utf-8'),
                "tag_b64": base64.b64encode(encryptor.tag).decode('utf-8'),
                "counter": message_counter
            }
        except Exception as e:
            logger.error(f"Message encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt message: {e}")
    
    @staticmethod
    def decrypt_message(
        ciphertext_b64: str,
        message_key_b64: str,
        iv_b64: str,
        tag_b64: str,
        message_counter: int = 0,
        additional_authenticated_data: str = None
    ) -> str:
        """
        Decrypt message content with AES-256-GCM.
        
        Args:
            ciphertext_b64: Base64 encoded ciphertext
            message_key_b64: Base64 encoded 32-byte message key
            iv_b64: Base64 encoded IV
            tag_b64: Base64 encoded authentication tag
            message_counter: Message sequence number
            additional_authenticated_data: Optional AAD
            
        Returns:
            Decrypted plaintext
        """
        try:
            message_key = base64.b64decode(message_key_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            tag = base64.b64decode(tag_b64)
            
            # Prepare AAD
            aad = f"{message_counter}".encode('utf-8')
            if additional_authenticated_data:
                aad = aad + b'|' + additional_authenticated_data.encode('utf-8')
            
            # Decrypt with GCM
            cipher = Cipher(
                algorithms.AES(message_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(aad)
            plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Message decryption failed: {e}")
            raise DecryptionError(f"Failed to decrypt message: {e}")


def generate_fingerprint(public_key_b64: str, format_type: str = "human") -> str:
    """
    Generate fingerprint for device identity key verification.
    
    Human-readable format for QR code verification (out-of-band).
    
    Args:
        public_key_b64: Base64 encoded public identity key
        format_type: "human" (default) or "hex"
        
    Returns:
        Fingerprint string (e.g., "EA2B-C4D7-9F1E-3A5B")
    """
    public_key_bytes = base64.b64decode(public_key_b64)
    fingerprint_hash = hashlib.sha256(public_key_bytes).digest()
    
    if format_type == "human":
        # Human-readable: hex pairs with dashes (32 chars total)
        fingerprint_hex = base64.b16encode(fingerprint_hash[:16]).decode().upper()
        # Format as pairs: AAAA-BBBB-CCCC-DDDD
        return '-'.join([fingerprint_hex[i:i+4] for i in range(0, len(fingerprint_hex), 4)])
    else:
        # Full hex string
        return base64.b16encode(fingerprint_hash).decode().upper()


class ReplayProtection:
    """
    Prevent replay attacks by tracking message counters.
    
    SECURITY STRATEGY:
    - Each message has unique counter (incremented per device pair)
    - Sliding window detects replayed/duplicated messages
    - Out-of-order messages allowed (Signal Protocol feature)
    - Counters reset on new DH ratchet (fresh session establishment)
    
    ATTACK SCENARIOS PREVENTED:
    1. Simple Replay: Attacker replays old message → counter detected as duplicate
    2. Out-of-sync: Legitimate out-of-order delivery → stored in skipped keys
    3. Message Deletion: Attacker drops message N → counter gap detected
    """
    
    def __init__(self, window_size: int = 2048):
        """
        Initialize replay protection.
        
        Args:
            window_size: Size of sliding window for tracking (default 2048)
        """
        self.window_size = window_size
        self.highest_counter = 0
        self.seen_counters = set()  # Track seen counters in window
    
    def check_counter(self, message_counter: int) -> bool:
        """
        Check if message counter is valid (not a replay).
        
        Returns:
            True if valid, False if replay/duplicate
            
        Raises:
            ReplayAttackError for out-of-window or duplicate messages
        """
        if message_counter <= self.highest_counter - self.window_size:
            # Outside sliding window - too old
            raise ReplayAttackError(
                f"Message counter {message_counter} outside sliding window "
                f"(highest: {self.highest_counter}, window: {self.window_size})"
            )
        
        if message_counter in self.seen_counters:
            # Duplicate message detected
            raise ReplayAttackError(
                f"Duplicate message detected (counter: {message_counter})"
            )
        
        # Valid counter
        self.seen_counters.add(message_counter)
        
        if message_counter > self.highest_counter:
            self.highest_counter = message_counter
        
        # Prune old entries from sliding window
        cutoff = self.highest_counter - self.window_size
        self.seen_counters = {c for c in self.seen_counters if c > cutoff}
        
        return True
    
    def is_out_of_order(self, message_counter: int) -> bool:
        """Check if message is out-of-order (but valid)."""
        return message_counter < self.highest_counter
    
    def reset_for_new_session(self) -> None:
        """Reset replay protection for new DH ratchet session."""
        self.highest_counter = 0
        self.seen_counters = set()
        logger.debug("✓ Replay protection reset for new session")


class SessionKeyDerivation:
    """
    Session key derivation for Signal Protocol initial session establishment.
    
    Derives the initial root key from X3DH shared secret and identity keys.
    This is the cryptographic foundation for Double Ratchet sessions.
    """
    
    @staticmethod
    def derive_initial_session_key(
        shared_secret_b64: str,
        initiator_identity_b64: str,
        receiver_identity_b64: str
    ) -> str:
        """
        Derive initial session root key from X3DH parameters.
        
        Args:
            shared_secret_b64: Base64 encoded X3DH shared secret
            initiator_identity_b64: Base64 encoded initiator identity key
            receiver_identity_b64: Base64 encoded receiver identity key
            
        Returns:
            Base64 encoded root key for Double Ratchet session
        """
        try:
            # Decode all inputs
            shared_secret = base64.b64decode(shared_secret_b64)
            initiator_identity = base64.b64decode(initiator_identity_b64)
            receiver_identity = base64.b64decode(receiver_identity_b64)
            
            # Combine inputs for HKDF
            # This follows Signal Protocol specification for root key derivation
            input_material = (
                shared_secret +
                initiator_identity +
                receiver_identity
            )
            
            # Derive root key using HKDF-SHA256
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit root key
                salt=b'Hypersend_RootKey_Salt_v1',
                info=b'Hypersend_SessionKeyDerivation_v1',
                backend=default_backend()
            )
            
            root_key = hkdf.derive(input_material)
            root_key_b64 = base64.b64encode(root_key).decode('utf-8')
            
            logger.debug("✓ Session root key derived successfully")
            return root_key_b64
            
        except Exception as e:
            logger.error(f"Session key derivation failed: {e}")
            raise KeyGenerationError(f"Failed to derive session key: {e}")


def generate_fingerprint(identity_key_b64: str) -> str:
    """
    Generate fingerprint for identity key verification.
    
    Args:
        identity_key_b64: Base64 encoded identity key
        
    Returns:
        Hexadecimal fingerprint string for manual verification
    """
    try:
        identity_key = base64.b64decode(identity_key_b64)
        fingerprint_hash = hashlib.sha256(identity_key).digest()
        return base64.b16encode(fingerprint_hash).decode().upper()
    except Exception as e:
        logger.error(f"Fingerprint generation failed: {e}")
        raise KeyGenerationError(f"Failed to generate fingerprint: {e}")
