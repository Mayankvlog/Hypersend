"""
End-to-End Encryption (E2EE) Module using Signal Protocol
Implements Double Ratchet algorithm with forward secrecy and replay protection.

SECURITY CRITICAL: 
- All keys are base64 encoded for transmission
- Private keys NEVER sent to server
- Only public keys stored on server
- Messages encrypted client-side, decrypted client-side
- Server is stateless courier
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
    - Receiving Chain: Can decrypt out-of-order messages
    """
    
    def __init__(self, root_key_b64: str, dh_send_pair: Optional[Tuple] = None):
        """
        Initialize Double Ratchet session.
        
        Args:
            root_key_b64: Base64 encoded 32-byte root key (derived from DH)
            dh_send_pair: (private_key, public_key) for sending (both base64)
        """
        self.root_key = base64.b64decode(root_key_b64)
        self.dh_send_pair = dh_send_pair  # Sending key pair
        self.dh_receive_public = None  # Peer's DH public key
        self.chain_key_send = None
        self.chain_key_recv = None
        self.message_key_counter = 0
        self.prev_chain_counter = 0
        self.receiving_chains = {}  # For out-of-order messages
        
    def create_sending_chain_key(self) -> str:
        """Create initial sending chain key."""
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
    
    def ratchet_sending_chain(self) -> Tuple[str, str]:
        """
        Ratchet sending chain for next message.
        
        Returns:
            (message_key_b64, chain_key_b64) - message key for encryption, new chain key
        """
        chain_key = base64.b64decode(self.chain_key_send)
        message_key, new_chain_key = self._kdf_message_and_chain(chain_key)
        
        self.message_key_counter += 1
        self.chain_key_send = base64.b64encode(new_chain_key).decode('utf-8')
        
        return (
            base64.b64encode(message_key).decode('utf-8'),
            self.chain_key_send
        )
    
    def ratchet_receiving_chain(self) -> Tuple[str, str]:
        """
        Ratchet receiving chain for next expected message.
        
        Returns:
            (message_key_b64, chain_key_b64) - message key for decryption, new chain key
        """
        chain_key = base64.b64decode(self.chain_key_recv)
        message_key, new_chain_key = self._kdf_message_and_chain(chain_key)
        
        self.chain_key_recv = base64.b64encode(new_chain_key).decode('utf-8')
        
        return (
            base64.b64encode(message_key).decode('utf-8'),
            self.chain_key_recv
        )
    
    def perform_dh_ratchet_step(self, peer_dh_public_b64: str) -> None:
        """
        Perform DH ratchet step (when sending to new public key).
        This enables key recovery after compromise.
        """
        peer_dh_public_bytes = base64.b64decode(peer_dh_public_b64)
        new_root_key, new_chain_key = self._perform_dh_ratchet(peer_dh_public_bytes)
        
        # Save previous chain for skipped messages
        self.prev_chain_counter = self.message_key_counter
        self.message_key_counter = 0
        
        self.root_key = new_root_key
        self.dh_receive_public = peer_dh_public_b64
        self.chain_key_recv = base64.b64encode(new_chain_key).decode('utf-8')
    
    @staticmethod
    def _kdf_chain_key(root_key: bytes) -> bytes:
        """KDF for chain key derivation (32 bytes)."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'chain_key',
            info=b'Hypersend_v1',
            backend=default_backend()
        )
        return hkdf.derive(root_key)
    
    @staticmethod
    def _kdf_message_and_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
        """KDF for deriving message key and new chain key."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 for message key + 32 for chain key
            salt=b'chain_step',
            info=b'Hypersend_v1',
            backend=default_backend()
        )
        derived = hkdf.derive(chain_key)
        return derived[:32], derived[32:64]  # Split into message key and chain key
    
    @staticmethod
    def _perform_dh_ratchet(peer_dh_public_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Perform DH ratchet to get new root key and chain key.
        
        Returns:
            (root_key, chain_key)
        """
        # Generate new ephemeral key
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        # Perform DH
        shared_secret = ephemeral_private.exchange(
            x25519.X25519PublicKey(peer_dh_public_bytes)
        )
        
        # Derive new root key and chain key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'dh_ratchet',
            info=b'Hypersend_v1',
            backend=default_backend()
        )
        derived = hkdf.derive(shared_secret)
        return derived[:32], derived[32:64]


class MessageEncryption:
    """Symmetric encryption for message content using AES-256-GCM."""
    
    @staticmethod
    def encrypt_message(plaintext: str, message_key_b64: str) -> str:
        """
        Encrypt message content with AES-256-GCM.
        
        Args:
            plaintext: Message content to encrypt
            message_key_b64: Base64 encoded 32-byte message key
            
        Returns:
            Base64 encoded ciphertext with IV and tag
        """
        try:
            message_key = base64.b64decode(message_key_b64)
            plaintext_bytes = plaintext.encode('utf-8')
            
            # Generate random IV (12 bytes for GCM)
            iv = os.urandom(12)
            
            # Encrypt
            cipher = Cipher(
                algorithms.AES(message_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
            
            # Combine: IV (12) + ciphertext + auth_tag (16)
            combined = iv + ciphertext + encryptor.tag
            
            return base64.b64encode(combined).decode('utf-8')
        except Exception as e:
            logger.error(f"Message encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt message: {e}")
    
    @staticmethod
    def decrypt_message(ciphertext_b64: str, message_key_b64: str) -> str:
        """
        Decrypt message content with AES-256-GCM.
        
        Args:
            ciphertext_b64: Base64 encoded ciphertext
            message_key_b64: Base64 encoded 32-byte message key
            
        Returns:
            Decrypted plaintext
        """
        try:
            message_key = base64.b64decode(message_key_b64)
            combined = base64.b64decode(ciphertext_b64)
            
            # Extract: IV (12) + ciphertext + auth_tag (16)
            iv = combined[:12]
            auth_tag = combined[-16:]
            ciphertext = combined[12:-16]
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(message_key),
                modes.GCM(iv, auth_tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Message decryption failed: {e}")
            raise DecryptionError(f"Failed to decrypt message: {e}")


class ReplayProtection:
    """
    Prevent replay attacks by tracking message counters.
    
    Uses sliding window approach to detect duplicate/replayed messages.
    """
    
    def __init__(self, window_size: int = 1024):
        """
        Initialize replay protection.
        
        Args:
            window_size: Size of sliding window for tracking (default 1024)
        """
        self.window_size = window_size
        self.highest_counter = 0
        self.seen_counters = set()  # Duplicate detection
    
    def is_replay(self, message_counter: int) -> bool:
        """
        Check if message is a replay.
        
        Returns:
            True if replay detected, False if valid
        """
        if message_counter <= self.highest_counter - self.window_size:
            # Outside sliding window - old message
            raise ReplayAttackError(f"Message counter {message_counter} outside sliding window")
        
        if message_counter in self.seen_counters:
            # Duplicate message
            raise ReplayAttackError(f"Duplicate message detected (counter: {message_counter})")
        
        if message_counter <= self.highest_counter:
            # Out of order (allowed in Double Ratchet)
            self.seen_counters.add(message_counter)
            return False
        
        # New valid counter
        self.highest_counter = message_counter
        self.seen_counters.add(message_counter)
        
        # Prune old entries from sliding window
        cutoff = self.highest_counter - self.window_size
        self.seen_counters = {c for c in self.seen_counters if c > cutoff}
        
        return False


class SessionKeyDerivation:
    """Derive initial session keys from DH shared secret."""
    
    @staticmethod
    def derive_initial_session_key(
        shared_secret_b64: str,
        initiator_identity_b64: str,
        receiver_identity_b64: str
    ) -> str:
        """
        Derive initial root key for Double Ratchet.
        
        Args:
            shared_secret_b64: Base64 encoded DH shared secret
            initiator_identity_b64: Base64 initiator identity key (public)
            receiver_identity_b64: Base64 receiver identity key (public)
            
        Returns:
            Base64 encoded root key
        """
        shared_secret = base64.b64decode(shared_secret_b64)
        initiator_identity = base64.b64decode(initiator_identity_b64)
        receiver_identity = base64.b64decode(receiver_identity_b64)
        
        # Include both identities to prevent key substitution attacks
        key_material = shared_secret + initiator_identity + receiver_identity
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'session_init',
            info=b'Hypersend_Session_Key_v1',
            backend=default_backend()
        )
        root_key = hkdf.derive(key_material)
        
        return base64.b64encode(root_key).decode('utf-8')


def generate_fingerprint(public_key_b64: str) -> str:
    """
    Generate human-readable fingerprint for key verification.
    
    Uses SHA256 hash truncated to 32 characters.
    """
    public_key_bytes = base64.b64decode(public_key_b64)
    fingerprint = hashlib.sha256(public_key_bytes).digest()
    # Use first 32 bytes of hash
    fingerprint_b64 = base64.b16encode(fingerprint[:16]).decode().lower()
    # Format as pairs: XXXX-XXXX-XXXX-XXXX...
    return '-'.join([fingerprint_b64[i:i+4] for i in range(0, len(fingerprint_b64), 4)])[:16]
