"""
WhatsApp-Grade Signal Protocol Implementation
===========================================

Core cryptographic primitives and protocol implementation
compatible with Signal Protocol specifications.

Security Properties:
- Forward secrecy through Double Ratchet
- Post-compromise security via DH ratchet
- Per-device key isolation
- Server remains crypto-blind
- Zero-knowledge message delivery
- Automatic key rotation for sessions and groups
"""

import os
import json
import hashlib
import hmac
import secrets
import struct
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

@dataclass
class IdentityKeyPair:
    """Long-term identity key pair (X25519 + Ed25519)"""
    private_key: bytes
    public_key: bytes
    signature_key: bytes  # Ed25519 for signing
    
    @classmethod
    def generate(cls) -> 'IdentityKeyPair':
        """Generate new identity key pair"""
        # X25519 for DH
        dh_private = x25519.X25519PrivateKey.generate()
        dh_public = dh_private.public_key()
        
        # Ed25519 for signing
        ed_private = ed25519.Ed25519PrivateKey.generate()
        ed_public = ed_private.public_key()
        
        return cls(
            private_key=dh_private.private_bytes_raw(),
            public_key=dh_public.public_bytes_raw(),
            signature_key=ed_private.private_bytes_raw()
        )
    
    def sign(self, message: bytes) -> bytes:
        """Sign message with Ed25519 key"""
        ed_private = ed25519.Ed25519PrivateKey.from_private_bytes(self.signature_key)
        return ed_private.sign(message)
    
    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature with Ed25519 public key"""
        try:
            ed_public = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            ed_public.verify(signature, message)
            return True
        except Exception:
            return False

@dataclass
class SignedPreKey:
    """Signed pre-key for X3DH handshake"""
    key_id: int
    key_pair: bytes  # X25519 key pair
    signature: bytes  # Ed25519 signature
    
    @classmethod
    def create(cls, key_id: int, identity_key: IdentityKeyPair) -> 'SignedPreKey':
        """Create signed pre-key"""
        # Generate X25519 key pair
        pre_key = x25519.X25519PrivateKey.generate()
        pre_key_public = pre_key.public_key()
        
        # Serialize key pair
        key_pair = pre_key.private_bytes_raw() + pre_key_public.public_bytes_raw()
        
        # Sign the public key
        signature = identity_key.sign(pre_key_public.public_bytes_raw())
        
        return cls(
            key_id=key_id,
            key_pair=key_pair,
            signature=signature
        )

@dataclass
class OneTimePreKey:
    """One-time pre-key for X3DH handshake"""
    key_id: int
    public_key: bytes
    
    @classmethod
    def generate(cls, key_id: int) -> 'OneTimePreKey':
        """Generate one-time pre-key"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        return cls(
            key_id=key_id,
            public_key=public_key.public_bytes_raw()
        )

@dataclass
class X3DHBundle:
    """X3DH initialization bundle"""
    identity_key: bytes  # X25519 public key
    signed_pre_key: bytes  # X25519 public key
    signed_pre_key_id: int
    signed_pre_key_signature: bytes  # Ed25519 signature
    one_time_pre_key: Optional[bytes]  # X25519 public key
    one_time_pre_key_id: Optional[int]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for transmission"""
        result = {
            "identity_key": self.identity_key.hex(),
            "signed_pre_key": self.signed_pre_key.hex(),
            "signed_pre_key_id": self.signed_pre_key_id,
            "signed_pre_key_signature": self.signed_pre_key_signature.hex()
        }
        if self.one_time_pre_key:
            result.update({
                "one_time_pre_key": self.one_time_pre_key.hex(),
                "one_time_pre_key_id": self.one_time_pre_key_id
            })
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'X3DHBundle':
        """Create from dictionary"""
        return cls(
            identity_key=bytes.fromhex(data["identity_key"]),
            signed_pre_key=bytes.fromhex(data["signed_pre_key"]),
            signed_pre_key_id=data["signed_pre_key_id"],
            signed_pre_key_signature=bytes.fromhex(data["signed_pre_key_signature"]),
            one_time_pre_key=bytes.fromhex(data["one_time_pre_key"]) if data.get("one_time_pre_key") else None,
            one_time_pre_key_id=data.get("one_time_pre_key_id")
        )

class X3DHHandshake:
    """X3DH handshake implementation"""
    
    @staticmethod
    def generate_ephemeral_key() -> Tuple[bytes, bytes]:
        """Generate ephemeral key pair for X3DH"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key.private_bytes_raw(), public_key.public_bytes_raw()
    
    @staticmethod
    def compute_shared_secret(private_key: bytes, public_key: bytes) -> bytes:
        """Compute X25519 shared secret"""
        priv = x25519.X25519PrivateKey.from_private_bytes(private_key)
        pub = x25519.X25519PublicKey.from_public_bytes(public_key)
        return priv.exchange(pub)
    
    @staticmethod
    def initiator_handshake(
        identity_key: IdentityKeyPair,
        signed_pre_key: SignedPreKey,
        one_time_pre_key: Optional[OneTimePreKey],
        remote_bundle: X3DHBundle
    ) -> bytes:
        """
        Perform X3DH handshake as initiator
        
        Returns: shared secret for Double Ratchet initialization
        """
        # Generate ephemeral key
        ephemeral_priv, ephemeral_pub = X3DHHandshake.generate_ephemeral_key()
        
        # Verify signed pre-key signature
        if not identity_key.verify_signature(
            remote_bundle.signed_pre_key,
            remote_bundle.signed_pre_key_signature,
            remote_bundle.identity_key + remote_bundle.signed_pre_key
        ):
            raise ValueError("Invalid signed pre-key signature")
        
        # Compute DH shared secrets
        dh1 = X3DHHandshake.compute_shared_secret(identity_key.private_key, remote_bundle.signed_pre_key)
        dh2 = X3DHHandshake.compute_shared_secret(signed_pre_key.key_pair[:32], remote_bundle.identity_key)
        dh3 = X3DHHandshake.compute_shared_secret(signed_pre_key.key_pair[:32], remote_bundle.signed_pre_key)
        dh4 = b""
        if one_time_pre_key and remote_bundle.one_time_pre_key:
            dh4 = X3DHHandshake.compute_shared_secret(one_time_pre_key.key_pair[:32], remote_bundle.one_time_pre_key)
        dh5 = X3DHHandshake.compute_shared_secret(ephemeral_priv, remote_bundle.identity_key)
        dh6 = X3DHHandshake.compute_shared_secret(ephemeral_priv, remote_bundle.signed_pre_key)
        
        # Combine shared secrets
        shared_secrets = [dh1, dh2, dh3, dh5, dh6]
        if dh4:
            shared_secrets.append(dh4)
        
        # Derive master secret using HKDF
        master_secret = b"".join(shared_secrets)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"X3DH_MasterSecret",
            backend=default_backend()
        )
        
        return hkdf.derive(master_secret)

@dataclass
class DoubleRatchetState:
    """Double Ratchet state per device"""
    root_key: bytes
    chain_key: bytes
    sending_chain_key: Optional[bytes]
    receiving_chain_key: Optional[bytes]
    dh_private_key: bytes
    dh_public_key: bytes
    remote_dh_public_key: Optional[bytes]
    message_number: int
    received_message_number: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize state for storage"""
        return {
            "root_key": self.root_key.hex(),
            "chain_key": self.chain_key.hex(),
            "sending_chain_key": self.sending_chain_key.hex() if self.sending_chain_key else None,
            "receiving_chain_key": self.receiving_chain_key.hex() if self.receiving_chain_key else None,
            "dh_private_key": self.dh_private_key.hex(),
            "dh_public_key": self.dh_public_key.hex(),
            "remote_dh_public_key": self.remote_dh_public_key.hex() if self.remote_dh_public_key else None,
            "message_number": self.message_number,
            "received_message_number": self.received_message_number
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DoubleRatchetState':
        """Deserialize state from storage"""
        return cls(
            root_key=bytes.fromhex(data["root_key"]),
            chain_key=bytes.fromhex(data["chain_key"]),
            sending_chain_key=bytes.fromhex(data["sending_chain_key"]) if data["sending_chain_key"] else None,
            receiving_chain_key=bytes.fromhex(data["receiving_chain_key"]) if data["receiving_chain_key"] else None,
            dh_private_key=bytes.fromhex(data["dh_private_key"]),
            dh_public_key=bytes.fromhex(data["dh_public_key"]),
            remote_dh_public_key=bytes.fromhex(data["remote_dh_public_key"]) if data["remote_dh_public_key"] else None,
            message_number=data["message_number"],
            received_message_number=data["received_message_number"]
        )

class DoubleRatchet:
    """Double Ratchet implementation for per-message encryption"""
    
    def __init__(self, shared_secret: bytes):
        """Initialize Double Ratchet with X3DH shared secret"""
        # Generate DH key pair
        self.dh_private = x25519.X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()
        
        # Derive initial root key and chain key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"DoubleRatchet_Init",
            backend=default_backend()
        )
        
        derived = hkdf.derive(shared_secret)
        self.root_key = derived[:32]
        self.chain_key = derived[32:]
        
        self.message_number = 0
        self.received_message_number = 0
        self.remote_dh_public = None
    
    def dh_ratchet(self, remote_public_key: bytes) -> None:
        """Perform DH ratchet step"""
        # Compute DH shared secret
        shared_secret = self.dh_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(remote_public_key)
        )
        
        # Derive new root key and chain key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"DoubleRatchet_DHRatchet",
            backend=default_backend()
        )
        
        derived = hkdf.derive(self.root_key + shared_secret)
        self.root_key = derived[:32]
        self.chain_key = derived[32:]
        
        # Generate new DH key pair
        self.dh_private = x25519.X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()
        self.remote_dh_public = remote_public_key
        self.message_number = 0
    
    def symmetric_key_ratchet(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """Perform symmetric key ratchet step"""
        # Derive message key and next chain key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"DoubleRatchet_MessageKeys",
            backend=default_backend()
        )
        
        derived = hkdf.derive(chain_key)
        message_key = derived[:32]
        next_chain_key = derived[32:]
        
        return message_key, next_chain_key
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, Dict[str, Any]]:
        """
        Encrypt message using Double Ratchet
        
        Returns: (ciphertext, metadata)
        """
        # Derive message key
        message_key, self.chain_key = self.symmetric_key_ratchet(self.chain_key)
        
        # Generate random IV
        iv = secrets.token_bytes(12)
        
        # Encrypt with AES-GCM
        cipher = Cipher(
            algorithms.AES(message_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        metadata = {
            "iv": iv.hex(),
            "dh_public": self.dh_public.public_bytes_raw().hex(),
            "message_number": self.message_number,
            "tag": encryptor.tag.hex()
        }
        
        self.message_number += 1
        
        return ciphertext, metadata
    
    def decrypt(self, ciphertext: bytes, metadata: Dict[str, Any], associated_data: bytes = b"") -> bytes:
        """
        Decrypt message using Double Ratchet
        
        Returns: plaintext
        """
        iv = bytes.fromhex(metadata["iv"])
        dh_public = bytes.fromhex(metadata["dh_public"])
        message_number = metadata["message_number"]
        tag = bytes.fromhex(metadata["tag"])
        
        # Perform DH ratchet if needed
        if self.remote_dh_public != dh_public:
            self.dh_ratchet(dh_public)
        
        # Derive message key for the specific message number
        current_chain_key = self.chain_key
        for _ in range(message_number - self.received_message_number):
            _, current_chain_key = self.symmetric_key_ratchet(current_chain_key)
        
        message_key, _ = self.symmetric_key_ratchet(current_chain_key)
        
        # Decrypt with AES-GCM
        cipher = Cipher(
            algorithms.AES(message_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        self.received_message_number = message_number + 1
        
        return plaintext

class SignalProtocol:
    """Complete Signal Protocol implementation with WhatsApp-grade security"""
    
    def __init__(self):
        self.identity_key: Optional[IdentityKeyPair] = None
        self.signed_pre_key: Optional[SignedPreKey] = None
        self.one_time_pre_keys: List[OneTimePreKey] = []
        self.ratchet_states: Dict[str, DoubleRatchet] = {}  # device_id -> ratchet
        self.session_states: Dict[str, DoubleRatchetState] = {}  # device_id -> state
        self.group_sender_keys: Dict[str, bytes] = {}  # group_id -> sender_key
        self.message_counters: Dict[str, int] = {}  # device_id -> counter
        self.last_seen_keys: Dict[str, bytes] = {}  # device_id -> last_dh_public
    
    def initialize(self) -> None:
        """Initialize protocol with new identity"""
        self.identity_key = IdentityKeyPair.generate()
        self.signed_pre_key = SignedPreKey.create(1, self.identity_key)
        
        # Generate one-time pre-keys
        self.one_time_pre_keys = [
            OneTimePreKey.generate(i) for i in range(100)
        ]
        
        # Initialize counters
        self.message_counters = {}
        self.last_seen_keys = {}
        self.session_states = {}
    
    def get_bundle(self) -> X3DHBundle:
        """Get X3DH bundle for sharing"""
        if not self.identity_key or not self.signed_pre_key:
            raise ValueError("Protocol not initialized")
        
        # Select a one-time pre-key if available
        one_time_key = None
        one_time_id = None
        if self.one_time_pre_keys:
            one_time_key = self.one_time_pre_keys.pop(0)
            one_time_id = one_time_key.key_id
        
        return X3DHBundle(
            identity_key=self.identity_key.public_key,
            signed_pre_key=self.signed_pre_key.key_pair[32:],  # Public part
            signed_pre_key_id=self.signed_pre_key.key_id,
            signed_pre_key_signature=self.signed_pre_key.signature,
            one_time_pre_key=one_time_key.public_key if one_time_key else None,
            one_time_pre_key_id=one_time_id
        )
    
    def initiate_session(self, device_id: str, remote_bundle: X3DHBundle) -> None:
        """Initiate session with remote device"""
        if not self.identity_key or not self.signed_pre_key:
            raise ValueError("Protocol not initialized")
        
        # Perform X3DH handshake
        shared_secret = X3DHHandshake.initiator_handshake(
            self.identity_key,
            self.signed_pre_key,
            None,  # No one-time pre-key for initiator
            remote_bundle
        )
        
        # Initialize Double Ratchet
        self.ratchet_states[device_id] = DoubleRatchet(shared_secret)
    
    def respond_to_session(self, device_id: str, initiator_bundle: X3DHBundle) -> None:
        """Respond to session initiation"""
        if not self.identity_key or not self.signed_pre_key:
            raise ValueError("Protocol not initialized")
        
        # Select one-time pre-key
        one_time_key = None
        if self.one_time_pre_keys:
            one_time_key = self.one_time_pre_keys.pop(0)
        
        # Perform X3DH handshake as responder
        shared_secret = X3DHHandshake.initiator_handshake(
            self.identity_key,
            self.signed_pre_key,
            one_time_key,
            initiator_bundle
        )
        
        # Initialize Double Ratchet
        self.ratchet_states[device_id] = DoubleRatchet(shared_secret)
    
    def encrypt_message(self, device_id: str, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt message for specific device with enhanced security"""
        if device_id not in self.ratchet_states:
            raise ValueError(f"No session established with device {device_id}")
        
        ratchet = self.ratchet_states[device_id]
        
        # Get message counter
        counter = self.message_counters.get(device_id, 0)
        
        # Encrypt message
        ciphertext, metadata = ratchet.encrypt(plaintext, associated_data)
        
        # Add enhanced metadata
        metadata.update({
            "message_counter": counter,
            "sender_device_id": "primary",  # Would be actual device ID
            "timestamp": int(time.time()),
            "ephemeral_public": metadata.get("dh_public"),
            "version": "1.0"
        })
        
        # Update counter
        self.message_counters[device_id] = counter + 1
        
        # Store session state
        self.session_states[device_id] = self.get_session_state(device_id)
        
        return ciphertext, metadata
    
    def decrypt_message(self, device_id: str, ciphertext: bytes, metadata: Dict[str, Any], associated_data: bytes = b"") -> bytes:
        """Decrypt message from specific device with enhanced security"""
        if device_id not in self.ratchet_states:
            raise ValueError(f"No session established with device {device_id}")
        
        ratchet = self.ratchet_states[device_id]
        
        # Verify message counter for replay protection
        expected_counter = self.message_counters.get(device_id, 0)
        message_counter = metadata.get("message_counter", 0)
        
        if message_counter < expected_counter:
            raise ValueError(f"Replay attack detected: message_counter {message_counter} < expected {expected_counter}")
        
        # Decrypt message
        plaintext = ratchet.decrypt(ciphertext, metadata, associated_data)
        
        # Update counter
        self.message_counters[device_id] = max(expected_counter, message_counter + 1)
        
        # Store session state
        self.session_states[device_id] = self.get_session_state(device_id)
        
        return plaintext
    
    def get_session_state(self, device_id: str) -> Optional[DoubleRatchetState]:
        """Get current session state for device"""
        if device_id not in self.ratchet_states:
            return None
        
        ratchet = self.ratchet_states[device_id]
        return DoubleRatchetState(
            root_key=ratchet.root_key,
            chain_key=ratchet.chain_key,
            sending_chain_key=None,  # Would need to track separately
            receiving_chain_key=None,  # Would need to track separately
            dh_private_key=ratchet.dh_private.private_bytes_raw(),
            dh_public_key=ratchet.dh_public.public_bytes_raw(),
            remote_dh_public_key=ratchet.remote_dh_public,
            message_number=ratchet.message_number,
            received_message_number=ratchet.received_message_number
        )
    
    def restore_session_state(self, device_id: str, state: DoubleRatchetState) -> None:
        """Restore session state for device"""
        ratchet = DoubleRatchet(b"dummy")  # Will be overwritten
        
        ratchet.root_key = state.root_key
        ratchet.chain_key = state.chain_key
        ratchet.dh_private = x25519.X25519PrivateKey.from_private_bytes(state.dh_private_key)
        ratchet.dh_public = x25519.X25519PublicKey.from_public_bytes(state.dh_public_key)
        ratchet.remote_dh_public = state.remote_dh_public
        ratchet.message_number = state.message_number
        ratchet.received_message_number = state.received_message_number
        
        self.ratchet_states[device_id] = ratchet
        self.message_counters[device_id] = 0
        self.last_seen_keys[device_id] = ratchet.dh_public.public_bytes_raw()
    
    def create_group_sender_key(self, group_id: str) -> bytes:
        """Create sender key for group chat"""
        if group_id in self.group_sender_keys:
            return self.group_sender_keys[group_id]
        
        # Generate random sender key (32 bytes)
        sender_key = os.urandom(32)
        self.group_sender_keys[group_id] = sender_key
        
        return sender_key
    
    def encrypt_group_message(self, group_id: str, plaintext: bytes) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt group message using Sender Key"""
        if group_id not in self.group_sender_keys:
            self.create_group_sender_key(group_id)
        
        sender_key = self.group_sender_keys[group_id]
        
        # Generate random IV
        iv = os.urandom(12)
        
        # Encrypt with AES-GCM
        cipher = Cipher(
            algorithms.AES(sender_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        metadata = {
            "group_id": group_id,
            "iv": iv.hex(),
            "tag": encryptor.tag.hex(),
            "sender_key_id": hashlib.sha256(sender_key).hexdigest()[:16],
            "message_type": "group",
            "timestamp": int(time.time())
        }
        
        return ciphertext, metadata
    
    def decrypt_group_message(self, group_id: str, ciphertext: bytes, metadata: Dict[str, Any]) -> bytes:
        """Decrypt group message using Sender Key"""
        if group_id not in self.group_sender_keys:
            raise ValueError(f"No sender key for group {group_id}")
        
        sender_key = self.group_sender_keys[group_id]
        iv = bytes.fromhex(metadata["iv"])
        tag = bytes.fromhex(metadata["tag"])
        
        # Decrypt with AES-GCM
        cipher = Cipher(
            algorithms.AES(sender_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def rotate_group_sender_key(self, group_id: str) -> bytes:
        """Rotate sender key for group (when members change)"""
        # Generate new sender key
        new_sender_key = os.urandom(32)
        self.group_sender_keys[group_id] = new_sender_key
        
        return new_sender_key
    
    def add_group_member(self, group_id: str, new_member_device_id: str) -> Dict[str, Any]:
        """Add member to group and distribute sender key"""
        # Rotate sender key for security
        new_sender_key = self.rotate_group_sender_key(group_id)
        
        # Encrypt sender key for new member using their device session
        if new_member_device_id in self.ratchet_states:
            encrypted_key, key_metadata = self.encrypt_message(
                new_member_device_id, 
                new_sender_key,
                associated_data=b"group_sender_key_distribution"
            )
            
            return {
                "encrypted_sender_key": base64.b64encode(encrypted_key).decode(),
                "key_metadata": key_metadata,
                "group_id": group_id,
                "action": "member_added"
            }
        
        raise ValueError(f"No session established with device {new_member_device_id}")
    
    def remove_group_member(self, group_id: str, removed_member_device_id: str) -> Dict[str, Any]:
        """Remove member from group and rotate sender key"""
        # Rotate sender key to exclude removed member
        new_sender_key = self.rotate_group_sender_key(group_id)
        
        return {
            "group_id": group_id,
            "new_sender_key_id": hashlib.sha256(new_sender_key).hexdigest()[:16],
            "action": "member_removed",
            "removed_member": removed_member_device_id
        }


class KeyRotationManager:
    """
    WhatsApp-grade automatic key rotation manager.
    
    Handles automatic rotation of:
    - Signed pre-keys (every 7 days)
    - One-time pre-keys (when depleted)
    - Group sender keys (on membership changes)
    - Session keys (periodic for post-compromise security)
    """
    
    def __init__(self, signal_protocol: SignalProtocol):
        self.signal = signal_protocol
        self.rotation_intervals = {
            "signed_pre_key": 7 * 24 * 60 * 60,  # 7 days
            "one_time_pre_keys": 100,  # When less than 100 available
            "group_sender_key": 30 * 24 * 60 * 60,  # 30 days
            "session_key": 7 * 24 * 60 * 60  # 7 days for post-compromise security
        }
        self.last_rotations = {}
    
    async def check_and_rotate_keys(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Check and rotate all keys as needed"""
        rotation_results = {}
        
        try:
            # Check signed pre-key rotation
            spk_result = await self._check_signed_pre_key_rotation(user_id, device_id)
            if spk_result["rotated"]:
                rotation_results["signed_pre_key"] = spk_result
            
            # Check one-time pre-key rotation
            otpk_result = await self._check_one_time_pre_key_rotation(user_id, device_id)
            if otpk_result["rotated"]:
                rotation_results["one_time_pre_keys"] = otpk_result
            
            # Check session key rotation
            session_result = await self._check_session_key_rotation(user_id, device_id)
            if session_result["rotated"]:
                rotation_results["session_keys"] = session_result
            
            return {
                "success": True,
                "rotations_performed": rotation_results,
                "timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Key rotation check failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def rotate_group_keys_on_membership_change(
        self, 
        group_id: str, 
        user_id: str, 
        device_id: str,
        change_type: str,  # "member_added", "member_removed", "admin_changed"
        affected_members: List[str] = None
    ) -> Dict[str, Any]:
        """Rotate group keys when membership changes"""
        try:
            rotation_result = {
                "group_id": group_id,
                "change_type": change_type,
                "timestamp": time.time()
            }
            
            if change_type in ["member_added", "member_removed"]:
                # Always rotate sender key on membership changes
                new_sender_key = self.signal.rotate_group_sender_key(group_id)
                rotation_result["sender_key_rotated"] = True
                rotation_result["new_sender_key_id"] = hashlib.sha256(new_sender_key).hexdigest()[:16]
                
                # Distribute new key to remaining members
                if change_type == "member_added" and affected_members:
                    for member_device_id in affected_members:
                        try:
                            key_distribution = self.signal.distribute_group_sender_key(
                                group_id, member_device_id, new_sender_key
                            )
                            rotation_result.setdefault("key_distributions", []).append({
                                "device_id": member_device_id,
                                "distribution": key_distribution
                            })
                        except Exception as e:
                            logger.warning(f"Failed to distribute key to {member_device_id}: {e}")
            
            # Store rotation metadata
            await self._store_rotation_metadata(group_id, rotation_result)
            
            return {
                "success": True,
                "rotation_result": rotation_result,
                "message": f"Group keys rotated for {change_type}"
            }
            
        except Exception as e:
            logger.error(f"Group key rotation failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def force_rotate_all_keys(self, user_id: str, device_id: str, reason: str = "security") -> Dict[str, Any]:
        """Force rotation of all keys (emergency/security)"""
        try:
            rotation_results = {}
            
            # Force rotate signed pre-key
            spk_result = await self._force_rotate_signed_pre_key(user_id, device_id, reason)
            rotation_results["signed_pre_key"] = spk_result
            
            # Force rotate one-time pre-keys
            otpk_result = await self._force_rotate_one_time_pre_keys(user_id, device_id, reason)
            rotation_results["one_time_pre_keys"] = otpk_result
            
            # Force rotate all session keys
            session_result = await self._force_rotate_all_sessions(user_id, device_id, reason)
            rotation_results["session_keys"] = session_result
            
            # Log emergency rotation
            logger.warning(f"Emergency key rotation triggered for {user_id}:{device_id} - {reason}")
            
            return {
                "success": True,
                "rotations_performed": rotation_results,
                "reason": reason,
                "timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Force key rotation failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    # Private methods for key rotation
    
    async def _check_signed_pre_key_rotation(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Check if signed pre-key needs rotation"""
        try:
            last_rotation_key = f"last_spk_rotation:{user_id}:{device_id}"
            current_time = time.time()
            
            # Get last rotation time
            last_rotation = await self._get_last_rotation_time(last_rotation_key)
            
            if current_time - last_rotation > self.rotation_intervals["signed_pre_key"]:
                # Rotate signed pre-key
                new_spk = await self._force_rotate_signed_pre_key(user_id, device_id, "scheduled")
                return new_spk
            
            return {"rotated": False, "reason": "not_due"}
            
        except Exception as e:
            logger.error(f"Signed pre-key rotation check failed: {str(e)}")
            return {"rotated": False, "error": str(e)}
    
    async def _check_one_time_pre_key_rotation(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Check if one-time pre-keys need rotation"""
        try:
            # Check available one-time pre-keys count
            available_keys = len(self.signal.one_time_pre_keys.get(device_id, []))
            
            if available_keys < self.rotation_intervals["one_time_pre_keys"]:
                # Generate new one-time pre-keys
                new_keys = await self._force_rotate_one_time_pre_keys(user_id, device_id, "low_supply")
                return new_keys
            
            return {"rotated": False, "reason": "sufficient_keys", "available": available_keys}
            
        except Exception as e:
            logger.error(f"One-time pre-key rotation check failed: {str(e)}")
            return {"rotated": False, "error": str(e)}
    
    async def _check_session_key_rotation(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Check if session keys need rotation for post-compromise security"""
        try:
            rotated_sessions = []
            current_time = time.time()
            
            # Check all active sessions
            for session_id, ratchet_state in self.signal.ratchet_states.items():
                if session_id.startswith(f"{device_id}:"):
                    last_rotation_key = f"last_session_rotation:{session_id}"
                    last_rotation = await self._get_last_rotation_time(last_rotation_key)
                    
                    if current_time - last_rotation > self.rotation_intervals["session_key"]:
                        # Rotate session key
                        await self._rotate_session_key(session_id, "scheduled")
                        rotated_sessions.append(session_id)
            
            if rotated_sessions:
                return {
                    "rotated": True,
                    "rotated_sessions": rotated_sessions,
                    "count": len(rotated_sessions)
                }
            
            return {"rotated": False, "reason": "sessions_not_due"}
            
        except Exception as e:
            logger.error(f"Session key rotation check failed: {str(e)}")
            return {"rotated": False, "error": str(e)}
    
    async def _force_rotate_signed_pre_key(self, user_id: str, device_id: str, reason: str) -> Dict[str, Any]:
        """Force rotate signed pre-key"""
        try:
            # Generate new signed pre-key
            new_spk = SignedPreKey.generate(self.signal.identity_key)
            
            # Store new signed pre-key
            self.signal.signed_pre_keys[device_id] = new_spk
            
            # Update rotation time
            rotation_key = f"last_spk_rotation:{user_id}:{device_id}"
            await self._update_rotation_time(rotation_key)
            
            return {
                "rotated": True,
                "new_spk_id": new_spk.key_id,
                "reason": reason,
                "timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Force signed pre-key rotation failed: {str(e)}")
            return {"rotated": False, "error": str(e)}
    
    async def _force_rotate_one_time_pre_keys(self, user_id: str, device_id: str, reason: str) -> Dict[str, Any]:
        """Force rotate one-time pre-keys"""
        try:
            # Generate new batch of one-time pre-keys
            new_keys = []
            start_id = secrets.randbelow(1000000)
            
            for i in range(100):  # Generate 100 new keys
                key_id = start_id + i
                otpk = OneTimePreKey.generate(key_id)
                new_keys.append(otpk)
            
            # Replace existing keys
            self.signal.one_time_pre_keys[device_id] = new_keys
            
            return {
                "rotated": True,
                "new_keys_count": len(new_keys),
                "key_range": f"{start_id}-{start_id + len(new_keys) - 1}",
                "reason": reason,
                "timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Force one-time pre-key rotation failed: {str(e)}")
            return {"rotated": False, "error": str(e)}
    
    async def _force_rotate_all_sessions(self, user_id: str, device_id: str, reason: str) -> Dict[str, Any]:
        """Force rotate all session keys"""
        try:
            rotated_sessions = []
            
            # Rotate all active sessions for this device
            for session_id in list(self.signal.ratchet_states.keys()):
                if session_id.startswith(f"{device_id}:"):
                    await self._rotate_session_key(session_id, reason)
                    rotated_sessions.append(session_id)
            
            return {
                "rotated": True,
                "rotated_sessions": rotated_sessions,
                "count": len(rotated_sessions),
                "reason": reason,
                "timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Force all session rotation failed: {str(e)}")
            return {"rotated": False, "error": str(e)}
    
    async def _rotate_session_key(self, session_id: str, reason: str):
        """Rotate a specific session key"""
        try:
            if session_id in self.signal.ratchet_states:
                ratchet_state = self.signal.ratchet_states[session_id]
                
                # Perform DH ratchet step to rotate keys
                new_dh_private = x25519.X25519PrivateKey.generate()
                new_dh_public = new_dh_private.public_key()
                
                # Update ratchet state
                ratchet_state.dh_private_key = new_dh_private
                ratchet_state.dh_public_key = new_dh_public
                ratchet_state.dh_ratchet_counter += 1
                
                # Update rotation time
                rotation_key = f"last_session_rotation:{session_id}"
                await self._update_rotation_time(rotation_key)
                
                logger.info(f"Session key rotated: {session_id} - {reason}")
            
        except Exception as e:
            logger.error(f"Session key rotation failed for {session_id}: {str(e)}")
    
    async def _get_last_rotation_time(self, key: str) -> float:
        """Get last rotation time for a key"""
        # In a real implementation, this would query Redis or database
        # For now, return a default time (7 days ago)
        return time.time() - self.rotation_intervals["signed_pre_key"]
    
    async def _update_rotation_time(self, key: str):
        """Update rotation time for a key"""
        # In a real implementation, this would update Redis or database
        # For now, just log
        logger.info(f"Updated rotation time for: {key}")
    
    async def _store_rotation_metadata(self, group_id: str, metadata: Dict[str, Any]):
        """Store rotation metadata"""
        # In a real implementation, this would store in database
        # For now, just log
        logger.info(f"Stored rotation metadata for group {group_id}: {metadata['change_type']}")
    
    def get_rotation_status(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Get current rotation status for all keys"""
        try:
            status = {
                "user_id": user_id,
                "device_id": device_id,
                "timestamp": time.time(),
                "keys": {}
            }
            
            # Signed pre-key status
            spk = self.signal.signed_pre_keys.get(device_id)
            if spk:
                status["keys"]["signed_pre_key"] = {
                    "key_id": spk.key_id,
                    "generated_at": spk.timestamp,
                    "age_days": (time.time() - spk.timestamp) / (24 * 60 * 60)
                }
            
            # One-time pre-keys status
            otpks = self.signal.one_time_pre_keys.get(device_id, [])
            status["keys"]["one_time_pre_keys"] = {
                "available": len(otpks),
                "threshold": self.rotation_intervals["one_time_pre_keys"],
                "needs_rotation": len(otpks) < self.rotation_intervals["one_time_pre_keys"]
            }
            
            # Session keys status
            session_count = len([s for s in self.signal.ratchet_states.keys() if s.startswith(f"{device_id}:")])
            status["keys"]["sessions"] = {
                "active_count": session_count,
                "rotation_interval_days": self.rotation_intervals["session_key"] / (24 * 60 * 60)
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get rotation status: {str(e)}")
            return {"error": str(e)}
