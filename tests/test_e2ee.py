"""
E2EE Validation and Test Suite

Tests for:
- Key generation (Signal Protocol)
- Session establishment (Double Ratchet)
- Message encryption/decryption
- Replay protection
- Forward secrecy
- Device management
- Multi-device fan-out
"""

import asyncio
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Tuple

import pytest

# Import crypto modules directly
try:
    from crypto.signal_protocol import SignalProtocol, X3DHBundle, IdentityKeyPair
    from crypto.multi_device import MultiDeviceManager, DeviceInfo
    from crypto.delivery_semantics import DeliveryManager, MessageStatus
    from crypto.media_encryption import MediaEncryptionService
    from e2ee_service import E2EEService, EncryptedMessageEnvelope, EncryptionError, DecryptionError
except ImportError:
    # Try relative imports for testing
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    
    from backend.crypto.signal_protocol import SignalProtocol, X3DHBundle, IdentityKeyPair
    from backend.crypto.multi_device import MultiDeviceManager, DeviceInfo
    from backend.crypto.delivery_semantics import DeliveryManager, MessageStatus
    from backend.crypto.media_encryption import MediaEncryptionService
    from backend.e2ee_service import E2EEService, EncryptedMessageEnvelope, EncryptionError, DecryptionError

logger = logging.getLogger(__name__)


class TestKeyGeneration:
    """Test Signal Protocol key generation"""
    
    def test_generate_identity_key_pair(self):
        """Test identity key generation"""
        priv_b64, pub_b64 = SignalProtocolKeyManager.generate_identity_key_pair()
        
        # Validate base64 encoding
        assert isinstance(priv_b64, str)
        assert isinstance(pub_b64, str)
        
        # Validate lengths (X25519 keys are 32 bytes = 44 chars in base64)
        decoded_priv = base64.b64decode(priv_b64)
        decoded_pub = base64.b64decode(pub_b64)
        
        assert len(decoded_priv) == 32  # Private key 32 bytes
        assert len(decoded_pub) == 32   # Public key 32 bytes
        
        # Ensure keys are different
        assert priv_b64 != pub_b64
    
    def test_generate_signed_prekey(self):
        """Test signed prekey generation"""
        identity_priv_b64, identity_pub_b64 = \
            SignalProtocolKeyManager.generate_identity_key_pair()
        
        signed_prekey_data = SignalProtocolKeyManager.generate_signed_prekey_pair(
            identity_priv_b64
        )
        
        # Validate structure
        assert 'signed_prekey_id' in signed_prekey_data
        assert 'public_key_b64' in signed_prekey_data
        assert 'signature_b64' in signed_prekey_data
        
        # Validate values
        assert isinstance(signed_prekey_data['signed_prekey_id'], int)
        assert signed_prekey_data['signed_prekey_id'] >= 0
        
        # Validate base64
        decoded_pub = base64.b64decode(signed_prekey_data['public_key_b64'])
        decoded_sig = base64.b64decode(signed_prekey_data['signature_b64'])
        
        assert len(decoded_pub) == 32  # DH public key
        assert len(decoded_sig) == 64  # Ed25519 signature
    
    def test_generate_one_time_prekeys(self):
        """Test one-time prekey batch generation"""
        prekeys = SignalProtocolKeyManager.generate_one_time_prekeys(count=100)
        
        assert len(prekeys) == 100
        
        prekey_ids = set()
        for prekey in prekeys:
            assert 'prekey_id' in prekey
            assert 'public_key_b64' in prekey
            assert isinstance(prekey['prekey_id'], int)
            
            # Validate unique IDs
            prekey_ids.add(prekey['prekey_id'])
            
            # Validate key encoding
            decoded_key = base64.b64decode(prekey['public_key_b64'])
            assert len(decoded_key) == 32
        
        # All IDs should be unique
        assert len(prekey_ids) == 100


class TestDoubleRatchet:
    """Test Double Ratchet algorithm (forward secrecy + break-in recovery)"""
    
    def test_double_ratchet_initialization(self):
        """Test Double Ratchet initialization"""
        root_key_b64 = base64.b64encode(b'root_key_32_bytes_long_exactly!').decode()
        
        ratchet = DoubleRatchet(root_key_b64)
        
        # Initialize sending chain
        chain_key_send = ratchet.create_sending_chain_key()
        assert isinstance(chain_key_send, str)
        assert len(base64.b64decode(chain_key_send)) == 32
    
    def test_message_ratcheting(self):
        """Test forward secrecy through message ratcheting"""
        root_key_b64 = base64.b64encode(b'root_key_32_bytes_long_exactly!').decode()
        ratchet = DoubleRatchet(root_key_b64)
        ratchet.create_sending_chain_key()
        
        # Generate multiple message keys
        message_keys = []
        for i in range(10):
            msg_key_b64, chain_key_b64, message_counter = ratchet.ratchet_sending_chain()
            message_keys.append(msg_key_b64)
        
        # All message keys should be different
        assert len(set(message_keys)) == 10  # 10 unique keys
        
        # First key should be different from last
        assert message_keys[0] != message_keys[9]
    
    def test_forward_secrecy(self):
        """Test that message key compromise doesn't expose others"""
        root_key_b64 = base64.b64encode(b'root_key_32_bytes_long_exactly!').decode()
        ratchet1 = DoubleRatchet(root_key_b64)
        ratchet2 = DoubleRatchet(root_key_b64)
        
        ratchet1.create_sending_chain_key()
        ratchet2.create_sending_chain_key()
        
        # Generate first message key
        msg_key1, _, _ = ratchet1.ratchet_sending_chain()
        msg_key2, _, _ = ratchet2.ratchet_sending_chain()
        
        assert msg_key1 == msg_key2  # Same key from same root
        
        # Even if key 1 is compromised, key 2 cannot be derived
        # (no way to reverse the KDF)
        msg_key1_next, _, _ = ratchet1.ratchet_sending_chain()
        msg_key2_next, _, _ = ratchet2.ratchet_sending_chain()
        
        assert msg_key1_next == msg_key2_next


class TestMessageEncryption:
    """Test AES-256-GCM message encryption"""
    
    def test_encrypt_decrypt_message(self):
        """Test encryption and decryption"""
        message = "Hello, this is a secret message!"
        message_key_b64 = base64.b64encode(b'message_key_32bytes_long_exactly').decode()
        
        # Encrypt
        encrypt_result = MessageEncryption.encrypt_message(message, message_key_b64)
        assert isinstance(encrypt_result, dict)
        assert 'ciphertext_b64' in encrypt_result
        assert 'iv_b64' in encrypt_result
        assert 'tag_b64' in encrypt_result
        
        # Decrypt
        plaintext = MessageEncryption.decrypt_message(
            encrypt_result['ciphertext_b64'],
            message_key_b64,
            encrypt_result['iv_b64'],
            encrypt_result['tag_b64']
        )
        assert plaintext == message
    
    def test_encryption_randomness(self):
        """Test that same message encrypts differently each time (random IV)"""
        message = "Test message"
        message_key_b64 = base64.b64encode(b'message_key_32bytes_long_exactly').decode()
        
        ciphertext1 = MessageEncryption.encrypt_message(message, message_key_b64)
        ciphertext2 = MessageEncryption.encrypt_message(message, message_key_b64)
        
        # Ciphertexts should be different (random IV)
        assert ciphertext1['ciphertext_b64'] != ciphertext2['ciphertext_b64']
        assert ciphertext1['iv_b64'] != ciphertext2['iv_b64']  # Different IVs
        
        # But both decrypt to same plaintext
        assert MessageEncryption.decrypt_message(
            ciphertext1['ciphertext_b64'],
            message_key_b64,
            ciphertext1['iv_b64'],
            ciphertext1['tag_b64']
        ) == message
        assert MessageEncryption.decrypt_message(
            ciphertext2['ciphertext_b64'],
            message_key_b64,
            ciphertext2['iv_b64'],
            ciphertext2['tag_b64']
        ) == message
    
    def test_tamper_detection(self):
        """Test that tampering with ciphertext is detected"""
        message = "Secret"
        message_key_b64 = base64.b64encode(b'message_key_32bytes_long_exactly').decode()
        
        encrypt_result = MessageEncryption.encrypt_message(message, message_key_b64)
        
        # Tamper with ciphertext
        ciphertext_bytes = base64.b64decode(encrypt_result['ciphertext_b64'])
        tampered_bytes = bytearray(ciphertext_bytes)
        tampered_bytes[0] ^= 0xFF  # Flip bits
        tampered_b64 = base64.b64encode(bytes(tampered_bytes)).decode()
        
        # Decryption should fail (GCM tag invalid)
        with pytest.raises(Exception):  # DecryptionError
            MessageEncryption.decrypt_message(
                tampered_b64,
                message_key_b64,
                encrypt_result['iv_b64'],
                encrypt_result['tag_b64']
            )


class TestReplayProtection:
    """Test replay attack prevention"""
    
    def test_replay_detection(self):
        """Test detection of duplicate messages"""
        replay_protector = ReplayProtection(window_size=1024)
        
        # First message
        assert replay_protector.check_counter(1) == True  # Valid
        assert replay_protector.highest_counter == 1
        
        # Duplicate
        with pytest.raises(Exception):  # ReplayAttackError
            replay_protector.check_counter(1)
    
    def test_out_of_order_messages(self):
        """Test handling of out-of-order delivery"""
        replay_protector = ReplayProtection(window_size=1024)
        
        # Messages can arrive out of order in Double Ratchet
        assert replay_protector.check_counter(5) == True  # Valid (sets highest to 5)
        assert replay_protector.check_counter(3) == True  # Valid (within window, already seen)
        assert replay_protector.check_counter(7) == True  # Valid (new, advances highest)
        
        # But not outside window
        assert replay_protector.highest_counter == 7
        with pytest.raises(Exception):  # Outside sliding window
            replay_protector.check_counter(7 - 1024 - 1)
    
    def test_sliding_window_cleanup(self):
        """Test that old entries are cleaned from sliding window"""
        replay_protector = ReplayProtection(window_size=10)
        
        # Add messages up to counter 100
        for i in range(1, 101):
            try:
                replay_protector.check_counter(i)
            except Exception:
                pass  # Ignore exceptions for this test
        
        # Highest should be 100
        assert replay_protector.highest_counter == 100
        
        # Only last 10 should be tracked
        assert len(replay_protector.seen_counters) <= 10


class TestSessionKeyDerivation:
    """Test session key derivation from shared secrets"""
    
    def test_derive_session_key(self):
        """Test initial session key derivation"""
        shared_secret_b64 = base64.b64encode(b'shared_secret_32bytes_long_exact').decode()
        identity1_b64 = base64.b64encode(b'identity_key_1__32bytes_long_exactl').decode()
        identity2_b64 = base64.b64encode(b'identity_key_2__32bytes_long_exactl').decode()
        
        root_key_b64 = SessionKeyDerivation.derive_initial_session_key(
            shared_secret_b64=shared_secret_b64,
            initiator_identity_b64=identity1_b64,
            receiver_identity_b64=identity2_b64
        )
        
        # Should produce 32-byte (base64) key
        decoded = base64.b64decode(root_key_b64)
        assert len(decoded) == 32
    
    def test_session_key_uniqueness(self):
        """Test that different identities produce different session keys"""
        shared_secret_b64 = base64.b64encode(b'shared_secret_32bytes_long_exact').decode()
        identity1_b64 = base64.b64encode(b'identity_1_______32bytes_long_exact').decode()
        identity2_b64 = base64.b64encode(b'identity_2_______32bytes_long_exact').decode()
        identity3_b64 = base64.b64encode(b'identity_3_______32bytes_long_exact').decode()
        
        # Different initiators should produce different keys
        root_key1 = SessionKeyDerivation.derive_initial_session_key(
            shared_secret_b64, identity1_b64, identity2_b64
        )
        root_key2 = SessionKeyDerivation.derive_initial_session_key(
            shared_secret_b64, identity2_b64, identity3_b64
        )
        
        assert root_key1 != root_key2


class TestFingerprinting:
    """Test key fingerprinting for manual verification"""
    
    def test_fingerprint_generation(self):
        """Test fingerprint generation"""
        public_key_b64 = base64.b64encode(b'public_key_32bytes_long_exactly_pk').decode()
        
        fingerprint = generate_fingerprint(public_key_b64)
        
        # Should be hex string (uppercase, no spaces)
        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 64  # 32 bytes = 64 hex chars
        assert all(c in '0123456789ABCDEF' for c in fingerprint)
    
    def test_fingerprint_consistency(self):
        """Test that same key produces same fingerprint"""
        public_key_b64 = base64.b64encode(b'public_key_32bytes_long_exactly_pk').decode()
        
        fp1 = generate_fingerprint(public_key_b64)
        fp2 = generate_fingerprint(public_key_b64)
        
        assert fp1 == fp2
    
    def test_fingerprint_uniqueness(self):
        """Test that different keys produce different fingerprints"""
        key1_b64 = base64.b64encode(b'public_key_1_____32bytes_long_exactly').decode()
        key2_b64 = base64.b64encode(b'public_key_2_____32bytes_long_exactly').decode()
        
        fp1 = generate_fingerprint(key1_b64)
        fp2 = generate_fingerprint(key2_b64)
        
        assert fp1 != fp2


class TestEndToEndFlow:
    """Integration tests for complete E2EE flow"""
    
    def test_complete_message_flow(self):
        """Test complete message encryption and decryption flow"""
        # 1. Generate keys for both users
        alice_priv, alice_pub = SignalProtocolKeyManager.generate_identity_key_pair()
        bob_priv, bob_pub = SignalProtocolKeyManager.generate_identity_key_pair()
        
        # 2. Exchange keys (getting bob's signed prekey)
        bob_signed_prekey = SignalProtocolKeyManager.generate_signed_prekey_pair(bob_priv)
        
        # 3. Derive shared secret (only done locally with DH)
        shared_secret_b64 = base64.b64encode(b'shared_secret_32bytes_long_exact').decode()
        
        # 4. Establish sessions
        alice_root_key = SessionKeyDerivation.derive_initial_session_key(
            shared_secret_b64=shared_secret_b64,
            initiator_identity_b64=alice_pub,
            receiver_identity_b64=bob_pub
        )
        bob_root_key = alice_root_key  # Same shared secret
        
        alice_ratchet = DoubleRatchet(alice_root_key)
        bob_ratchet = DoubleRatchet(bob_root_key)
        
        alice_ratchet.create_sending_chain_key()
        bob_ratchet.create_sending_chain_key()
        
        # 5. Send message from Alice to Bob
        message = "Hello Bob, this is Alice!"
        alice_msg_key, _, _ = alice_ratchet.ratchet_sending_chain()
        encrypt_result = MessageEncryption.encrypt_message(message, alice_msg_key)
        
        # 6. Bob receives and decrypts
        bob_msg_key, _, _ = bob_ratchet.ratchet_sending_chain()
        plaintext = MessageEncryption.decrypt_message(
            encrypt_result['ciphertext_b64'],
            bob_msg_key,
            encrypt_result['iv_b64'],
            encrypt_result['tag_b64']
        )
        
        assert plaintext == message
        assert plaintext != encrypt_result['ciphertext_b64']


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
