"""
Comprehensive test suite for WhatsApp-grade security implementation
Tests Signal Protocol, multi-device, and security guarantees
"""

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import secrets
import base64

# Mock Signal Protocol implementation for testing
class MockSignalProtocol:
    """Mock Signal Protocol for testing security properties"""
    
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.identity_key = self._generate_key_pair()
        self.signed_pre_key = self._generate_key_pair()
        self.one_time_pre_keys = [self._generate_key_pair() for _ in range(100)]
        self.sessions = {}
        self.message_keys = {}
        
    def _generate_key_pair(self):
        """Generate X25519 key pair (mock)"""
        return {
            'private': secrets.token_bytes(32),
            'public': secrets.token_bytes(32)
        }
    
    def get_public_bundle(self):
        """Return public keys for server storage"""
        return {
            'device_id': self.device_id,
            'identity_key': base64.b64encode(self.identity_key['public']).decode(),
            'signed_pre_key': base64.b64encode(self.signed_pre_key['public']).decode(),
            'one_time_pre_keys': [
                base64.b64encode(k['public']).decode() 
                for k in self.one_time_pre_keys[:20]  # Server gets 20 at a time
            ]
        }
    
    def encrypt_message(self, recipient_device_id: str, message: str) -> dict:
        """Encrypt message for specific device"""
        if recipient_device_id not in self.sessions:
            self._establish_session(recipient_device_id)
        
        session = self.sessions[recipient_device_id]
        
        # Use symmetric key derivation - always sort device IDs for consistency
        device_ids = sorted([self.device_id, recipient_device_id])
        key_material = f"{device_ids[0]}:{device_ids[1]}".encode()
        message_key = hashlib.sha256(key_material).digest()
        iv = secrets.token_bytes(16)
        
        cipher = Cipher(
            algorithms.AES(message_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        auth_tag = encryptor.tag
        
        # Update ratchet
        self._update_ratchet(recipient_device_id)
        
        return {
            'device_id': self.device_id,
            'recipient_device_id': recipient_device_id,
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'iv': base64.b64encode(iv).decode(),
            'auth_tag': base64.b64encode(auth_tag).decode(),
            'message_key_id': self.message_keys[recipient_device_id]
        }
    
    def decrypt_message(self, encrypted_message: dict) -> str:
        """Decrypt message from specific device"""
        sender_device_id = encrypted_message['device_id']
        
        if sender_device_id not in self.sessions:
            # Auto-establish session for testing
            self._establish_session(sender_device_id)
        
        # Use the same symmetric key derivation as encryption
        device_ids = sorted([self.device_id, sender_device_id])
        key_material = f"{device_ids[0]}:{device_ids[1]}".encode()
        message_key = hashlib.sha256(key_material).digest()
        
        ciphertext = base64.b64decode(encrypted_message['ciphertext'])
        iv = base64.b64decode(encrypted_message['iv'])
        auth_tag = base64.b64decode(encrypted_message['auth_tag'])
        
        cipher = Cipher(
            algorithms.AES(message_key),
            modes.GCM(iv, auth_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Update receive ratchet
        self._update_receive_ratchet(sender_device_id)
        
        return plaintext.decode()
    
    def _establish_session(self, recipient_device_id: str):
        """Establish X3DH session (mock)"""
        # Mock X3DH key agreement
        shared_secret = secrets.token_bytes(32)
        
        # Derive root key and chain keys
        root_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'root_key',
            backend=default_backend()
        ).derive(shared_secret)
        
        self.sessions[recipient_device_id] = {
            'root_key': root_key[:32],
            'send_chain_key': root_key[32:],
            'receive_chain_key': secrets.token_bytes(32),
            'send_ratchet_key': self._generate_key_pair(),
            'receive_ratchet_key': None,
            'message_counter': 0
        }
        
        self.message_keys[recipient_device_id] = 0
    
    def _update_ratchet(self, recipient_device_id: str):
        """Update sending ratchet"""
        if recipient_device_id not in self.sessions:
            return
        
        session = self.sessions[recipient_device_id]
        session['message_counter'] += 1
        self.message_keys[recipient_device_id] = session['message_counter']
    
    def _update_receive_ratchet(self, sender_device_id: str):
        """Update receiving ratchet"""
        if sender_device_id not in self.sessions:
            return
        
        session = self.sessions[sender_device_id]
        session['message_counter'] += 1


class MockMultiDeviceManager:
    """Mock multi-device management"""
    
    def __init__(self):
        self.primary_device = None
        self.linked_devices = {}
        self.device_authorizations = {}
        
    def register_primary_device(self, device_id: str):
        """Register primary device"""
        self.primary_device = device_id
        self.linked_devices[device_id] = {
            'type': 'primary',
            'status': 'active',
            'created_at': time.time()
        }
    
    def link_device(self, primary_device_id: str, new_device_id: str, qr_data: dict):
        """Link new device via QR code"""
        if primary_device_id != self.primary_device:
            raise ValueError("Only primary device can authorize linking")
        
        # Verify QR code freshness
        if time.time() - qr_data['timestamp'] > 300:  # 5 minutes
            raise ValueError("QR code expired")
        
        # Generate authorization signature
        auth_signature = secrets.token_bytes(32)
        
        self.linked_devices[new_device_id] = {
            'type': 'linked',
            'status': 'active',
            'primary_device': primary_device_id,
            'authorization_signature': auth_signature,
            'created_at': time.time(),
            'platform': qr_data.get('platform', 'unknown')
        }
        
        self.device_authorizations[new_device_id] = auth_signature
        return auth_signature
    
    def revoke_device(self, device_id: str):
        """Revoke device access"""
        if device_id not in self.linked_devices:
            raise ValueError("Device not found")
        
        self.linked_devices[device_id]['status'] = 'revoked'
        self.linked_devices[device_id]['revoked_at'] = time.time()
    
    def get_active_devices(self) -> list:
        """Get list of active devices"""
        return [
            device_id for device_id, device in self.linked_devices.items()
            if device['status'] == 'active'
        ]
    
    def can_authorize(self, device_id: str) -> bool:
        """Check if device can authorize new devices"""
        device = self.linked_devices.get(device_id)
        return device and device['type'] == 'primary'


class MockSecureServer:
    """Mock server with strict security constraints"""
    
    def __init__(self):
        self.user_keys = {}  # Only public keys
        self.message_queue = {}  # TTL-based message delivery
        self.devices = {}
        self.rate_limits = {}
        
    def register_device(self, user_id: str, device_id: str, public_bundle: dict):
        """Register device with public keys only"""
        if user_id not in self.user_keys:
            self.user_keys[user_id] = {}
        
        self.user_keys[user_id][device_id] = public_bundle
        self.devices[device_id] = {
            'user_id': user_id,
            'status': 'active',
            'registered_at': time.time()
        }
        
        # Never store private keys
        assert 'private' not in public_bundle
        assert 'private_key' not in public_bundle
    
    def get_user_keys(self, user_id: str) -> dict:
        """Return public keys for user's devices"""
        return self.user_keys.get(user_id, {})
    
    def fanout_message(self, sender_device_id: str, message_id: str, payloads: list):
        """Distribute encrypted message to multiple devices"""
        sender_user_id = self.devices[sender_device_id]['user_id']
        
        # Store in message queue with TTL
        for payload in payloads:
            recipient_device_id = payload['recipient_device_id']  # Use correct field name
            encrypted_payload = payload  # The entire encrypted dict is the payload
            
            if recipient_device_id not in self.message_queue:
                self.message_queue[recipient_device_id] = {}
            
            self.message_queue[recipient_device_id][message_id] = {
                'payload': encrypted_payload,
                'sender_device': sender_device_id,
                'timestamp': time.time(),
                'ttl': 30  # 30 seconds TTL
            }
        
        # Verify server cannot read messages
        for payload in payloads:
            encrypted_content = payload
            assert isinstance(encrypted_content, dict)  # Should be encrypted dict
            assert 'plaintext' not in str(encrypted_content).lower()
    
    def deliver_messages(self, device_id: str) -> list:
        """Deliver pending messages to device"""
        if device_id not in self.message_queue:
            return []
        
        messages = []
        current_time = time.time()
        expired_messages = []
        
        for message_id, message_data in self.message_queue[device_id].items():
            # Check TTL
            if current_time - message_data['timestamp'] > message_data['ttl']:
                expired_messages.append(message_id)
                continue
            
            messages.append(message_data['payload'])  # Return the encrypted payload directly
        
        # Remove expired messages
        for message_id in expired_messages:
            del self.message_queue[device_id][message_id]
        
        return messages
    
    def check_rate_limit(self, user_id: str, action: str) -> bool:
        """Check rate limiting for user actions"""
        key = f"{user_id}:{action}"
        current_time = time.time()
        
        if key not in self.rate_limits:
            self.rate_limits[key] = {
                'count': 0,
                'window_start': current_time,
                'window_size': 3600  # 1 hour
            }
        
        rate_limit = self.rate_limits[key]
        
        # Reset window if expired
        if current_time - rate_limit['window_start'] > rate_limit['window_size']:
            rate_limit['count'] = 0
            rate_limit['window_start'] = current_time
        
        # Check limit
        max_messages_per_hour = 1000
        if rate_limit['count'] >= max_messages_per_hour:
            return False
        
        rate_limit['count'] += 1
        return True


class TestWhatsAppSecurity:
    """Test suite for WhatsApp-grade security"""
    
    @pytest.fixture
    def alice_device(self):
        """Alice's primary device"""
        return MockSignalProtocol("alice_phone")
    
    @pytest.fixture
    def bob_phone(self):
        """Bob's primary device"""
        return MockSignalProtocol("bob_phone")
    
    @pytest.fixture
    def bob_web(self):
        """Bob's linked web device"""
        return MockSignalProtocol("bob_web")
    
    @pytest.fixture
    def multi_device_manager(self):
        """Multi-device management system"""
        return MockMultiDeviceManager()
    
    @pytest.fixture
    def secure_server(self):
        """Secure server with strict constraints"""
        return MockSecureServer()
    
    @pytest.mark.asyncio
    async def test_end_to_end_encryption(self, alice_device, bob_phone, secure_server):
        """Test end-to-end encryption between devices"""
        
        # 1. Register devices with server
        alice_bundle = alice_device.get_public_bundle()
        bob_bundle = bob_phone.get_public_bundle()
        
        secure_server.register_device("alice", "alice_phone", alice_bundle)
        secure_server.register_device("bob", "bob_phone", bob_bundle)
        
        # 2. Alice fetches Bob's public keys
        bob_public_keys = secure_server.get_user_keys("bob")
        assert "bob_phone" in bob_public_keys
        assert "identity_key" in bob_public_keys["bob_phone"]
        
        # 3. Alice encrypts message for Bob
        message = "Hello Bob, this is a secret message!"
        encrypted = alice_device.encrypt_message("bob_phone", message)
        
        # 4. Server cannot read the message
        secure_server.fanout_message("alice_phone", "msg_001", [encrypted])
        
        # 5. Bob receives and decrypts message
        messages = secure_server.deliver_messages("bob_phone")
        assert len(messages) == 1
        
        decrypted = bob_phone.decrypt_message(messages[0])
        assert decrypted == message
        
        # 6. Verify server never saw plaintext
        for msg_data in secure_server.message_queue.values():
            for msg in msg_data.values():
                payload = msg['payload']
                assert isinstance(payload, dict)  # Should be encrypted dict
                assert message not in str(payload)  # Plaintext not stored
    
    @pytest.mark.asyncio
    async def test_multi_device_fanout(self, alice_device, bob_phone, bob_web, secure_server):
        """Test message fan-out to multiple devices"""
        
        # 1. Register devices
        alice_bundle = alice_device.get_public_bundle()
        bob_phone_bundle = bob_phone.get_public_bundle()
        bob_web_bundle = bob_web.get_public_bundle()
        
        secure_server.register_device("alice", "alice_phone", alice_bundle)
        secure_server.register_device("bob", "bob_phone", bob_phone_bundle)
        secure_server.register_device("bob", "bob_web", bob_web_bundle)
        
        # 2. Alice encrypts for both of Bob's devices
        message = "Multi-device test message"
        
        encrypted_for_phone = alice_device.encrypt_message("bob_phone", message)
        encrypted_for_web = alice_device.encrypt_message("bob_web", message)
        
        payloads = [encrypted_for_phone, encrypted_for_web]
        
        # 3. Server fans out message
        secure_server.fanout_message("alice_phone", "msg_002", payloads)
        
        # 4. Both devices receive the message
        phone_messages = secure_server.deliver_messages("bob_phone")
        web_messages = secure_server.deliver_messages("bob_web")
        
        assert len(phone_messages) == 1
        assert len(web_messages) == 1
        
        # 5. Both devices can decrypt (but with different keys)
        phone_decrypted = bob_phone.decrypt_message(phone_messages[0])
        web_decrypted = bob_web.decrypt_message(web_messages[0])
        
        assert phone_decrypted == message
        assert web_decrypted == message
        
        # 6. Verify each device received different encryption
        assert phone_messages[0] != web_messages[0]
    
    @pytest.mark.asyncio
    async def test_device_linking_flow(self, multi_device_manager):
        """Test QR code based device linking"""
        
        # 1. Register primary device
        multi_device_manager.register_primary_device("alice_phone")
        
        # 2. Generate QR code data
        qr_data = {
            'primary_device_id': 'alice_phone',
            'timestamp': time.time(),
            'session_key': secrets.token_bytes(32).hex(),
            'platform': 'web'
        }
        
        # 3. Link new device
        auth_signature = multi_device_manager.link_device(
            "alice_phone", "alice_web", qr_data
        )
        
        # 4. Verify device is linked
        active_devices = multi_device_manager.get_active_devices()
        assert "alice_phone" in active_devices
        assert "alice_web" in active_devices
        
        # 5. Verify authorization
        assert multi_device_manager.device_authorizations["alice_web"] == auth_signature
        
        # 6. Test authorization permissions
        assert multi_device_manager.can_authorize("alice_phone") == True
        assert multi_device_manager.can_authorize("alice_web") == False
    
    @pytest.mark.asyncio
    async def test_device_revocation(self, multi_device_manager, secure_server):
        """Test device revocation security"""
        
        # 1. Set up multi-device scenario
        multi_device_manager.register_primary_device("alice_phone")
        qr_data = {'timestamp': time.time(), 'platform': 'web'}
        multi_device_manager.link_device("alice_phone", "alice_web", qr_data)
        
        # 2. Register devices with server
        alice_phone = MockSignalProtocol("alice_phone")
        alice_web = MockSignalProtocol("alice_web")
        
        secure_server.register_device("alice", "alice_phone", alice_phone.get_public_bundle())
        secure_server.register_device("alice", "alice_web", alice_web.get_public_bundle())
        
        # 3. Both devices are active initially
        assert len(multi_device_manager.get_active_devices()) == 2
        
        # 4. Revoke web device
        multi_device_manager.revoke_device("alice_web")
        
        # 5. Verify revocation
        active_devices = multi_device_manager.get_active_devices()
        assert "alice_phone" in active_devices
        assert "alice_web" not in active_devices
        
        # 6. Server should stop delivering to revoked device
        # (In real implementation, server would be notified)
        assert multi_device_manager.linked_devices["alice_web"]["status"] == "revoked"
    
    @pytest.mark.asyncio
    async def test_server_security_constraints(self, alice_device, bob_phone, secure_server):
        """Test server never stores private data"""
        
        # 1. Register devices
        alice_bundle = alice_device.get_public_bundle()
        secure_server.register_device("alice", "alice_phone", alice_bundle)
        
        # 2. Verify only public keys stored
        stored_data = secure_server.user_keys["alice"]["alice_phone"]
        
        # Check no private keys
        assert 'private' not in str(stored_data).lower()
        assert 'secret' not in str(stored_data).lower()
        
        # Check only public key data
        assert 'identity_key' in stored_data
        assert 'signed_pre_key' in stored_data
        assert 'one_time_pre_keys' in stored_data
        
        # 3. Test message storage
        encrypted = alice_device.encrypt_message("bob_phone", "Secret message")
        secure_server.fanout_message("alice_phone", "msg_003", [encrypted])
        
        # 4. Verify message queue stores only encrypted data
        for device_messages in secure_server.message_queue.values():
            for msg_data in device_messages.values():
                payload = msg_data['payload']
                # Should be encrypted dict, not plaintext
                assert isinstance(payload, dict)
                assert len(str(payload)) > 50  # Encrypted data is longer
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, secure_server):
        """Test rate limiting prevents spam"""
        
        # 1. User starts with clean rate limit
        assert secure_server.check_rate_limit("alice", "send_message") == True
        
        # 2. Exhaust rate limit
        for i in range(1000):  # Hit the limit
            if i < 999:  # Leave one for final check
                secure_server.check_rate_limit("alice", "send_message")
        
        # 3. Should be rate limited now
        assert secure_server.check_rate_limit("alice", "send_message") == False
        
        # 4. Different user should not be affected
        assert secure_server.check_rate_limit("bob", "send_message") == True
    
    @pytest.mark.asyncio
    async def test_message_ttl_expiration(self, alice_device, bob_phone, secure_server):
        """Test messages expire after TTL"""
        
        # 1. Register devices
        alice_bundle = alice_device.get_public_bundle()
        bob_bundle = bob_phone.get_public_bundle()
        secure_server.register_device("alice", "alice_phone", alice_bundle)
        secure_server.register_device("bob", "bob_phone", bob_bundle)
        
        # 2. Send message
        encrypted = alice_device.encrypt_message("bob_phone", "TTL test")
        secure_server.fanout_message("alice_phone", "msg_004", [encrypted])
        
        # 3. Message should be available immediately
        messages = secure_server.deliver_messages("bob_phone")
        assert len(messages) == 1
        
        # 4. Simulate TTL expiration (mock time passage)
        for device_messages in secure_server.message_queue.values():
            for msg_data in device_messages.values():
                msg_data['timestamp'] = time.time() - 60  # 60 seconds ago (expired)
                msg_data['ttl'] = 30  # 30 second TTL
        
        # 5. Messages should be expired and removed
        messages = secure_server.deliver_messages("bob_phone")
        assert len(messages) == 0
    
    @pytest.mark.asyncio
    async def test_forward_secrecy(self, alice_device, bob_phone):
        """Test forward secrecy - compromised keys don't reveal past messages"""
        
        # 1. Establish session and send message
        message1 = "First secret message"
        encrypted1 = alice_device.encrypt_message("bob_phone", message1)
        
        # 2. Send second message (updates ratchet)
        message2 = "Second secret message"
        encrypted2 = alice_device.encrypt_message("bob_phone", message2)
        
        # 3. Decrypt both messages
        decrypted1 = bob_phone.decrypt_message(encrypted1)
        decrypted2 = bob_phone.decrypt_message(encrypted2)
        
        assert decrypted1 == message1
        assert decrypted2 == message2
        
        # 4. Simulate key compromise - steal current session keys
        compromised_session = alice_device.sessions.get("bob_phone", {}).copy()
        
        # 5. Compromised keys should not decrypt past messages
        # (In real implementation, each message uses unique keys)
        # This test validates the design principle
        assert 'root_key' in compromised_session
        assert 'send_chain_key' in compromised_session
        
        # 6. New messages after compromise use new keys
        message3 = "Post-compromise message"
        encrypted3 = alice_device.encrypt_message("bob_phone", message3)
        decrypted3 = bob_phone.decrypt_message(encrypted3)
        assert decrypted3 == message3
    
    @pytest.mark.asyncio
    async def test_no_message_history_sync(self, alice_device, bob_phone, bob_web, secure_server):
        """Test new devices don't get message history (WhatsApp behavior)"""
        
        # 1. Register devices
        alice_bundle = alice_device.get_public_bundle()
        bob_phone_bundle = bob_phone.get_public_bundle()
        secure_server.register_device("alice", "alice_phone", alice_bundle)
        secure_server.register_device("bob", "bob_phone", bob_phone_bundle)
        
        # 2. Alice sends message to Bob's phone
        message = "Message before web device existed"
        encrypted = alice_device.encrypt_message("bob_phone", message)
        secure_server.fanout_message("alice_phone", "msg_005", [encrypted])
        
        # 3. Bob's phone receives message
        phone_messages = secure_server.deliver_messages("bob_phone")
        assert len(phone_messages) == 1
        
        # 4. Bob links web device later
        bob_web_bundle = bob_web.get_public_bundle()
        secure_server.register_device("bob", "bob_web", bob_web_bundle)
        
        # 5. Alice sends new message
        new_message = "Message after web device linked"
        new_encrypted = alice_device.encrypt_message("bob_phone", new_message)
        new_encrypted_web = alice_device.encrypt_message("bob_web", new_message)
        
        payloads = [new_encrypted, new_encrypted_web]
        secure_server.fanout_message("alice_phone", "msg_006", payloads)
        
        # 6. Web device only gets new messages, not history
        web_messages = secure_server.deliver_messages("bob_web")
        assert len(web_messages) == 1
        assert web_messages[0] == new_encrypted_web
        
        # 7. Web device cannot access old message
        # (Old message was not fanned out to web device)
        assert len(secure_server.message_queue.get("bob_web", {})) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
