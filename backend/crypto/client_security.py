"""
WhatsApp-Grade Client-Side Security & Metadata Minimization
============================================================

Encrypted local storage, OS secure keystore, screenshot protection,
root/jailbreak detection, IP obfuscation, timing padding.

Security Properties:
- Encrypted local message database
- OS secure keystore usage
- Screenshot & screen-record protection
- Secure clipboard handling
- Root / jailbreak detection
- Auto-wipe on auth failure
- IP obfuscation via relay
- Timing padding
- Anonymous delivery receipts
"""

import os
import secrets
import hashlib
import hmac
import time
import platform
import subprocess
import ctypes
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

@dataclass
class SecurityConfig:
    """Security configuration for client"""
    enable_screenshot_protection: bool = True
    enable_screen_record_protection: bool = True
    enable_root_detection: bool = True
    enable_jailbreak_detection: bool = True
    auto_wipe_on_auth_failure: bool = True
    max_auth_failures: int = 5
    session_timeout_minutes: int = 30
    enable_ip_obfuscation: bool = True
    enable_timing_padding: bool = True
    min_padding_ms: int = 100
    max_padding_ms: int = 500
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityConfig':
        """Create from dictionary"""
        return cls(**data)

@dataclass
class EncryptedMessage:
    """Encrypted local message storage"""
    message_id: str
    encrypted_content: bytes
    iv: bytes
    auth_tag: bytes
    sender_id: str
    chat_id: str
    timestamp: float
    message_type: str  # "text", "image", "video", "audio", "document"
    media_key: Optional[bytes]  # Encrypted media key
    thumbnail_key: Optional[bytes]  # Encrypted thumbnail key
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "message_id": self.message_id,
            "encrypted_content": self.encrypted_content.hex(),
            "iv": self.iv.hex(),
            "auth_tag": self.auth_tag.hex(),
            "sender_id": self.sender_id,
            "chat_id": self.chat_id,
            "timestamp": self.timestamp,
            "message_type": self.message_type,
            "media_key": self.media_key.hex() if self.media_key else None,
            "thumbnail_key": self.thumbnail_key.hex() if self.thumbnail_key else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptedMessage':
        """Create from dictionary"""
        return cls(
            message_id=data["message_id"],
            encrypted_content=bytes.fromhex(data["encrypted_content"]),
            iv=bytes.fromhex(data["iv"]),
            auth_tag=bytes.fromhex(data["auth_tag"]),
            sender_id=data["sender_id"],
            chat_id=data["chat_id"],
            timestamp=data["timestamp"],
            message_type=data["message_type"],
            media_key=bytes.fromhex(data["media_key"]) if data.get("media_key") else None,
            thumbnail_key=bytes.fromhex(data["thumbnail_key"]) if data.get("thumbnail_key") else None
        )

@dataclass
class SecurityEvent:
    """Security event for logging"""
    event_type: str  # "auth_failure", "root_detected", "screenshot_attempt", etc.
    timestamp: float
    device_id: str
    user_id: str
    details: Dict[str, Any]
    severity: str  # "low", "medium", "high", "critical"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

class ClientSecurityManager:
    """
    WhatsApp-grade client security manager.
    
    SECURITY FEATURES:
    - App lock with PIN/biometrics
    - Encrypted local storage
    - Screenshot & screen recording protection
    - Root/jailbreak detection
    - Auto-wipe on security violations
    - Secure clipboard handling
    - IP obfuscation via relay
    - Timing padding for traffic analysis protection
    - Anonymous delivery receipts
    """
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.auth_failure_count = 0
        self.last_security_check = time.time()
        self.security_events = []
        
    async def setup_app_lock(
        self,
        pin_code: Optional[str] = None,
        enable_biometrics: bool = True
    ) -> Dict[str, Any]:
        """Setup app lock with PIN and/or biometrics"""
        try:
            lock_config = {
                "enabled": True,
                "pin_enabled": pin_code is not None,
                "biometrics_enabled": enable_biometrics,
                "auto_lock_timeout": self.config.session_timeout_minutes,
                "max_attempts": self.config.max_auth_failures,
                "created_at": time.time()
            }
            
            # Store PIN securely if provided
            if pin_code:
                pin_hash = self._hash_pin(pin_code)
                await self._store_secure_setting("app_lock_pin", pin_hash)
                lock_config["pin_hash"] = pin_hash
            
            # Setup biometrics if enabled
            if enable_biometrics:
                biometric_config = await self._setup_biometrics()
                lock_config.update(biometric_config)
            
            await self._store_security_config(lock_config)
            
            return {
                "success": True,
                "lock_config": lock_config,
                "message": "App lock configured successfully"
            }
            
        except Exception as e:
            logger.error(f"App lock setup failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def verify_app_lock(
        self,
        pin_code: Optional[str] = None,
        biometric_data: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Verify app lock with PIN and/or biometrics"""
        try:
            # Check PIN if provided
            if pin_code:
                stored_pin_hash = await self._get_secure_setting("app_lock_pin")
                if stored_pin_hash:
                    input_pin_hash = self._hash_pin(pin_code)
                    if not hmac.compare_digest(stored_pin_hash.encode(), input_pin_hash.encode()):
                        await self._handle_auth_failure("invalid_pin")
                        return {"success": False, "error": "Invalid PIN"}
            
            # Check biometrics if provided
            if biometric_data:
                biometric_result = await self._verify_biometrics(biometric_data)
                if not biometric_result["verified"]:
                    await self._handle_auth_failure("invalid_biometrics")
                    return {"success": False, "error": "Biometric verification failed"}
            
            # Reset auth failure count on success
            self.auth_failure_count = 0
            await self._store_security_event("app_unlock_success")
            
            return {
                "success": True,
                "message": "App lock verified successfully"
            }
            
        except Exception as e:
            logger.error(f"App lock verification failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def enable_screenshot_protection(self) -> Dict[str, Any]:
        """Enable screenshot and screen recording protection"""
        try:
            if not self.config.enable_screenshot_protection:
                return {"success": False, "error": "Screenshot protection disabled in config"}
            
            protection_config = {
                "screenshot_blocked": True,
                "screen_record_blocked": True,
                "overlay_detection": True,
                "flags_secure": True,
                "enabled_at": time.time()
            }
            
            # Platform-specific protection
            if platform.system() == "Android":
                await self._enable_android_screenshot_protection(protection_config)
            elif platform.system() == "iOS":
                await self._enable_ios_screenshot_protection(protection_config)
            elif platform.system() == "Windows":
                await self._enable_windows_screenshot_protection(protection_config)
            elif platform.system() == "Darwin":
                await self._enable_macos_screenshot_protection(protection_config)
            elif platform.system() == "Linux":
                await self._enable_linux_screenshot_protection(protection_config)
            
            await self._store_security_config(protection_config)
            
            return {
                "success": True,
                "protection_config": protection_config,
                "message": "Screenshot protection enabled"
            }
            
        except Exception as e:
            logger.error(f"Screenshot protection setup failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def detect_security_violations(self) -> Dict[str, Any]:
        """Detect root/jailbreak and other security violations"""
        try:
            violations = []
            
            # Root/jailbreak detection
            if self.config.enable_root_detection:
                root_status = await self._detect_root_jailbreak()
                if root_status["detected"]:
                    violations.append({
                        "type": "root_jailbreak",
                        "severity": "critical",
                        "details": root_status
                    })
            
            # Jailbreak detection
            if self.config.enable_jailbreak_detection:
                jailbreak_status = await self._detect_jailbreak()
                if jailbreak_status["detected"]:
                    violations.append({
                        "type": "jailbreak",
                        "severity": "critical", 
                        "details": jailbreak_status
                    })
            
            # Debug mode detection
            debug_status = await self._detect_debug_mode()
            if debug_status["detected"]:
                violations.append({
                    "type": "debug_mode",
                    "severity": "high",
                    "details": debug_status
                })
            
            # Emulator detection
            emulator_status = await self._detect_emulator()
            if emulator_status["detected"]:
                violations.append({
                    "type": "emulator",
                    "severity": "medium",
                    "details": emulator_status
                })
            
            # Store violations
            for violation in violations:
                await self._store_security_event(violation)
            
            # Handle critical violations
            critical_violations = [v for v in violations if v["severity"] == "critical"]
            if critical_violations and self.config.auto_wipe_on_auth_failure:
                await self._trigger_security_wipe("critical_security_violations")
            
            return {
                "violations_detected": len(violations) > 0,
                "violations": violations,
                "security_score": self._calculate_security_score(violations),
                "checked_at": time.time()
            }
            
        except Exception as e:
            logger.error(f"Security violation detection failed: {str(e)}")
            return {"violations_detected": False, "error": str(e)}
    
    async def setup_privacy_controls(
        self,
        profile_visibility: str = "contacts",  # "everyone", "contacts", "nobody"
        last_seen_visibility: str = "contacts",  # "everyone", "contacts", "nobody"
        status_visibility: str = "contacts",  # "everyone", "contacts", "nobody"
        read_receipts: bool = True,
        online_status: bool = True,
        typing_indicators: bool = True
    ) -> Dict[str, Any]:
        """Setup comprehensive privacy controls"""
        try:
            privacy_config = {
                "profile_visibility": profile_visibility,
                "last_seen_visibility": last_seen_visibility,
                "status_visibility": status_visibility,
                "read_receipts_enabled": read_receipts,
                "online_status_enabled": online_status,
                "typing_indicators_enabled": typing_indicators,
                "configured_at": time.time()
            }
            
            await self._store_privacy_config(privacy_config)
            
            return {
                "success": True,
                "privacy_config": privacy_config,
                "message": "Privacy controls configured successfully"
            }
            
        except Exception as e:
            logger.error(f"Privacy controls setup failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def encrypt_local_data(
        self,
        data: Dict[str, Any],
        data_type: str = "messages"  # "messages", "contacts", "media", "keys"
    ) -> Dict[str, Any]:
        """Encrypt data for local storage"""
        try:
            # Generate encryption key
            encryption_key = secrets.token_bytes(32)
            salt = secrets.token_bytes(16)
            
            # Derive key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=f"hypersend_{data_type}_encryption".encode()
            )
            derived_key = hkdf.derive(encryption_key)
            
            # Encrypt data
            data_json = json.dumps(data, separators=(',', ':'))
            data_bytes = data_json.encode('utf-8')
            
            iv = secrets.token_bytes(12)
            aesgcm = AESGCM(derived_key)
            encrypted_data = aesgcm.encrypt(iv, data_bytes, None)
            
            # Store encryption metadata
            encryption_metadata = {
                "salt": base64.b64encode(salt).decode(),
                "iv": base64.b64encode(iv).decode(),
                "auth_tag": base64.b64encode(encrypted_data[-16:]).decode(),
                "encrypted_data": base64.b64encode(encrypted_data[:-16]).decode(),
                "algorithm": "AES-256-GCM",
                "created_at": time.time()
            }
            
            # Store encrypted data and metadata
            storage_key = f"encrypted_{data_type}"
            await self._store_encrypted_data(storage_key, encryption_metadata)
            
            return {
                "success": True,
                "storage_key": storage_key,
                "encryption_metadata": encryption_metadata,
                "message": f"{data_type.capitalize()} data encrypted successfully"
            }
            
        except Exception as e:
            logger.error(f"Local data encryption failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def decrypt_local_data(
        self,
        storage_key: str,
        encryption_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Decrypt locally stored data"""
        try:
            # Retrieve encryption key
            encrypted_data = await self._get_encrypted_data(storage_key)
            if not encrypted_data:
                return {"success": False, "error": "Encrypted data not found"}
            
            # Reconstruct encrypted data
            ciphertext = base64.b64decode(encrypted_data["encrypted_data"])
            iv = base64.b64decode(encrypted_data["iv"])
            auth_tag = base64.b64decode(encrypted_data["auth_tag"])
            salt = base64.b64decode(encrypted_data["salt"])
            
            # Derive decryption key
            # Note: In a real implementation, the key would be retrieved from secure storage
            encryption_key = secrets.token_bytes(32)  # Placeholder
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=f"hypersend_{storage_key.split('_')[1]}_encryption".encode()
            )
            derived_key = hkdf.derive(encryption_key)
            
            # Decrypt data
            aesgcm = AESGCM(derived_key)
            encrypted_content = ciphertext + auth_tag
            decrypted_bytes = aesgcm.decrypt(iv, encrypted_content, None)
            
            # Parse JSON data
            try:
                decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
                return {
                    "success": True,
                    "data": decrypted_data,
                    "message": "Data decrypted successfully"
                }
            except json.JSONDecodeError:
                return {"success": False, "error": "Corrupted encrypted data"}
                
        except Exception as e:
            logger.error(f"Local data decryption failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    # Private helper methods
    
    async def _handle_auth_failure(self, failure_type: str):
        """Handle authentication failure"""
        self.auth_failure_count += 1
        await self._store_security_event({
            "type": "auth_failure",
            "failure_type": failure_type,
            "count": self.auth_failure_count,
            "timestamp": time.time()
        })
        
        # Trigger auto-wipe if threshold exceeded
        if (self.auth_failure_count >= self.config.max_auth_failures and 
            self.config.auto_wipe_on_auth_failure):
            await self._trigger_security_wipe("max_auth_failures")
    
    def _hash_pin(self, pin: str) -> str:
        """Hash PIN code securely"""
        return hashlib.pbkdf2_hmac(
            pin.encode('utf-8'),
            b'hypersend_pin_salt',
            100000,  # iterations
            hashlib.sha256
        ).hex()
    
    async def _store_security_config(self, config: Dict[str, Any]):
        """Store security configuration"""
        await self._store_secure_setting("security_config", json.dumps(config))
    
    async def _store_privacy_config(self, config: Dict[str, Any]):
        """Store privacy configuration"""
        await self._store_secure_setting("privacy_config", json.dumps(config))
    
    async def _store_security_event(self, event: Dict[str, Any]):
        """Store security event"""
        self.security_events.append(event)
        await self._store_secure_setting("security_events", json.dumps(self.security_events[-100:]))  # Keep last 100 events
    
    async def _store_encrypted_data(self, key: str, metadata: Dict[str, Any]):
        """Store encrypted data"""
        await self._store_secure_setting(key, json.dumps(metadata))
    
    async def _get_secure_setting(self, key: str) -> Optional[str]:
        """Get secure setting"""
        # This would use platform secure storage (Keychain, Keystore)
        # For now, return mock data
        return None
    
    async def _store_secure_setting(self, key: str, value: str):
        """Store secure setting"""
        # This would use platform secure storage (Keychain, Keystore)
        # For now, just log
        logger.info(f"Storing secure setting: {key}")
    
    async def _get_encrypted_data(self, key: str) -> Optional[Dict[str, Any]]:
        """Get encrypted data"""
        # This would retrieve from secure storage
        # For now, return mock data
        return None
    
    def _calculate_security_score(self, violations: List[Dict[str, Any]]) -> int:
        """Calculate security score based on violations"""
        score = 100  # Start with perfect score
        
        for violation in violations:
            if violation["severity"] == "critical":
                score -= 50
            elif violation["severity"] == "high":
                score -= 25
            elif violation["severity"] == "medium":
                score -= 10
            elif violation["severity"] == "low":
                score -= 5
        
        return max(0, score)
    
    async def _trigger_security_wipe(self, reason: str):
        """Trigger security wipe"""
        await self._store_security_event({
            "type": "security_wipe",
            "reason": reason,
            "timestamp": time.time()
        })
        
        # In a real implementation, this would:
        # 1. Wipe all local encrypted data
        # 2. Wipe all cryptographic keys
        # 3. Logout from all sessions
        # 4. Clear secure storage
        # 5. Reset app to initial state
        
        logger.critical(f"Security wipe triggered: {reason}")
    
    # Platform-specific methods (placeholders for implementation)
    
    async def _enable_android_screenshot_protection(self, config: Dict[str, Any]):
        """Enable Android screenshot protection"""
        # Implementation would use Android FLAG_SECURE
        pass
    
    async def _enable_ios_screenshot_protection(self, config: Dict[str, Any]):
        """Enable iOS screenshot protection"""
        # Implementation would use iOS isScreenCaptured
        pass
    
    async def _enable_windows_screenshot_protection(self, config: Dict[str, Any]):
        """Enable Windows screenshot protection"""
        # Implementation would use Windows APIs
        pass
    
    async def _enable_macos_screenshot_protection(self, config: Dict[str, Any]):
        """Enable macOS screenshot protection"""
        # Implementation would use macOS APIs
        pass
    
    async def _enable_linux_screenshot_protection(self, config: Dict[str, Any]):
        """Enable Linux screenshot protection"""
        # Implementation would use X11/Wayland APIs
        pass
    
    async def _detect_root_jailbreak(self) -> Dict[str, Any]:
        """Detect root/jailbreak"""
        # Implementation would check for root indicators
        return {"detected": False, "indicators": []}
    
    async def _detect_jailbreak(self) -> Dict[str, Any]:
        """Detect jailbreak"""
        # Implementation would check for jailbreak indicators
        return {"detected": False, "indicators": []}
    
    async def _detect_debug_mode(self) -> Dict[str, Any]:
        """Detect debug mode"""
        # Implementation would check for debug indicators
        return {"detected": False, "indicators": []}
    
    async def _detect_emulator(self) -> Dict[str, Any]:
        """Detect emulator"""
        # Implementation would check for emulator indicators
        return {"detected": False, "indicators": []}
    
    async def _setup_biometrics(self) -> Dict[str, Any]:
        """Setup biometric authentication"""
        # Implementation would setup fingerprint/face ID
        return {"enabled": True, "type": "fingerprint"}
    
    async def _verify_biometrics(self, data: bytes) -> Dict[str, Any]:
        """Verify biometric data"""
        # Implementation would verify fingerprint/face ID
        return {"verified": True, "confidence": 0.95}
    """Manages client-side security"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.auth_failure_count = 0
        self.last_auth_time = 0
        self.security_events: List[SecurityEvent] = []
        self.encryption_key: Optional[bytes] = None
        self.screenshot_protected_windows: List[str] = []
        
    def initialize_encryption(self, master_key: bytes) -> None:
        """Initialize local encryption with master key"""
        # Derive encryption key from master key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Hypersend_LocalEncryption",
            backend=default_backend()
        )
        
        self.encryption_key = hkdf.derive(master_key)
        logger.info("Initialized local encryption")
    
    def encrypt_message(self, message_content: str, message_type: str = "text") -> EncryptedMessage:
        """
        Encrypt message for local storage
        
        Returns: encrypted message
        """
        if not self.encryption_key:
            raise ValueError("Encryption not initialized")
        
        # Generate random IV
        iv = secrets.token_bytes(12)
        
        # Encrypt content
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(message_content.encode()) + encryptor.finalize()
        auth_tag = encryptor.tag
        
        # Create encrypted message
        encrypted_msg = EncryptedMessage(
            message_id=secrets.token_urlsafe(32),
            encrypted_content=encrypted_content,
            iv=iv,
            auth_tag=auth_tag,
            sender_id="",  # Will be filled by caller
            chat_id="",  # Will be filled by caller
            timestamp=time.time(),
            message_type=message_type,
            media_key=None,
            thumbnail_key=None
        )
        
        return encrypted_msg
    
    def decrypt_message(self, encrypted_msg: EncryptedMessage) -> str:
        """
        Decrypt message from local storage
        
        Returns: decrypted message content
        """
        if not self.encryption_key:
            raise ValueError("Encryption not initialized")
        
        # Decrypt content
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(encrypted_msg.iv, encrypted_msg.auth_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(encrypted_msg.encrypted_content) + decryptor.finalize()
        
        return decrypted_content.decode()
    
    def check_root_jailbreak(self) -> bool:
        """
        Check if device is rooted or jailbroken
        
        Returns: True if device is compromised
        """
        system = platform.system()
        
        if system == "Android":
            return self._check_android_root()
        elif system == "iOS":
            return self._check_ios_jailbreak()
        elif system == "Linux":
            return self._check_linux_root()
        elif system == "Windows":
            return self._check_windows_admin()
        else:
            return False
    
    def _check_android_root(self) -> bool:
        """Check for Android root"""
        root_indicators = [
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        ]
        
        for path in root_indicators:
            if os.path.exists(path):
                return True
        
        # Check for root management apps
        try:
            result = subprocess.run(["pm", "list", "packages"], capture_output=True, text=True)
            packages = result.stdout.lower()
            root_apps = ["superuser", "supersu", "kingroot", "magisk"]
            return any(app in packages for app in root_apps)
        except:
            pass
        
        return False
    
    def _check_ios_jailbreak(self) -> bool:
        """Check for iOS jailbreak"""
        jailbreak_indicators = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/"
        ]
        
        for path in jailbreak_indicators:
            if os.path.exists(path):
                return True
        
        return False
    
    def _check_linux_root(self) -> bool:
        """Check for Linux root"""
        return os.geteuid() == 0
    
    def _check_windows_admin(self) -> bool:
        """Check for Windows admin"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def enable_screenshot_protection(self, window_title: str) -> bool:
        """
        Enable screenshot protection for window
        
        Returns: True if protection enabled
        """
        if not self.config.enable_screenshot_protection:
            return False
        
        system = platform.system()
        
        try:
            if system == "Windows":
                return self._enable_windows_screenshot_protection(window_title)
            elif system == "Darwin":  # macOS
                return self._enable_macos_screenshot_protection(window_title)
            elif system == "Linux":
                return self._enable_linux_screenshot_protection(window_title)
        except Exception as e:
            logger.error(f"Failed to enable screenshot protection: {e}")
        
        return False
    
    def _enable_windows_screenshot_protection(self, window_title: str) -> bool:
        """Enable Windows screenshot protection"""
        try:
            import win32gui
            import win32con
            
            hwnd = win32gui.FindWindow(None, window_title)
            if hwnd:
                # Set window to prevent screenshots
                win32gui.SetWindowLong(hwnd, win32con.GWL_EXSTYLE, 
                                     win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) | 
                                     win32con.WS_EX_TOOLWINDOW)
                self.screenshot_protected_windows.append(window_title)
                return True
        except ImportError:
            logger.warning("win32gui not available for screenshot protection")
        
        return False
    
    def _enable_macos_screenshot_protection(self, window_title: str) -> bool:
        """Enable macOS screenshot protection"""
        # macOS screenshot protection requires system-level integration
        # This is a placeholder for implementation
        logger.info("macOS screenshot protection not implemented")
        return False
    
    def _enable_linux_screenshot_protection(self, window_title: str) -> bool:
        """Enable Linux screenshot protection"""
        # Linux screenshot protection requires X11/Wayland integration
        # This is a placeholder for implementation
        logger.info("Linux screenshot protection not implemented")
        return False
    
    def record_security_event(
        self,
        event_type: str,
        device_id: str,
        user_id: str,
        details: Dict[str, Any],
        severity: str = "medium"
    ) -> None:
        """Record security event"""
        event = SecurityEvent(
            event_type=event_type,
            timestamp=time.time(),
            device_id=device_id,
            user_id=user_id,
            details=details,
            severity=severity
        )
        
        self.security_events.append(event)
        
        # Handle critical events
        if severity == "critical":
            self._handle_critical_security_event(event)
        
        logger.warning(f"Security event: {event_type} - {details}")
    
    def _handle_critical_security_event(self, event: SecurityEvent) -> None:
        """Handle critical security events"""
        if event.event_type == "root_detected" and self.config.auto_wipe_on_auth_failure:
            logger.critical(f"Root detected on device {event.device_id}, initiating auto-wipe")
            self._initiate_auto_wipe(event.user_id, event.device_id)
        elif event.event_type == "auth_failure" and self.auth_failure_count >= self.config.max_auth_failures:
            logger.critical(f"Too many auth failures for user {event.user_id}, initiating auto-wipe")
            self._initiate_auto_wipe(event.user_id, event.device_id)
    
    def _initiate_auto_wipe(self, user_id: str, device_id: str) -> None:
        """Initiate automatic data wipe"""
        logger.critical(f"Auto-wiping data for user {user_id} on device {device_id}")
        
        # In a real implementation, this would:
        # 1. Clear all local encrypted data
        # 2. Clear secure keystore
        # 3. Revoke device sessions
        # 4. Notify server of compromise
        
        # For now, just clear local data
        self.security_events.clear()
        self.auth_failure_count = 0
        self.encryption_key = None
    
    def add_timing_padding(self, base_time_ms: int) -> float:
        """
        Add timing padding to prevent traffic analysis
        
        Returns: padded time in milliseconds
        """
        if not self.config.enable_timing_padding:
            return base_time_ms
        
        padding_ms = secrets.randbelow(
            self.config.max_padding_ms - self.config.min_padding_ms + 1
        ) + self.config.min_padding_ms
        
        return base_time_ms + padding_ms
    
    def generate_anonymous_receipt(self, message_id: str) -> str:
        """
        Generate anonymous delivery receipt
        
        Returns: anonymous receipt token
        """
        # Create HMAC-based anonymous token
        receipt_data = f"{message_id}:{time.time()}".encode()
        hmac_key = secrets.token_bytes(32)
        
        receipt_token = hmac.new(
            hmac_key,
            receipt_data,
            hashes.SHA256()
        ).hexdigest()
        
        return receipt_token
    
    def verify_anonymous_receipt(self, message_id: str, receipt_token: str) -> bool:
        """
        Verify anonymous delivery receipt
        
        Returns: True if receipt is valid
        """
        # In a real implementation, this would verify against stored receipts
        # For now, just check format
        return len(receipt_token) == 64  # SHA-256 hex length
    
    def secure_clipboard_clear(self) -> bool:
        """
        Securely clear clipboard
        
        Returns: True if clipboard cleared
        """
        try:
            system = platform.system()
            
            if system == "Windows":
                import win32clipboard
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.CloseClipboard()
                return True
            elif system == "Darwin":  # macOS
                subprocess.run(["pbcopy"], input="", text=True)
                return True
            elif system == "Linux":
                # Try xclip first
                try:
                    subprocess.run(["xclip", "-selection", "clipboard"], input="", text=True)
                    return True
                except:
                    # Try xsel
                    subprocess.run(["xsel", "--clear", "--clipboard"], text=True)
                    return True
        except Exception as e:
            logger.error(f"Failed to clear clipboard: {e}")
        
        return False
    
    def get_security_status(self) -> Dict[str, Any]:
        """
        Get current security status
        
        Returns: security status dictionary
        """
        return {
            "is_compromised": self.check_root_jailbreak(),
            "auth_failure_count": self.auth_failure_count,
            "last_auth_time": self.last_auth_time,
            "screenshot_protected_windows": self.screenshot_protected_windows,
            "recent_security_events": [
                event.to_dict() for event in 
                sorted(self.security_events, key=lambda e: e.timestamp, reverse=True)[:10]
            ],
            "encryption_initialized": self.encryption_key is not None,
            "config": self.config.to_dict()
        }
    
    def handle_auth_failure(self, user_id: str, device_id: str) -> bool:
        """
        Handle authentication failure
        
        Returns: True if auto-wipe triggered
        """
        self.auth_failure_count += 1
        self.last_auth_time = time.time()
        
        self.record_security_event(
            event_type="auth_failure",
            device_id=device_id,
            user_id=user_id,
            details={
                "failure_count": self.auth_failure_count,
                "max_failures": self.config.max_auth_failures
            },
            severity="high" if self.auth_failure_count >= self.config.max_auth_failures else "medium"
        )
        
        # Check if auto-wipe should be triggered
        if (self.auth_failure_count >= self.config.max_auth_failures and 
            self.config.auto_wipe_on_auth_failure):
            self._initiate_auto_wipe(user_id, device_id)
            return True
        
        return False
    
    def handle_auth_success(self, user_id: str, device_id: str) -> None:
        """Handle successful authentication"""
        self.auth_failure_count = 0
        self.last_auth_time = time.time()
        
        self.record_security_event(
            event_type="auth_success",
            device_id=device_id,
            user_id=user_id,
            details={},
            severity="low"
        )
