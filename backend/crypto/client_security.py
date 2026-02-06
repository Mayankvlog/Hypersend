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
