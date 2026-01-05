"""
Security Configuration and Utilities for Hypersend
Provides security best practices and validation functions
"""

import os
import secrets
import hashlib
import hmac
from typing import Optional, Dict, Any
import re


class SecurityConfig:
    """Security configuration and validation"""
    
    # Password requirements (balanced security and usability)
    MIN_PASSWORD_LENGTH = 6
    MAX_PASSWORD_LENGTH = 128
    REQUIRE_UPPERCASE = False
    REQUIRE_LOWERCASE = False
    REQUIRE_DIGIT = False
    REQUIRE_SPECIAL = False
    
    # Rate limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_ATTEMPT_WINDOW = 300  # 5 minutes
    PASSWORD_RESET_ATTEMPTS = 3
    PASSWORD_RESET_WINDOW = 3600  # 1 hour
    
    # Token security
    TOKEN_LENGTH = 32
    RESET_TOKEN_LENGTH = 64
    
    # File upload security
    ALLOWED_MIME_TYPES = {
        # Images
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        # Documents
        'application/pdf', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        # Archives
        'application/zip', 'application/x-rar-compressed',
        # Text
        'text/plain', 'text/csv',
        # Other
        'application/json'
    }
    
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    BLOCKED_FILE_EXTENSIONS = {
        '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
        '.php', '.asp', '.jsp', '.sh', '.ps1', '.py', '.rb', '.pl', '.lnk', '.url',
        '.msi', '.dll', '.app', '.deb', '.rpm', '.dmg', '.pkg'  # Block all dangerous executables
    }
    
    @staticmethod
    def generate_secure_token(length: int = None) -> str:
        """Generate a cryptographically secure token"""
        if length is None:
            length = SecurityConfig.TOKEN_LENGTH
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_reset_token() -> str:
        """Generate a password reset token"""
        return secrets.token_urlsafe(SecurityConfig.RESET_TOKEN_LENGTH)
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> tuple[str, str]:
        """Hash password with salt using PBKDF2"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 with SHA-256
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        
        return password_hash.hex(), salt
    
    @staticmethod
    def verify_password(password: str, stored_hash: str, salt: str) -> bool:
        """Verify password against stored hash"""
        calculated_hash, _ = SecurityConfig.hash_password(password, salt)
        return hmac.compare_digest(calculated_hash, stored_hash)
    
    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """Validate password strength and return feedback"""
        issues = []
        score = 0
        
        # Length check
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            issues.append(f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters")
        elif len(password) >= SecurityConfig.MIN_PASSWORD_LENGTH:
            score += 1
        
        if len(password) >= 12:
            score += 1
        
        # Character variety checks
        if SecurityConfig.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            issues.append("Password must contain lowercase letters")
        elif re.search(r'[a-z]', password):
            score += 1
            
        if SecurityConfig.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            issues.append("Password must contain uppercase letters")
        elif re.search(r'[A-Z]', password):
            score += 1
            
        if SecurityConfig.REQUIRE_DIGIT and not re.search(r'\d', password):
            issues.append("Password must contain digits")
        elif re.search(r'\d', password):
            score += 1
            
        if SecurityConfig.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain special characters")
        elif re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        
        # Common password patterns
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            issues.append("Avoid repeated characters")
            score -= 1
            
        if re.search(r'123|abc|qwe|password|admin|user', password.lower()):
            issues.append("Avoid common patterns")
            score -= 1
        
        strength = "Weak"
        if score >= 5:
            strength = "Strong"
        elif score >= 3:
            strength = "Medium"
        
        return {
            "valid": len(issues) == 0,
            "strength": strength,
            "score": max(0, min(5, score)),
            "issues": issues
        }
    
    @staticmethod
    def sanitize_input(text: str, max_length: int = 10000) -> str:
        """Sanitize user input to prevent XSS and injection"""
        if not text:
            return ""
        
        # Remove HTML tags
        text = re.sub(r'<[^>]*>', '', text)
        
        # Remove potentially dangerous characters
        text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length]
        
        return text.strip()
    
    @staticmethod
    def validate_file_upload(filename: str, mime_type: str, file_size: int) -> Dict[str, Any]:
        """Validate file upload for security"""
        issues = []
        
        # Check file extension
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext in SecurityConfig.BLOCKED_FILE_EXTENSIONS:
            issues.append(f"File type {file_ext} is not allowed")
        
        # Check MIME type
        if mime_type not in SecurityConfig.ALLOWED_MIME_TYPES:
            issues.append(f"MIME type {mime_type} is not allowed")
        
        # Check file size
        if file_size > SecurityConfig.MAX_FILE_SIZE:
            issues.append(f"File size exceeds maximum allowed size")
        
        # Check filename for suspicious patterns
        if re.search(r'[<>:"/\\|?*]', filename):
            issues.append("Filename contains invalid characters")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues
        }
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get security headers for HTTP responses"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            # HSTS removed - will be added by middleware only for HTTPS
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }


def generate_csrf_token() -> str:
    """Generate CSRF token"""
    return SecurityConfig.generate_secure_token(32)


def validate_csrf_token(token: str, expected_token: str) -> bool:
    """Validate CSRF token"""
    return hmac.compare_digest(token, expected_token)


def rate_limit_key(identifier: str, action: str) -> str:
    """Generate rate limit key"""
    return f"rate_limit:{identifier}:{action}"


class SecurityLogger:
    """Security event logging"""
    
    @staticmethod
    def log_security_event(event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security events"""
        import time
        timestamp = time.time()  # Get current time
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        
        # In production, this should go to a secure logging system
        print(f"[SECURITY-{severity}] {event_type}: {details}")
        
        return log_entry
    
    @staticmethod
    def log_failed_login(email: str, ip_address: str, reason: str):
        """Log failed login attempt"""
        SecurityLogger.log_security_event("FAILED_LOGIN", {
            "email": email,
            "ip_address": ip_address,
            "reason": reason
        }, "WARNING")
    
    @staticmethod
    def log_suspicious_activity(activity: str, details: Dict[str, Any]):
        """Log suspicious activity"""
        SecurityLogger.log_security_event("SUSPICIOUS_ACTIVITY", {
            "activity": activity,
            "details": details
        }, "HIGH")
    
    @staticmethod
    def log_file_upload(filename: str, user_id: str, file_size: int):
        """Log file upload"""
        SecurityLogger.log_security_event("FILE_UPLOAD", {
            "filename": filename,
            "user_id": user_id,
            "file_size": file_size
        }, "INFO")