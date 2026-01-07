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
    
    # Enhanced rate limiting with progressive penalties
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_ATTEMPT_WINDOW = 300  # 5 minutes
    PASSWORD_RESET_ATTEMPTS = 3
    PASSWORD_RESET_WINDOW = 3600  # 1 hour
    
    # Progressive lockout durations (in seconds)
    PROGRESSIVE_LOCKOUTS = {
        1: 300,   # 5 minutes after 1st failed attempt
        2: 600,   # 10 minutes after 2nd failed attempt
        3: 900,   # 15 minutes after 3rd failed attempt
        4: 1200,  # 20 minutes after 4th failed attempt
        5: 1800,  # 30 minutes after 5th failed attempt (maximum duration)
    }
    
    # IP-based rate limiting
    MAX_LOGIN_ATTEMPTS_PER_IP = 20
    IP_LOCKOUT_DURATION = 900  # 15 minutes for IP-based lockout
    
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
    
    MAX_FILE_SIZE = 40 * 1024 * 1024 * 1024  # 40GB
    BLOCKED_FILE_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.vbscript', '.wsf', '.reg', '.js', '.jar',
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
        """Sanitize user input to prevent XSS and injection with enhanced security"""
        if not text:
            return ""
        
        # CRITICAL SECURITY: Remove all HTML tags and scripts
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r'<[^>]*>', '', text)
        
        # Remove potentially dangerous characters and control sequences
        text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]', '', text)
        
        # Remove JavaScript and data URIs
        text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
        text = re.sub(r'data:', '', text, flags=re.IGNORECASE)
        text = re.sub(r'vbscript:', '', text, flags=re.IGNORECASE)
        
        # Remove SQL injection patterns
        text = re.sub(r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)", '', text, flags=re.IGNORECASE)
        text = re.sub(r"[;'\"]", '', text)
        
        # Normalize whitespace and prevent horizontal tabs
        text = re.sub(r'\s+', ' ', text)
        
        # Limit length to prevent DoS attacks
        if len(text) > max_length:
            text = text[:max_length]
        
        return text.strip()
    
    @staticmethod
    def validate_email_format(email: str) -> bool:
        """Enhanced email format validation to prevent injection"""
        if not email or not isinstance(email, str):
            return False
        
        email = email.strip()
        
        # Basic length check
        if len(email) > 254:  # RFC 5321 limit
            return False
            
        # Enhanced regex pattern that prevents injection
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        # Additional security checks
        if '..' in email:  # Prevent path traversal
            return False
        if email.startswith('.') or email.endswith('.'):  # Prevent leading/trailing dots
            return False
        if email.count('@') != 1:  # Ensure exactly one @
            return False
            
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_file_path(file_path: str) -> bool:
        """Enhanced file path validation to prevent directory traversal and injection attacks"""
        if not file_path or not isinstance(file_path, str):
            return False
            
        # Prevent directory traversal attacks with comprehensive patterns
        dangerous_patterns = [
            '..', '../', '..\\', '%2e%2e', '%2e%2e%2f', '%2e%2e%5c',
            '....', '....../', '....\\\\', '~/', '~\\', '/etc/', '/var/',
            'c:\\', 'd:\\', 'e:\\', '/root/', '/home/', '/usr/', '/bin/',
            # Additional patterns for security
            '....//', '//', '\\\\.\\', '....\\\\',  # Double slash/backslash
            '%c0%af', '%c1%9c', '%c1%pc',  # Windows bypass
            '%252e', '%255c', '%252f',  # URL encoded variations
            'file://', 'ftp://', 'http://', 'https://',  # Protocol injection
            'javascript:', 'vbscript:', 'data:text/html',  # Script injection
            '<script', '</script>', '<iframe', '</iframe>',  # HTML injection
            'rm -rf', 'del /', 'format c:',  # Command injection
        ]
        
        normalized_path = file_path.lower()
        for pattern in dangerous_patterns:
            if pattern in normalized_path:
                return False
                
        # Enhanced checks for null bytes and control characters
        if '\x00' in file_path or any(ord(c) < 32 for c in file_path):
            return False
        
        # Check for extremely long paths (potential DoS)
        if len(file_path) > 4096:  # PATH_MAX on most systems
            return False
            
        # Check for excessive consecutive slashes (path normalization bypass)
        if '//' in file_path or '\\\\' in file_path:
            return False
            
        return True
    
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
        """Get security headers for HTTP responses with enhanced protection"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            # HSTS removed - will be added by middleware only for HTTPS
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'strict-dynamic' 'nonce-<nonce>'; style-src 'self' 'nonce-<nonce>'; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin"
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