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
    
    # File upload security - Comprehensive format support with 40GB limit
    ALLOWED_MIME_TYPES = {
        # Text & Document Formats
        'text/plain', 'text/csv', 'text/tab-separated-values', 'text/markdown',
        'application/pdf', 'application/postscript',
        
        # Office Documents (Microsoft)
        'application/msword',  # .doc
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # .docx
        'application/vnd.ms-excel',  # .xls
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',  # .xlsx
        'application/vnd.ms-powerpoint',  # .ppt
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',  # .pptx
        
        # Office Documents (OpenDocument)
        'application/vnd.oasis.opendocument.text',  # .odt
        'application/vnd.oasis.opendocument.spreadsheet',  # .ods
        'application/vnd.oasis.opendocument.presentation',  # .odp
        'application/vnd.oasis.opendocument.graphics',  # .odg
        
        # Rich Text Format
        'application/rtf', 'text/rtf',
        
        # Image Formats
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/tiff',
        'image/svg+xml', 'image/x-icon', 'image/vnd.microsoft.icon', 'image/heic',
        
        # Video Formats
        'video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo', 'video/x-matroska',
        'video/x-flv', 'video/mpeg', 'video/3gpp', 'video/x-ms-wmv',
        'video/mp2t', 'video/ogg', 'video/dv', 'video/x-ms-wm', 'video/x-ms-asf',
        
        # Audio Formats
        'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/aac', 'audio/flac',
        'audio/mp4', 'audio/m4a', 'audio/x-wav', 'audio/webm', 'audio/opus',
        'audio/x-ms-wma', 'audio/x-matroska', 'audio/amr-nb', 'audio/amr-wb',
        'audio/midi', 'audio/x-midi', 'audio/aiff', 'audio/x-aiff', 'audio/x-wav',
        
        # Archive & Compressed Formats
        'application/zip', 'application/x-zip-compressed',
        'application/x-rar-compressed', 'application/x-7z-compressed',
        'application/x-tar', 'application/gzip', 'application/x-bzip2', 'application/x-xz',
        'application/x-iso9660-image', 'application/x-cd-image',  # ISO support
        
        # Data & ML Formats
        'application/json', 'application/xml', 'text/xml', 'application/sql',
        'application/x-parquet', 'application/x-hdf', 'application/hdf5',
        'application/octet-stream', 'application/x-sqlite3', 'application/x-sqlite',
        'text/yaml', 'application/x-yaml', 'application/x-pickle', 'application/x-numpy',
        
        # Code Files (informational - web executables blocked by extension)
        'text/x-java', 'text/x-csharp', 'text/x-c++',
        'text/x-golang', 'text/x-rust',
        'text/x-r', 'text/x-lua', 'text/x-swift', 'text/x-kotlin', 'text/x-scala',
        'text/x-kotlin', 'text/x-groovy', 'text/x-typescript',
    }
    
    MAX_FILE_SIZE = 40 * 1024 * 1024 * 1024  # 40GB
    
    # Allowed file extensions - comprehensive format support
    ALLOWED_FILE_EXTENSIONS = {
        # Text & Document Formats
        '.txt', '.md', '.csv', '.tsv',
        '.pdf', '.ps',
        
        # Office Documents (Microsoft)
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        
        # Office Documents (OpenDocument/LibreOffice)
        '.odt', '.ods', '.odp', '.odg',
        
        # Rich Text Format
        '.rtf',
        
        # Image Formats
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.tif',
        '.svg', '.ico', '.heic',
        
        # Video Formats
        '.mp4', '.mkv', '.avi', '.mov', '.webm', '.flv', '.mpeg', '.mpg', '.3gp', '.wmv',
        
        # Audio Formats
        '.mp3', '.wav', '.ogg', '.aac', '.m4a', '.flac', '.amr', '.opus', '.wma',
        
        # Archive & Compressed Formats
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso',
        
        # Data & ML Formats
        '.json', '.xml', '.sql', '.db', '.sqlite', '.sqlite3', '.parquet',
        '.h5', '.hdf5', '.pickle', '.pkl', '.npy', '.npz',
        
        # Code Files (source code only - web executables and server executables blocked for security)
        '.java', '.c', '.cpp', '.cs', '.go', '.rs',  # Programming languages
        '.lua', '.r', '.m', '.swift',  # Scripting languages (non-executable)
        '.kt', '.scala', '.groovy', '.ts', '.tsx', '.jsx', '.vue',  # Modern languages
        '.yaml', '.yml', '.json', '.xml',  # Data formats
    }
    
    # Executables and dangerous files - BLOCKED regardless of other rules
    # NOTE: This blocks dangerous executables, web-executable content, and server scripts
    BLOCKED_FILE_EXTENSIONS = {
        # Executables (Windows)
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.msi',
        
        # Executables (Linux/Mac) - package installers only
        '.app', '.deb', '.rpm', '.dmg', '.pkg', '.apk', '.aab',
        
        # Scripts that execute code (blocked for security)
        '.vbs', '.vbscript', '.wsf', '.ps1', '.psc1', '.msh', '.msh1', '.msh2',
        '.mshxml', '.msh2xml', '.scr', '.sh', '.bash', '.zsh', '.csh', '.ksh',
        
        # Server-side scripting (blocked for security)
        '.py', '.rb', '.pl', '.php', '.asp', '.aspx', '.jsp', '.jspx', '.cgi', '.fcgi',
        
        # Java/Python/Ruby/Perl compiled/bytecode (not source code)
        '.jar', '.class', '.pyc', '.pyo', '.pyd', '.so', '.a', '.lib', '.dll', '.dylib',
        
        # Libraries and system files
        '.dll', '.so', '.dylib', '.a', '.lib', '.o', '.obj', '.sys', '.ocx', '.cpl',
        
        # Web-executable content (blocked for security)
        '.js', '.html', '.htm', '.css',  # Can execute in browsers
        
        # Config files that could be dangerous
        '.reg', '.inf', '.ini', '.cfg', '.conf', '.config', '.plist',
        
        # Shortcuts and links
        '.lnk', '.url', '.webloc', '.desktop',
        
        # Virtual machine and disk images (blocking only dangerous formats)
        '.vhd', '.vmdk', '.ova', '.ovf', '.qcow2', '.img',
        
        # Duplicate entries removed for clarity
        '.btm',
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