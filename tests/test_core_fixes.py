"""
Simplified test suite for HTTP error fixes
Tests core security and validation functionality without full app import
"""

import pytest
from datetime import datetime, timedelta, timezone
from backend.models import UserCreate, UserLogin
from backend.auth.utils import decode_token, create_access_token
from backend.validators import validate_command_injection, validate_path_injection
from backend.rate_limiter import RateLimiter
from backend.config import settings
# Import from standalone file to avoid caching issues
import sys
import os

# Add the current directory to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from debug_hash import hash_password, verify_password

class TestSecurityFeatures:
    """Test security improvements"""
    
    def test_password_hashing(self):
        """Test secure password hashing"""
        password = "test_password_123"
        hashed = hash_password(password)
        
        # Should contain salt and hash
        assert '$' in hashed
        assert len(hashed) == 97  # 32 chars salt + $ + 64 chars hash
        
        # Should verify correctly
        assert verify_password(password, hashed) == True
        assert verify_password("wrong_password", hashed) == False
    
    def test_password_hashing_edge_cases(self):
        """Test password hashing edge cases"""
        # Empty password
        with pytest.raises(ValueError):
            hash_password("")
        
        # None password
        with pytest.raises(ValueError):
            hash_password(None)
        
        # Non-string password
        with pytest.raises(ValueError):
            hash_password(123)
    
    def test_token_creation_and_validation(self):
        """Test JWT token creation and validation"""
        user_id = "507f1f77bcf86cd799439011"  # Valid ObjectId format
        
        # Create token
        token = create_access_token(data={"sub": user_id})
        assert token is not None
        assert isinstance(token, str)
        
        # Decode token
        token_data = decode_token(token)
        assert token_data.user_id == user_id
        assert token_data.token_type == "access"
    
    def test_token_validation_errors(self):
        """Test JWT token validation errors"""
        # Invalid token
        with pytest.raises(Exception):
            decode_token("invalid_token")
        
        # Expired token
        from datetime import datetime, timedelta, timezone
        expired_token = create_access_token(
            data={"sub": "507f1f77bcf86cd799439011"},
            expires_delta=timedelta(seconds=-1)  # Expired
        )
        with pytest.raises(Exception):
            decode_token(expired_token)

class TestValidationFeatures:
    """Test validation functionality"""
    
    def test_model_validation_email(self):
        """Test Pydantic email validation"""
        # Valid emails
        valid_emails = [
            "test@example.com",
            "user.name@domain.com",
            "user_tag@domain.com",
            "user123@domain.com",
            "test-domain@site.com"
        ]
        
        for email in valid_emails:
            user = UserCreate(name="Test", email=email, password="Password123")
            assert user.email == email
        
        # Invalid emails
        invalid_emails = [
            "ab",  # Too short
            "invalid#email",  # Contains invalid character
            "user name@domain.com",  # Contains space
            ""  # Empty string
        ]
        
        for email in invalid_emails:
            with pytest.raises(ValueError):
                UserCreate(name="Test", email=email, password="Password123")
    
    def test_model_validation_password(self):
        """Test Pydantic password validation"""
        # Valid passwords
        valid_passwords = [
            "Password123",
            "P@ssw0rd!",
            "Mypassword1",
            "Password1"
        ]
        
        for password in valid_passwords:
            user = UserCreate(name="Test", email="testuser@example.com", password=password)
            assert user.password == password
        
        # Empty password
        with pytest.raises(ValueError):
            UserCreate(name="Test", email="testuser@example.com", password="")
    
    def test_model_validation_name(self):
        """Test Pydantic name validation"""
        # Valid names
        valid_names = [
            "John Doe",
            "Alice",
            "Bob Smith",
            "Émilie"
        ]
        
        for name in valid_names:
            user = UserCreate(name=name, email="testuser@example.com", password="Password123")
            assert user.name == name.strip()
        
        # Empty name
        with pytest.raises(ValueError):
            UserCreate(name="", email="testuser@example.com", password="Password123")
        
        # Name with HTML tags (should be sanitized)
        user = UserCreate(name="<script>alert('xss')</script>", email="testuser@example.com", password="Password123")
        assert '<script>' not in user.name
    
    def test_command_injection_validation(self):
        """Test command injection prevention"""
        # Safe inputs
        safe_inputs = [
            "normal text",
            "Hello world",
            "File name.txt",
            "user@example.com",
            "SELECT * FROM users",  # SQL keywords are allowed in normal text
            "DROP table name",      # SQL keywords are allowed in normal text
            "rm -rf file",         # Command name without shell metacharacters (safe in text context)
            "cat filename",         # Command name without shell metacharacters (safe in text context)
        ]
        
        for input_str in safe_inputs:
            assert validate_command_injection(input_str) == True
        
        # Dangerous inputs that contain shell metacharacters
        dangerous_inputs = [
            "rm -rf /; cat /etc/passwd",  # Command separator
            "ls | grep secret",             # Pipe operator
            "command & background_process",   # Background execution
            "cat file > /dev/null",         # Redirection
            "cat < /etc/passwd",           # Input redirection
            "`malicious command`",          # Backtick execution
            "$(malicious command)",          # Command substitution
            "command1 && command2",         # Command chaining
            "command1 || command2",         # OR command execution
            "cat >> file",                  # Append redirection
            "system('shutdown')",           # Function call
            "<script>alert('xss')</script>", # XSS
            "eval(malicious_code)",         # Code execution
            "exec('rm -rf /')",           # Code execution
            "os.system('format c:')",       # System call
            "subprocess.run('rm -rf /')",   # Subprocess
            "shell=true"                    # Shell parameter
        ]
        
        for input_str in dangerous_inputs:
            assert validate_command_injection(input_str) == False
    
    def test_path_injection_validation(self):
        """Test path injection prevention"""
        # Safe paths
        safe_paths = [
            "file.txt",
            "documents/file.pdf",
            "uploads/image.jpg"
        ]
        
        for path in safe_paths:
            assert validate_path_injection(path) == True
        
        # Dangerous paths
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\cmd.exe",
            "/root/.ssh/id_rsa",
            "~/.ssh/config",
            "\x00nullbyte.txt"
        ]
        
        for path in dangerous_paths:
            assert validate_path_injection(path) == False

class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limiter_normal_operation(self):
        """Test rate limiter allows normal requests"""
        limiter = RateLimiter(max_requests=5, window_seconds=300)
        
        # Should allow requests under limit
        for i in range(3):
            assert limiter.is_allowed("test_user") == True
    
    def test_rate_limiter_exceeds_limit(self):
        """Test rate limiter blocks when limit exceeded"""
        limiter = RateLimiter(max_requests=2, window_seconds=300)
        
        # Should allow first 2 requests
        assert limiter.is_allowed("test_user") == True
        assert limiter.is_allowed("test_user") == True
        
        # Should block 3rd request
        assert limiter.is_allowed("test_user") == False
    
    def test_rate_limiter_window_reset(self):
        """Test rate limiter window resets over time"""
        import time
        limiter = RateLimiter(max_requests=2, window_seconds=1)  # 1 second window
        
        # Fill up the limit
        assert limiter.is_allowed("test_user") == True
        assert limiter.is_allowed("test_user") == True
        assert limiter.is_allowed("test_user") == False
        
        # Wait for window to reset
        time.sleep(1.1)
        
        # Should allow requests again
        assert limiter.is_allowed("test_user") == True
    
    def test_rate_limiter_different_identifiers(self):
        """Test rate limiter works independently for different identifiers"""
        limiter = RateLimiter(max_requests=1, window_seconds=300)
        
        # Should allow one request for each user
        assert limiter.is_allowed("user1") == True
        assert limiter.is_allowed("user2") == True
        
        # Should block second request for same user
        assert limiter.is_allowed("user1") == False
        assert limiter.is_allowed("user2") == False
    
    def test_rate_limiter_error_handling(self):
        """Test rate limiter allows requests on error"""
        limiter = RateLimiter(max_requests=5, window_seconds=300)
        
        # Mock an error scenario - should allow request instead of blocking
        original_requests = limiter.requests
        limiter.requests = None  # Force error
        
        # Should allow request on error
        assert limiter.is_allowed("test_user") == True
        
        # Restore
        limiter.requests = original_requests
    
    def test_rate_limiter_retry_after(self):
        """Test retry after calculation"""
        limiter = RateLimiter(max_requests=2, window_seconds=300)
        
        # Fill up the limit
        limiter.is_allowed("test_user")
        limiter.is_allowed("test_user")
        limiter.is_allowed("test_user")  # Blocked
        
        # Should return retry after time
        retry_after = limiter.get_retry_after("test_user")
        assert retry_after > 0
        assert retry_after <= 300

class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_email_validation_edge_cases(self):
        """Test email validation edge cases"""
        # Very long email (should be rejected)
        with pytest.raises(ValueError):
            UserCreate(
                name="Test",
                email="a" * 250 + "@example.com",  # Over 254 char limit
                password="password123"
            )
        
        # Email with dots at start/end (should be rejected by model validation)
        with pytest.raises(ValueError):
            UserCreate(
                name="Test",
                email=".test@example.com",
                password="password123"
            )
    
    def test_password_verification_edge_cases(self):
        """Test password verification edge cases"""
        # Invalid hash formats
        assert verify_password("password", "") == False
        assert verify_password("password", "invalid") == False
        assert verify_password("password", "not_a_hash") == False
        
        # Legacy hash format (64 hex chars)
        import hashlib
        legacy_hash = hashlib.sha256("password".encode()).hexdigest()
        assert verify_password("password", legacy_hash) == True
        assert verify_password("wrong", legacy_hash) == False
    
    def test_input_validation_edge_cases(self):
        """Test input validation edge cases"""
        # Empty inputs
        assert validate_command_injection("") == True
        assert validate_command_injection(None) == True
        assert validate_path_injection("") == False
        assert validate_path_injection(None) == False
        
        # Very long inputs
        long_input = "a" * 10000
        assert validate_command_injection(long_input) == True
        assert validate_path_injection(long_input) == False  # Too long

if __name__ == "__main__":
    # Run all tests
    pytest.main([__file__, "-v", "--tb=short"])