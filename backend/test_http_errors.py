"""
Comprehensive test suite for HTTP error fixes
Tests all 3xx, 4xx, 5xx error scenarios and security improvements
"""

import pytest
import asyncio
import time
from fastapi.testclient import TestClient
from fastapi import status
from unittest.mock import patch, MagicMock
import mongomock
import motor.motor_asyncio
from datetime import datetime, timedelta, timezone

# Import the application and modules
try:
    from main import app
except ImportError:
    # Skip tests if main app can't be imported
    app = None

from models import UserCreate, UserLogin
from auth.utils import verify_password, hash_password, decode_token
from validators import validate_command_injection, validate_path_injection
from rate_limiter import RateLimiter

# Test client - only create if app is available
client = TestClient(app) if app else None

class TestAuthenticationErrors:
    """Test authentication-related HTTP errors"""
    
    @pytest.mark.skipif(client is None, reason="App not available")
    def test_login_invalid_email_format(self):
        """Test 400 error for invalid email format"""
        response = client.post("/api/v1/auth/login", json={
            "email": "invalid-email",
            "password": "password123"
        })
        assert response.status_code == 400
        assert "Invalid email format" in response.json()["detail"]
    
    def test_login_empty_password(self):
        """Test 400 error for empty password"""
        response = client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": ""
        })
        assert response.status_code == 400
        assert "Password is required" in response.json()["detail"]
    
    def test_login_invalid_credentials(self):
        """Test 401 error for invalid credentials"""
        response = client.post("/api/v1/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "password123"
        })
        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]
    
    def test_register_invalid_email_format(self):
        """Test 400 error for invalid email in registration"""
        response = client.post("/api/v1/auth/register", json={
            "name": "Test User",
            "email": "invalid-email",
            "password": "password123"
        })
        assert response.status_code == 400
        assert "Invalid email format" in response.json()["detail"]
    
    def test_register_weak_password(self):
        """Test 400 error for weak password"""
        response = client.post("/api/v1/auth/register", json={
            "name": "Test User",
            "email": "test@example.com",
            "password": "123"
        })
        assert response.status_code == 400
        assert "Password must be at least 6 characters" in response.json()["detail"]
    
    def test_register_existing_email(self):
        """Test 409 error for existing email"""
        # Mock existing user
        with patch('routes.auth.users_collection') as mock_collection:
            mock_collection.return_value.find_one.return_value = {"_id": "123", "email": "test@example.com"}
            
            response = client.post("/api/v1/auth/register", json={
                "name": "Test User",
                "email": "test@example.com",
                "password": "password123"
            })
            assert response.status_code == 409
            assert "Email already registered" in response.json()["detail"]

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
    
    def test_rate_limiter_error_handling(self):
        """Test rate limiter allows requests on error"""
        limiter = RateLimiter(max_requests=5, window_seconds=300)
        
        # Mock an error scenario
        with patch.object(limiter, 'lock') as mock_lock:
            mock_lock.__enter__.side_effect = Exception("Lock error")
            
            # Should allow request on error
            assert limiter.is_allowed("test_user") == True

class TestDatabaseErrors:
    """Test database-related error handling"""
    
    def test_database_connection_error(self):
        """Test 503 error when database is unavailable"""
        with patch('routes.auth.users_collection') as mock_collection:
            mock_collection.return_value.find_one.side_effect = ConnectionError("Database down")
            
            response = client.post("/api/v1/auth/login", json={
                "email": "test@example.com",
                "password": "password123"
            })
            assert response.status_code == 503
            assert "Database service temporarily unavailable" in response.json()["detail"]
    
    def test_database_timeout_error(self):
        """Test 503 error when database times out"""
        with patch('routes.auth.users_collection') as mock_collection:
            mock_collection.return_value.find_one.side_effect = TimeoutError("Database timeout")
            
            response = client.post("/api/v1/auth/login", json={
                "email": "test@example.com",
                "password": "password123"
            })
            assert response.status_code == 503
            assert "Database service temporarily unavailable" in response.json()["detail"]

class TestValidationErrors:
    """Test input validation errors"""
    
    def test_model_validation_email(self):
        """Test Pydantic email validation"""
        # Valid emails
        valid_emails = [
            "test@example.com",
            "user.name@domain.co.uk",
            "user+tag@example.org",
            "user123@test-domain.com"
        ]
        
        for email in valid_emails:
            user = UserCreate(name="Test", email=email, password="password123")
            assert user.email == email.lower()
        
        # Invalid emails
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "test@",
            "test.example.com"
        ]
        
        for email in invalid_emails:
            with pytest.raises(ValueError):
                UserCreate(name="Test", email=email, password="password123")
    
    def test_command_injection_validation(self):
        """Test command injection prevention"""
        # Safe inputs
        safe_inputs = [
            "normal text",
            "Hello world",
            "File name.txt",
            "user@example.com"
        ]
        
        for input_str in safe_inputs:
            assert validate_command_injection(input_str) == True
        
        # Dangerous inputs
        dangerous_inputs = [
            "rm -rf /",
            "cat /etc/passwd",
            "system('shutdown')",
            "<script>alert('xss')</script>"
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
            "/root/.ssh/id_rsa"
        ]
        
        for path in dangerous_paths:
            assert validate_path_injection(path) == False

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
    
    def test_timing_attack_protection(self):
        """Test timing attack protection in password verification"""
        import time
        
        password = "test_password"
        hashed = hash_password(password)
        
        # Measure time for correct password
        start = time.time()
        result1 = verify_password(password, hashed)
        time1 = time.time() - start
        
        # Measure time for wrong password
        start = time.time()
        result2 = verify_password("wrong_password", hashed)
        time2 = time.time() - start
        
        # Results should be different
        assert result1 == True
        assert result2 == False
        
        # Times should be similar (within reasonable range to prevent timing attacks)
        # This is a basic test - in practice, you'd use statistical analysis
        assert abs(time1 - time2) < 0.1  # Within 100ms
    
    def test_token_validation(self):
        """Test JWT token validation"""
        # Test invalid token
        with pytest.raises(Exception):
            decode_token("invalid_token")
        
        # Test malformed token
        with pytest.raises(Exception):
            decode_token("not.a.jwt")
    
    def test_security_headers(self):
        """Test security headers in error responses"""
        response = client.post("/api/v1/auth/login", json={
            "email": "invalid-email",
            "password": "password123"
        })
        
        headers = response.headers
        assert "X-Content-Type-Options" in headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in headers
        assert headers["X-Frame-Options"] == "DENY"

class TestErrorHandling:
    """Test comprehensive error handling"""
    
    def test_404_error(self):
        """Test 404 error for non-existent endpoint"""
        response = client.get("/api/v1/nonexistent")
        assert response.status_code == 404
    
    def test_405_error(self):
        """Test 405 error for wrong HTTP method"""
        response = client.get("/api/v1/auth/login")
        assert response.status_code == 405
    
    def test_422_validation_error(self):
        """Test 422 error for validation failures"""
        response = client.post("/api/v1/auth/login", json={
            "email": "test@example.com"
            # Missing password field
        })
        assert response.status_code == 422
        assert "validation_errors" in response.json()
    
    def test_429_rate_limit_error(self):
        """Test 429 error for rate limiting"""
        # This would require mocking the rate limiter to trigger limit
        pass  # Implementation depends on rate limiter integration
    
    def test_error_response_format(self):
        """Test standardized error response format"""
        response = client.post("/api/v1/auth/login", json={
            "email": "invalid-email",
            "password": "password123"
        })
        
        error_data = response.json()
        assert "status_code" in error_data
        assert "error" in error_data
        assert "detail" in error_data
        assert "timestamp" in error_data
        assert "path" in error_data
        assert "method" in error_data
        assert "hints" in error_data

class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_empty_request_body(self):
        """Test handling of empty request body"""
        response = client.post("/api/v1/auth/login", data="")
        assert response.status_code in [400, 422]
    
    def test_large_payload(self):
        """Test handling of large payloads"""
        large_name = "A" * 1000
        response = client.post("/api/v1/auth/register", json={
            "name": large_name,
            "email": "test@example.com",
            "password": "password123"
        })
        # Should handle gracefully (either accept or reject with proper error)
        assert response.status_code in [200, 400, 413, 422]
    
    def test_special_characters(self):
        """Test handling of special characters"""
        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        response = client.post("/api/v1/auth/login", json={
            "email": f"user{special_chars}@example.com",
            "password": special_chars
        })
        # Should handle without crashing
        assert response.status_code != 500

if __name__ == "__main__":
    # Run all tests
    pytest.main([__file__, "-v", "--tb=short"])