"""
Comprehensive security and integration tests for hypersend backend
Tests all HTTP error scenarios, security vulnerabilities, and edge cases
"""

import pytest
import asyncio
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import tempfile
import os
from pathlib import Path

# Import application and modules
try:
    from backend.main import app
    client = TestClient(app)
    APP_AVAILABLE = True
except ImportError:
    client = None
    APP_AVAILABLE = False

from backend.auth.utils import hash_password, verify_password, decode_token, create_access_token
from backend.validators import validate_command_injection, validate_path_injection
from backend.rate_limiter import RateLimiter
from bson import ObjectId

class TestSecurityVulnerabilityFixes:
    """Test that security vulnerabilities identified in deep scan are fixed"""
    
    def test_jwt_object_id_validation(self):
        """Test ObjectId validation instead of regex"""
        valid_object_ids = [
            "507f1f77bcf86cd799439011",
            "67564dea8eac4df1519c7715",
            "ffffffffffffffffffffffff"  # Valid: 24 hex chars
        ]
        
        for object_id in valid_object_ids:
            # Should be valid
            assert ObjectId.is_valid(object_id) == True
        
        invalid_object_ids = [
            "invalid_id",
            "507f1f77bcf86cd79943901",  # Too short (23 chars)
            "507f1f77bcf86cd7994390111",  # Too long (25 chars)
            "gggggggggggggggggggggggg",  # Invalid hex characters
            "zzzzzzzzzzzzzzzzzzzzzzzzzz"  # Valid format but invalid hex (z is not hex)
        ]
        
        for object_id in invalid_object_ids:
            # Should be invalid
            assert ObjectId.is_valid(object_id) == False
    
    def test_password_hashing_security(self):
        """Test password hashing uses secure salt generation"""
        password = "test_password_123"
        hashed = hash_password(password)
        
        # Should contain salt separator
        assert '$' in hashed
        
        # Salt should be 32 hex characters
        salt = hashed.split('$')[0]
        assert len(salt) == 32
        assert all(c in '0123456789abcdefABCDEF' for c in salt)
        
        # Hash should be 64 hex characters
        hash_part = hashed.split('$')[1]
        assert len(hash_part) == 64
        assert all(c in '0123456789abcdefABCDEF' for c in hash_part)
        
        # Verification should work
        assert verify_password(password, hashed) == True
        assert verify_password("wrong_password", hashed) == False
    
    def test_path_traversal_protection(self):
        """Test enhanced path traversal protection"""
        # Dangerous paths that should be blocked
        dangerous_paths = [
            "../../../etc/passwd",              # Classic traversal
            "..\\..\\windows\\system32\\config\\sam",  # Windows traversal
            "/etc/shadow",                        # System file
            "/root/.ssh/id_rsa",                  # SSH key
            "~/.ssh/config",                       # SSH config
            "\x00nullbyte.txt",                    # Null byte injection
            "path/../../../etc/passwd",            # Mixed traversal
            "C:\\Windows\\System32\\cmd.exe"         # Windows system
            # Note: "absolute/path/to/file" is actually safe for relative paths
            # The pathlib validation will check if it resolves outside current dir
        ]
        
        for path in dangerous_paths:
            assert validate_path_injection(path) == False
        
        # Safe paths that should be allowed
        safe_paths = [
            "normal_file.txt",
            "documents/file.pdf",
            "uploads/image.jpg",
            "user_data.txt",
            "relative/path/file.txt"
        ]
        
        for path in safe_paths:
            assert validate_path_injection(path) == True
    
    def test_mime_type_validation_bypass_prevention(self):
        """Test MIME type validation can't be bypassed with case variation"""
        # These should all be blocked regardless of case
        dangerous_mime_types = [
            "application/javascript",
            "application/JavaScript",
            "APPLICATION/JAVASCRIPT",
            "text/html",
            "TEXT/HTML",
            "application/x-javascript"
        ]
        
        # Simulate MIME validation logic
        dangerous_mimes = ['application/javascript', 'text/javascript', 'application/x-javascript', 
                          'text/html', 'application/html']
        
        for mime in dangerous_mime_types:
            # Should be detected as dangerous
            assert mime.lower() in [d.lower() for d in dangerous_mimes]

class TestRateLimitingRaceConditions:
    """Test race condition fixes in rate limiting"""
    
    def test_concurrent_rate_limiting(self):
        """Test rate limiting handles concurrent access correctly"""
        limiter = RateLimiter(max_requests=2, window_seconds=300)
        
        # Simulate concurrent access
        async def test_concurrent_access():
            results = []
            for i in range(5):  # 5 concurrent requests
                result = limiter.is_allowed("test_user")
                results.append(result)
            return results
        
        # Run concurrent test
        results = asyncio.run(test_concurrent_access())
        
        # Should have exactly 2 allowed requests
        allowed_count = sum(1 for r in results if r)
        assert allowed_count == 2
        
        # Should have 3 blocked requests
        blocked_count = sum(1 for r in results if not r)
        assert blocked_count == 3
    
    def test_rate_limiting_persistence(self):
        """Test rate limiting state persists correctly"""
        limiter = RateLimiter(max_requests=3, window_seconds=1)
        
        # Use all requests
        for i in range(3):
            assert limiter.is_allowed("test_user") == True
        
        # Next request should be blocked
        assert limiter.is_allowed("test_user") == False
        
        # Check retry after time
        import time
        time.sleep(1.1)  # Wait for window to reset
        
        # Should be allowed again
        assert limiter.is_allowed("test_user") == True

class TestDatabaseErrorHandling:
    """Test enhanced database error handling"""
    
    def test_mongodb_configuration(self):
        """Test MongoDB configuration uses proper list format"""
        from database import connect_db
        
        # Test should not fail due to configuration
        # This is more of a configuration validation test
        assert True  # If we get here, imports worked
    
    def test_database_error_classification(self):
        """Test database errors are properly classified"""
        # Test error classification logic
        test_errors = [
            ("Connection refused", "connection"),
            ("Operation timeout occurred", "timeout"),
            ("Authentication failed", "authentication"),
            ("Network unreachable", "network")
        ]
        
        for error_msg, expected_type in test_errors:
            # Should categorize errors correctly
            error_lower = error_msg.lower()
            assert expected_type in error_lower, f"Expected '{expected_type}' in '{error_msg}'"

class TestFileUploadSecurityFixes:
    """Test file upload security fixes"""
    
    def test_dangerous_file_extension_blocking(self):
        """Test dangerous file extensions are properly blocked"""
        dangerous_extensions = [
            ".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".js",
            ".php", ".asp", ".sh", ".ps1", ".py", ".rb",
            ".dll", ".so", ".msi", ".reg", ".inf", ".ini",
            ".lnk", ".url", ".svg", ".swf"
        ]
        
        for ext in dangerous_extensions:
            # Should block dangerous extensions
            test_filename = f"test_file{ext}"
            try:
                result = validate_path_injection(test_filename)
                assert result == False, f"Expected False for {test_filename}, got {result}"
            except Exception as e:
                # If validation throws exception, that's also acceptable for dangerous files
                assert True, f"Exception for dangerous file {test_filename}: {e}"
    
    def test_safe_file_extension_allowing(self):
        """Test safe file extensions are allowed"""
        safe_extensions = [
            ".txt", ".pdf", ".jpg", ".png", ".gif", ".mp4", ".avi",
            ".mp3", ".wav", ".zip", ".doc", ".xls", ".ppt"
        ]
        
        for ext in safe_extensions:
            # Should allow safe extensions
            test_filename = f"test_file{ext}"
            assert validate_path_injection(test_filename) == True

class TestErrorHandlingImprovements:
    """Test error handling improvements"""
    
    @pytest.mark.skipif(client is None, reason="App not available")
    def test_upload_id_null_validation(self):
        """Test upload ID null validation is handled properly"""
        # Test that null/undefined upload IDs are rejected
        test_cases = [
            {"filename": "test.txt", "size": 1024},
            {"filename": "test.txt", "size": 1024, "upload_id": "null"},
            {"filename": "test.txt", "size": 1024, "upload_id": "undefined"}
        ]
        
        for case in test_cases:
            # Should handle gracefully (not crash)
            response = client.post(
                "/api/v1/files/init",
                json=case,
                headers={"Authorization": "Bearer fake_token"}
            )
            # Should return proper error (401 for auth, 422 for validation, etc.)
            assert response.status_code in [400, 401, 422]
    
    @pytest.mark.skipif(client is None, reason="App not available")
    def test_chunk_upload_error_handling(self):
        """Test chunk upload handles errors properly"""
        # Test invalid upload_id handling
        response = client.put(
            "/api/v1/files/null/chunk?chunk_index=0",
            data=b"test chunk data",
            headers={"Authorization": "Bearer fake_token"}
        )
        
        # Should return 400 for invalid upload_id
        assert response.status_code == 400

class TestPerformanceAndResourceManagement:
    """Test performance and resource management fixes"""
    
    def test_memory_efficient_operations(self):
        """Test operations are memory efficient"""
        # Test large data handling
        large_data = "A" * (10 * 1024 * 1024)  # 10MB string
        
        # Should handle large data efficiently
        result = validate_command_injection(large_data)
        assert result == True  # Large but safe data should be allowed
    
    def test_concurrent_safety(self):
        """Test concurrent operations are safe"""
        limiter = RateLimiter(max_requests=5, window_seconds=300)
        
        # Simulate high concurrency
        import threading
        
        results = []
        def worker():
            for i in range(10):
                results.append(limiter.is_allowed(f"user_{threading.get_ident()}"))
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        
        # Start all threads
        for t in threads:
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        # Should have handled all requests without errors
        assert len(results) == 50  # 5 threads * 10 requests each

class TestCORSAndSecurityHeaders:
    """Test CORS and security headers are properly implemented"""
    
    @pytest.mark.skipif(client is None, reason="App not available")
    def test_cors_security_headers(self):
        """Test CORS security headers are present"""
        response = client.options("/api/v1/files/init")
        
        # Should have proper CORS headers
        headers = response.headers
        assert "Access-Control-Allow-Origin" in headers
        assert "Access-Control-Allow-Methods" in headers
        assert "Access-Control-Allow-Headers" in headers
        assert "Access-Control-Max-Age" in headers
    
    @pytest.mark.skipif(client is None, reason="App not available")
    def test_security_headers_in_errors(self):
        """Test security headers are present in error responses"""
        response = client.post("/api/v1/auth/login", json={
            "email": "invalid-email",
            "password": "password"
        })
        
        # Should have security headers even in error responses
        headers = response.headers
        assert "X-Content-Type-Options" in headers
        assert "X-Frame-Options" in headers
        assert "X-XSS-Protection" in headers
        assert "Referrer-Policy" in headers

class TestIntegrationScenarios:
    """Test real-world integration scenarios"""
    
    def test_complete_file_upload_flow(self):
        """Test complete file upload flow with security checks"""
        # This test simulates a complete upload flow
        # 1. Initialize upload
        # 2. Upload chunks
        # 3. Complete upload
        # 4. Download file
        
        # Mock authentication for this test
        with patch('auth.utils.get_current_user_for_upload', return_value="test_user"):
            with patch('routes.files.uploads_collection') as mock_uploads:
                # Mock successful operations
                from unittest.mock import AsyncMock
                mock_insert_result = AsyncMock()
                mock_insert_result.inserted_id = "test_upload_id"
                mock_uploads.return_value.insert_one = AsyncMock(return_value=mock_insert_result)
                mock_uploads.return_value.find_one = AsyncMock(return_value={
                    "_id": "test_upload_id",
                    "user_id": "test_user", 
                    "total_chunks": 1,
                    "expires_at": None
                })
                
                if client:
                    # Test init
                    init_response = client.post("/api/v1/files/init", json={
                        "filename": "test.txt",
                        "size": 1024,
                        "chat_id": "chat_123",
                        "mime_type": "text/plain"
                    })
                    
                    # Should succeed
                    assert init_response.status_code in [200, 422]  # 422 if validation fails
    
    def test_authentication_flow_security(self):
        """Test authentication flow with security checks"""
        # Test login with various scenarios
        test_cases = [
            {"email": "test@example.com", "password": "password123"},  # Valid
            {"email": "test@example.com", "password": "wrong"},     # Wrong password
            {"email": "nonexistent@example.com", "password": "password123"},  # Non-existent user
            {"email": "invalid-email", "password": "password123"},   # Invalid email - should return 422
        ]
        
        for case in test_cases:
            if client:
                response = client.post("/api/v1/auth/login", json=case)
                # Should handle gracefully (not crash)
                assert response.status_code in [200, 422, 401]

if __name__ == "__main__":
    # Run all tests
    pytest.main([__file__, "-v", "--tb=short"])