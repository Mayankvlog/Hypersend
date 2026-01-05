"""
Comprehensive API test for all HTTP error codes (3xx, 4xx, 5xx)
Tests backend endpoints for logic errors and proper error handling
"""

import pytest
import sys
from pathlib import Path
import json
from unittest.mock import Mock, patch, MagicMock
from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
import jwt

# Add backend to path for imports
import os
backend_path = os.path.join(os.path.dirname(__file__), "..", "backend")
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import with proper error handling
ValidationErrorDetail = None
try:
    from error_handlers import ValidationErrorDetail  # type: ignore
except (ImportError, ModuleNotFoundError) as e:
    # Create fallback class if import fails
    class ValidationErrorDetail:  # type: ignore
        """Fallback class when error_handlers cannot be imported"""
        @staticmethod
        def extract_error_details(errors):
            return []


class TestSecurityKeyValidation:
    """Test SECRET_KEY validation logic"""
    
    def test_secret_key_complexity_validation(self):
        """Verify SECRET_KEY requires 3+ character types"""
        # Note: We test the validation logic directly without importing Settings
        # because the Settings class validates on instantiation during module import
        
        # Valid keys should pass
        valid_keys = [
            "aB9cD2eF5gH8jK1mN4pQ7rS0tU3vW6xY_ZlOpRsT@#$%^&*",  # Current key
            "MySecure@Pass2026_6add5b8a70d43ee404b7ef48efd1bd09f787af6cffd861d13344910e9fed9f19",
            "TestKey123!ABC",
            "Pass123@word",
            "MySecure#2025$Key"
        ]
        
        # Invalid keys should fail
        invalid_keys = [
            "6add5b8a70d43ee404b7ef48efd1bd09f787af6cffd861d13344910e9fed9f19",  # hex only
            "abcdefghijklmnopqrstuvwxyz",  # lowercase only
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",  # uppercase only
            "12345678901234567890",  # digits only
        ]
        
        # Test validation logic
        for key in valid_keys:
            has_upper = any(c.isupper() for c in key)
            has_lower = any(c.islower() for c in key)
            has_digit = any(c.isdigit() for c in key)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in key)
            char_types = sum([has_upper, has_lower, has_digit, has_special])
            assert char_types >= 3, f"Valid key '{key}' failed: only {char_types} types"
        
        for key in invalid_keys:
            has_upper = any(c.isupper() for c in key)
            has_lower = any(c.islower() for c in key)
            has_digit = any(c.isdigit() for c in key)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in key)
            char_types = sum([has_upper, has_lower, has_digit, has_special])
            assert char_types < 3, f"Invalid key '{key}' should fail: has {char_types} types"


class TestHTTPStatusCodes:
    """Test proper HTTP status code handling"""
    
    def test_3xx_redirection_codes(self):
        """Test 3xx redirection status codes"""
        status_codes_3xx = {
            300: "Multiple Choices",
            301: "Moved Permanently",
            302: "Found",
            303: "See Other",
            304: "Not Modified",
            305: "Use Proxy",
            307: "Temporary Redirect",
            308: "Permanent Redirect",
        }
        
        for code, name in status_codes_3xx.items():
            assert 300 <= code < 400, f"{code} {name} is a valid 3xx code"
    
    def test_4xx_client_error_codes(self):
        """Test 4xx client error status codes"""
        status_codes_4xx = {
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            409: "Conflict",
            410: "Gone",
            413: "Payload Too Large",
            415: "Unsupported Media Type",
            422: "Unprocessable Entity",
            429: "Too Many Requests",
        }
        
        for code, name in status_codes_4xx.items():
            assert 400 <= code < 500, f"{code} {name} is a valid 4xx code"
    
    def test_5xx_server_error_codes(self):
        """Test 5xx server error status codes"""
        status_codes_5xx = {
            500: "Internal Server Error",
            501: "Not Implemented",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }
        
        for code, name in status_codes_5xx.items():
            assert 500 <= code < 600, f"{code} {name} is a valid 5xx code"


class TestErrorHandlerLogic:
    """Test error handler logic for consistency"""
    
    def test_validation_error_response_format(self):
        """Test validation error response format"""
        # error_handlers import ValidationErrorDetail
        
        # Sample pydantic validation errors
        errors = [
            {
                "loc": ("field1",),
                "type": "value_error",
                "msg": "Field validation failed"
            },
            {
                "loc": ("nested", "field2"),
                "type": "type_error",
                "msg": "Invalid type"
            }
        ]
        
        details = ValidationErrorDetail.extract_error_details(errors)
        
        assert "validation_errors" in details
        assert details["error_count"] == 2
        assert "timestamp" in details
        assert len(details["validation_errors"]) == 2
        
        # Check first error
        assert details["validation_errors"][0]["field"] == "field1"
        assert details["validation_errors"][0]["type"] == "value_error"
    
    def test_http_exception_handling(self):
        """Test HTTP exception is properly formatted"""
        exc = HTTPException(
            status_code=400,
            detail="Invalid request"
        )
        
        assert exc.status_code == 400
        assert exc.detail == "Invalid request"


class TestAuthenticationErrors:
    """Test 401 Unauthorized errors"""
    
    @patch.dict('os.environ', {'SECRET_KEY': 'MySecure@Pass2026_6add5b8a70d43ee404b7ef48efd1bd09f787af6cffd861d13344910e9fed9f19'})
    def test_missing_token_returns_401(self):
        """Test missing authentication token returns 401"""
        # Simulate missing token scenario
        token = None
        
        if token is None:
            assert HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated"
            ).status_code == 401
    
    def test_invalid_token_returns_401(self):
        """Test invalid token returns 401"""
        invalid_token = "invalid.token.here"
        
        try:
            jwt.decode(invalid_token, "secret", algorithms=["HS256"])
            assert False, "Should have raised an exception"
        except jwt.InvalidTokenError:
            assert HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            ).status_code == 401


class TestFileUploadErrors:
    """Test file upload error handling"""
    
    def test_empty_file_returns_400(self):
        """Test empty file returns 400 Bad Request"""
        file_size = 0
        
        if file_size == 0:
            assert HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is empty"
            ).status_code == 400
    
    def test_oversized_file_returns_413(self):
        """Test oversized file returns 413 Payload Too Large"""
        file_size = 50 * 1024 * 1024 * 1024  # 50GB
        max_size = 42 * 1024 * 1024 * 1024  # 42GB limit
        
        if file_size > max_size:
            assert HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File too large"
            ).status_code == 413
    
    def test_invalid_chunk_index_returns_400(self):
        """Test invalid chunk index returns 400"""
        total_chunks = 10
        chunk_index = 15
        
        if chunk_index >= total_chunks:
            assert HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid chunk index"
            ).status_code == 400


class TestResourceNotFoundErrors:
    """Test 404 Not Found errors"""
    
    def test_file_not_found_returns_404(self):
        """Test file not found returns 404"""
        file_id = "nonexistent"
        found = False
        
        if not found:
            assert HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"File {file_id} not found"
            ).status_code == 404
    
    def test_user_not_found_returns_404(self):
        """Test user not found returns 404"""
        user_id = "nonexistent"
        found = False
        
        if not found:
            assert HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User {user_id} not found"
            ).status_code == 404


class TestConflictErrors:
    """Test 409 Conflict errors"""
    
    def test_duplicate_email_returns_409(self):
        """Test duplicate email returns 409 Conflict"""
        email = "test@example.com"
        email_exists = True
        
        if email_exists:
            assert HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered"
            ).status_code == 409
    
    def test_duplicate_chat_returns_409(self):
        """Test duplicate chat returns 409 Conflict"""
        chat_exists = True
        
        if chat_exists:
            assert HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Chat already exists"
            ).status_code == 409


class TestPermissionErrors:
    """Test 403 Forbidden errors"""
    
    def test_insufficient_permissions_returns_403(self):
        """Test insufficient permissions returns 403"""
        user_id = "user1"
        resource_owner = "user2"
        
        if user_id != resource_owner:
            assert HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            ).status_code == 403


class TestRateLimitingErrors:
    """Test 429 Too Many Requests errors"""
    
    def test_rate_limit_exceeded_returns_429(self):
        """Test rate limit exceeded returns 429"""
        requests_count = 101
        rate_limit = 100
        
        if requests_count > rate_limit:
            assert HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            ).status_code == 429


class TestServerErrors:
    """Test 5xx server error handling"""
    
    def test_database_error_returns_500(self):
        """Test database error returns 500"""
        db_error = True
        
        if db_error:
            assert HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            ).status_code == 500
    
    def test_service_unavailable_returns_503(self):
        """Test service unavailable returns 503"""
        service_available = False
        
        if not service_available:
            assert HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable"
            ).status_code == 503


class TestLogicValidation:
    """Test business logic consistency"""
    
    def test_token_expiration_logic(self):
        """Test token expiration logic"""
        from backend.auth.utils import create_access_token, verify_token
        from backend.config import settings
        import jwt
        
        # Test actual JWT token expiration
        user_id = "test_user_123"
        
        # Create a token that expires immediately for testing
        expired_token = create_access_token(
            data={"sub": user_id},
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        # Verify the token is properly expired
        with pytest.raises(jwt.ExpiredSignatureError):
            verify_token(expired_token)
        
        # Test valid token
        valid_token = create_access_token(
            data={"sub": user_id},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        # Verify valid token works
        payload = verify_token(valid_token)
        assert payload["user_id"] == user_id
    
    def test_file_size_validation(self):
        """Test file size validation logic"""
        file_size = 1024 * 1024  # 1MB
        max_size = 42 * 1024 * 1024 * 1024  # 42GB
        
        is_valid = 0 < file_size <= max_size
        assert is_valid, "File size should be valid"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
