#!/usr/bin/env python3
"""
Test password reset functionality with pytest
"""

import pytest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from datetime import datetime, timedelta, timezone

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Set mock DB before imports
os.environ['USE_MOCK_DB'] = 'True'

# Enable password reset for this test file (it tests the actual functionality)
os.environ['ENABLE_PASSWORD_RESET'] = 'True'

class TestPasswordResetFunctionality:
    """Test password reset functionality end-to-end"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        from main import app
        return TestClient(app)
    
    @pytest.mark.asyncio
    async def test_forgot_password_creates_reset_token(self):
        """Test that forgot password creates a valid reset token"""
        pytest.skip("/auth/forgot-password endpoint removed; token-based reset uses /auth/reset-password", allow_module_level=False)
        from routes.auth import forgot_password
        
        # Mock user
        test_user = {
            "_id": "507f1f77bcf86cd799439011",
            "email": "test@example.com",
            "name": "Test User"
        }
        
        class MockUsersCollection:
            def __init__(self):
                self.user = test_user
            
            async def find_one(self, query):
                # Handle both direct email match and regex queries
                if isinstance(query, dict):
                    email_query = query.get("email")
                    if email_query == "test@example.com":
                        return self.user
                    # Handle regex queries
                    elif "$regex" in query:
                        regex_pattern = query["$regex"]
                        if regex_pattern == "^test@example\.com$":  # Changed to use regex pattern
                            return self.user
                return None
        
        class MockResetTokensCollection:
            def __init__(self):
                self.tokens = []
            
            async def insert_one(self, token_doc):
                self.tokens.append(token_doc)
                return MagicMock(inserted_id="mock_id")
        
        mock_reset_tokens = MockResetTokensCollection()
        
        # ForgotPasswordRequest model removed - create simple dict
        from models import ForgotPasswordRequest
        request_data = ForgotPasswordRequest(email="test@example.com")
        
        with patch("routes.auth.users_collection", return_value=MockUsersCollection()), \
             patch("routes.auth.reset_tokens_collection", return_value=mock_reset_tokens), \
             patch("routes.auth.password_reset_limiter") as mock_limiter, \
             patch("routes.auth.settings") as mock_settings:
            
            mock_limiter.is_allowed.return_value = True
            mock_settings.EMAIL_SERVICE_ENABLED = True  # Enable to create token
            mock_settings.API_BASE_URL = "http://test.com"
            mock_settings.PASSWORD_RESET_EXPIRE_MINUTES = 30
            mock_settings.ENABLE_PASSWORD_RESET = True  # Enable for this test
            
            response = await forgot_password(request_data)
            
            assert response.success is True
            assert "Password reset" in response.message or "password reset link has been sent" in response.message.lower()
            
            # Check that token was created (functionality is now implemented)
            assert len(mock_reset_tokens.tokens) >= 1
    
    @pytest.mark.asyncio
    async def test_reset_password_with_valid_token(self):
        """Test password reset with valid token"""
        from routes.auth import reset_password
        from models import PasswordResetRequest
        from auth.utils import create_access_token
        
        # Create a valid reset token
        reset_token = create_access_token(
            data={"sub": "507f1f77bcf86cd799439011", "token_type": "password_reset"},
            expires_delta=timedelta(minutes=30)
        )

        from auth.utils import decode_token
        token_data = decode_token(reset_token)
        jti = getattr(token_data, "jti", None)
        assert jti, "Password reset token must include jti"
        
        test_user = {
            "_id": "507f1f77bcf86cd799439011",
            "email": "test@example.com",
            "name": "Test User"
        }
        
        class MockUsersCollection:
            def __init__(self):
                self.user = test_user
                self.updated = False
            
            async def find_one(self, query):
                from bson import ObjectId
                # Handle both _id and email queries
                if "_id" in query:
                    user_id = query.get("_id")
                    if isinstance(user_id, str):
                        user_id = ObjectId(user_id)
                    if str(user_id) == "507f1f77bcf86cd799439011":
                        return self.user
                elif "email" in query:
                    email = query.get("email")
                    if email == "test@example.com":
                        return self.user
                return None
            
            async def update_one(self, query, update):
                from bson import ObjectId
                user_id = query.get("_id")
                if isinstance(user_id, str):
                    user_id = ObjectId(user_id)
                if str(user_id) == "507f1f77bcf86cd799439011":
                    self.updated = True
                    return MagicMock(matched_count=1, modified_count=1)
                return MagicMock(matched_count=0, modified_count=0)
        
        class MockResetTokensCollection:
            def __init__(self):
                self.token_used = False
            
            async def find_one(self, query):
                if query.get("jti") == jti and query.get("token_type") == "password_reset" and query.get("used") is False:
                    return {
                        "_id": "mock_token_id",  # Add _id for update query
                        "jti": jti,
                        "token_type": "password_reset",
                        "used": False,
                        "invalidated": False,
                        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=30)
                    }
                return None
            
            async def update_one(self, query, update):
                if query.get("_id") == "mock_token_id":
                    self.token_used = True
                    return MagicMock(matched_count=1, modified_count=1)
                return MagicMock(matched_count=0, modified_count=0)
        
        class MockRefreshTokensCollection:
            async def update_many(self, query, update):
                return MagicMock(matched_count=1, modified_count=1)
        
        mock_users = MockUsersCollection()
        mock_reset_tokens = MockResetTokensCollection()
        mock_refresh_tokens = MockRefreshTokensCollection()
        
        request = PasswordResetRequest(
            token=reset_token,
            new_password="NewSecurePassword123!"
        )
        
        with patch("routes.auth.users_collection", return_value=mock_users), \
             patch("routes.auth.reset_tokens_collection", return_value=mock_reset_tokens), \
             patch("routes.auth.refresh_tokens_collection", return_value=mock_refresh_tokens), \
             patch("routes.auth.hash_password") as mock_hash, \
             patch("routes.auth.settings") as mock_settings:
            
            mock_hash.return_value = ("hashed_password", "salt_value")
            mock_settings.ENABLE_PASSWORD_RESET = True  # Enable for this test
            
            response = await reset_password(request)
            
            assert response.success is True
            assert "successfully" in response.message
            
            # Verify password was updated
            assert mock_users.updated is True
            
            # Verify token was marked as used
            assert mock_reset_tokens.token_used is True
    
    @pytest.mark.asyncio
    async def test_reset_password_with_invalid_token(self):
        """Test password reset with invalid token"""
        from routes.auth import reset_password
        from models import PasswordResetRequest
        
        class MockUsersCollection:
            async def find_one(self, query):
                return None
        
        class MockResetTokensCollection:
            async def find_one(self, query):
                return None
        
        request = PasswordResetRequest(
            token="invalid_token",
            new_password="NewSecurePassword123!"
        )
        
        with patch("routes.auth.users_collection", return_value=MockUsersCollection()), \
             patch("routes.auth.reset_tokens_collection", return_value=MockResetTokensCollection()), \
             patch("routes.auth.settings") as mock_settings:
            
            mock_settings.ENABLE_PASSWORD_RESET = True  # Enable for this test
            
            with pytest.raises(Exception) as exc_info:
                await reset_password(request)
            
            # Invalid token should fail at JWT validation level
            assert "Could not validate credentials" in str(exc_info.value) or "Invalid or expired" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_reset_password_token_validation(self):
        """Test that reset token validation works correctly"""
        from auth.utils import decode_token, create_access_token
        
        # Test valid password reset token
        valid_token = create_access_token(
            data={"sub": "507f1f77bcf86cd799439011", "token_type": "password_reset"},
            expires_delta=timedelta(minutes=30)
        )
        
        decoded = decode_token(valid_token)
        assert decoded.user_id == "507f1f77bcf86cd799439011"
        assert decoded.token_type == "password_reset"
        
        # Test invalid token (wrong type) - this should still decode but with "access" type
        access_token = create_access_token(
            data={"sub": "507f1f77bcf86cd799439011", "token_type": "access"},
            expires_delta=timedelta(minutes=30)
        )
        
        # This should decode successfully as access token
        decoded_access = decode_token(access_token)
        assert decoded_access.user_id == "507f1f77bcf86cd799439011"
        assert decoded_access.token_type == "access"
        
        # Test completely invalid token
        with pytest.raises(Exception) as exc_info:
            decode_token("invalid_token")
        
        assert "Could not validate credentials" in str(exc_info.value)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
