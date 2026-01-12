#!/usr/bin/env python3
"""
Comprehensive Password Management Tests
Tests for forgot password, reset password, and change password functionality
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
import sys
import os

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import required modules
try:
    from main import app
    from models import ForgotPasswordRequest, PasswordResetRequest, ChangePasswordRequest
    from auth.utils import get_current_user, hash_password, create_access_token
    from db_proxy import users_collection, refresh_tokens_collection, reset_tokens_collection
    from bson import ObjectId
    from datetime import datetime, timedelta, timezone
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)

class TestPasswordManagement:
    def setup_method(self):
        """Setup test environment"""
        self.client = TestClient(app)
        # Clear mock database
        users_collection().data.clear()
        refresh_tokens_collection().data.clear()
        reset_tokens_collection().data.clear()
        
        # Override dependency for testing
        self.test_user_id = str(ObjectId())
        app.dependency_overrides[get_current_user] = lambda: self.test_user_id
    
    def create_test_user(self, email="test@example.com", password="Test@123"):
        """Create a test user"""
        password_hash, password_salt = hash_password(password)
        user = {
            "_id": ObjectId(self.test_user_id),
            "email": email,
            "name": "Test User",
            "password_hash": password_hash,
            "password_salt": password_salt,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        users_collection().data[self.test_user_id] = user
        return user
    
    def create_legacy_test_user(self, email="legacy@example.com", password="Test@123"):
        """Create a test user with legacy password format"""
        from auth.utils import hash_password
        legacy_password = hash_password(password)  # Combined hash for legacy
        user = {
            "_id": ObjectId(self.test_user_id),
            "email": email,
            "name": "Legacy User",
            "password": legacy_password,  # Legacy format
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        users_collection().data[self.test_user_id] = user
        return user

    @pytest.mark.asyncio
    async def test_forgot_password_success(self):
        """Test successful forgot password request"""
        print("\n🧪 Test: Forgot Password Success")
        
        # Create test user
        self.create_test_user("forgot@example.com")
        
        # Test forgot password
        request_data = {"email": "forgot@example.com"}
        
        with patch('backend.routes.auth.password_reset_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = True
            
            response = self.client.post(
                "/api/v1/auth/forgot-password",
                json=request_data
            )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert "password reset" in result["message"].lower()
        
        # Check if reset token was created
        reset_tokens = reset_tokens_collection().data
        assert len(reset_tokens) > 0
        
        print("✅ Forgot password test passed")

    @pytest.mark.asyncio
    async def test_forgot_password_nonexistent_email(self):
        """Test forgot password with non-existent email"""
        print("\n🧪 Test: Forgot Password - Non-existent Email")
        
        request_data = {"email": "nonexistent@example.com"}
        
        with patch('backend.routes.auth.password_reset_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = True
            
            response = self.client.post(
                "/api/v1/auth/forgot-password",
                json=request_data
            )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True  # Should still return success for security
        
        print("✅ Forgot password security test passed")

    @pytest.mark.asyncio
    async def test_forgot_password_invalid_email(self):
        """Test forgot password with invalid email format"""
        print("\n🧪 Test: Forgot Password - Invalid Email")
        
        request_data = {"email": "invalid-email"}
        
        response = self.client.post(
            "/api/v1/auth/forgot-password",
            json=request_data
        )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 400
        assert "Invalid email format" in response.text
        
        print("✅ Invalid email validation test passed")

    @pytest.mark.asyncio
    async def test_reset_password_success(self):
        """Test successful password reset"""
        print("\n🧪 Test: Reset Password Success")
        
        # Create test user
        self.create_test_user("reset@example.com")
        
        # Generate reset token
        reset_token = create_access_token(
            data={"sub": self.test_user_id, "token_type": "password_reset"},
            expires_delta=timedelta(minutes=30)
        )
        
        # Store reset token
        await reset_tokens_collection().insert_one({
            "user_id": self.test_user_id,
            "token": reset_token,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=30),
            "used": False
        })
        
        # Test password reset
        request_data = {
            "token": reset_token,
            "new_password": "NewPassword@123"
        }
        
        response = self.client.post(
            "/api/v1/auth/reset-password",
            json=request_data
        )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert "reset successfully" in result["message"].lower()
        
        # Verify password was updated
        user = await users_collection().find_one({"_id": ObjectId(self.test_user_id)})
        assert user["password_hash"] is not None
        assert user["password_salt"] is not None
        
        print("✅ Reset password test passed")

    @pytest.mark.asyncio
    async def test_reset_password_invalid_token(self):
        """Test password reset with invalid token"""
        print("\n🧪 Test: Reset Password - Invalid Token")
        
        request_data = {
            "token": "invalid_token",
            "new_password": "NewPassword@123"
        }
        
        response = self.client.post(
            "/api/v1/auth/reset-password",
            json=request_data
        )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 401 or response.status_code == 400
        
        print("✅ Invalid token test passed")

    @pytest.mark.asyncio
    async def test_change_password_success_new_format(self):
        """Test successful password change with new password format"""
        print("\n🧪 Test: Change Password Success - New Format")
        
        # Create test user with new format
        self.create_test_user("change@example.com", "OldPassword@123")
        
        # Test password change
        request_data = {
            "old_password": "OldPassword@123",
            "new_password": "NewPassword@123"
        }
        
        response = self.client.post(
            "/api/v1/auth/change-password",
            json=request_data
        )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert "changed successfully" in result["message"].lower()
        
        print("✅ Change password test passed")

    @pytest.mark.asyncio
    async def test_change_password_success_legacy_format(self):
        """Test successful password change with legacy password format"""
        print("\n🧪 Test: Change Password Success - Legacy Format")
        
        # Create test user with legacy format
        self.create_legacy_test_user("legacy@example.com", "OldPassword@123")
        
        # Test password change
        request_data = {
            "old_password": "OldPassword@123",
            "new_password": "NewPassword@123"
        }
        
        response = self.client.post(
            "/api/v1/auth/change-password",
            json=request_data
        )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        
        print("✅ Legacy password change test passed")

    @pytest.mark.asyncio
    async def test_change_password_wrong_old_password(self):
        """Test password change with wrong old password"""
        print("\n🧪 Test: Change Password - Wrong Old Password")
        
        # Create test user
        self.create_test_user("wrong@example.com", "CorrectPassword@123")
        
        # Test password change with wrong old password
        request_data = {
            "old_password": "WrongPassword@123",
            "new_password": "NewPassword@123"
        }
        
        response = self.client.post(
            "/api/v1/auth/change-password",
            json=request_data
        )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 400
        assert "Current password is incorrect" in response.text
        
        print("✅ Wrong password validation test passed")

    @pytest.mark.asyncio
    async def test_change_password_missing_old_password(self):
        """Test password change with missing old password field"""
        print("\n🧪 Test: Change Password - Missing Old Password")
        
        # Test with missing old_password field
        request_data = {
            "new_password": "NewPassword@123"
        }
        
        response = self.client.post(
            "/api/v1/auth/change-password",
            json=request_data
        )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 422  # Validation error
        assert "old_password" in response.text
        
        print("✅ Missing field validation test passed")

    @pytest.mark.asyncio
    async def test_change_password_weak_new_password(self):
        """Test password change with weak new password"""
        print("\n🧪 Test: Change Password - Weak New Password")
        
        # Create test user
        self.create_test_user("weak@example.com", "OldPassword@123")
        
        # Test password change with weak new password
        request_data = {
            "old_password": "OldPassword@123",
            "new_password": "123"  # Too short
        }
        
        response = self.client.post(
            "/api/v1/auth/change-password",
            json=request_data
        )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 400  # Validation error (400, not 422)
        assert "Password must be at least 8 characters" in response.text
        
        print("✅ Weak password validation test passed")

    @pytest.mark.asyncio
    async def test_change_password_unauthorized(self):
        """Test password change without authentication"""
        print("\n🧪 Test: Change Password - Unauthorized")
        
        # Remove dependency override to simulate unauthenticated request
        app.dependency_overrides.clear()
        
        request_data = {
            "old_password": "OldPassword@123",
            "new_password": "NewPassword@123"
        }
        
        response = self.client.post(
            "/api/v1/auth/change-password",
            json=request_data
        )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 401 or response.status_code == 403
        
        print("✅ Unauthorized access test passed")

    @pytest.mark.asyncio
    async def test_password_rate_limiting(self):
        """Test password reset rate limiting"""
        print("\n🧪 Test: Password Reset Rate Limiting")
        
        # Create test user
        self.create_test_user("ratelimit@example.com")
        
        request_data = {"email": "ratelimit@example.com"}
        
        with patch('backend.routes.auth.password_reset_limiter') as mock_limiter:
            # Simulate rate limit exceeded
            mock_limiter.is_allowed.return_value = False
            mock_limiter.get_retry_after.return_value = 60
            
            response = self.client.post(
                "/api/v1/auth/forgot-password",
                json=request_data
            )
        
        print(f"📥 Response Status: {response.status_code}")
        print(f"📥 Response Body: {response.text}")
        
        assert response.status_code == 429
        assert "Too many password reset attempts" in response.text
        
        print("✅ Rate limiting test passed")

    @pytest.mark.asyncio
    async def test_password_token_invalidation(self):
        """Test that refresh tokens are invalidated after password change"""
        print("\n🧪 Test: Password Change - Token Invalidation")
        
        # Create test user
        self.create_test_user("token@example.com", "OldPassword@123")
        
        # Create some refresh tokens individually (mock collection doesn't support insert_many)
        await refresh_tokens_collection().insert_one({
            "user_id": self.test_user_id,
            "token": "refresh_token_1",
            "created_at": datetime.now(timezone.utc),
            "invalidated": False
        })
        await refresh_tokens_collection().insert_one({
            "user_id": self.test_user_id,
            "token": "refresh_token_2",
            "created_at": datetime.now(timezone.utc),
            "invalidated": False
        })
        
        # Test password change
        request_data = {
            "old_password": "OldPassword@123",
            "new_password": "NewPassword@123"
        }
        
        response = self.client.post(
            "/api/v1/auth/change-password",
            json=request_data
        )
        
        assert response.status_code == 200
        
        # Check that refresh tokens were invalidated
        tokens = await refresh_tokens_collection().find({"user_id": self.test_user_id}).to_list(None)
        for token in tokens:
            assert token.get("invalidated") is True
        
        print("✅ Token invalidation test passed")

if __name__ == "__main__":
    print("🧪 Running Password Management Tests")
    print("=" * 50)
    
    # Run tests
    pytest.main([__file__, "-v", "-s"])
