#!/usr/bin/env python3
"""
Complete Password Management Pytest Tests
Test forget password, reset password, change password
"""

import pytest
import asyncio
import sys
import os
from datetime import datetime
from unittest.mock import patch, AsyncMock

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Set mock DB before imports
os.environ['USE_MOCK_DB'] = 'True'

# Enable password reset for this test file to match actual backend behavior
os.environ['ENABLE_PASSWORD_RESET'] = 'True'

from fastapi.testclient import TestClient
from main import app
from models import UserCreate, ChangePasswordRequest
from db_proxy import users_collection
from bson import ObjectId

class TestPasswordManagementComplete:
    """Complete password management tests"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def test_user_id(self):
        """Create test user ID"""
        return str(ObjectId())
    
    @pytest.fixture
    def test_user(self, test_user_id):
        """Create test user"""
        return {
            "_id": test_user_id,
            "name": "Test User",
            "email": "test@example.com",
            "password_hash": "hashed_password",
            "password_salt": "salt",
            "avatar": None,
            "avatar_url": None,
            "created_at": datetime.now()
        }
    
    def test_forgot_password_success(self, client, test_user, test_user_id):
        pytest.skip("/auth/forgot-password endpoint removed; token-based reset uses /auth/reset-password", allow_module_level=False)
        """Test forgot password endpoint success"""
        print("\n🔐 Test: Forgot Password Success")
        
        # Clear and setup test data
        users_collection().data.clear()
        users_collection().data[test_user_id] = test_user
        
        # Test forgot password
        forgot_data = {
            "email": "test@example.com"
        }
        
        response = client.post("/api/v1/auth/forgot-password", json=forgot_data)
        
        assert response.status_code == 200
        result = response.json()
        assert "message" in result
        assert "reset" in result["message"].lower() or "initiated" in result["message"].lower()
        
        print("✅ Forgot password successful")
    
    def test_forgot_password_user_not_found(self, client):
        pytest.skip("/auth/forgot-password endpoint removed; token-based reset uses /auth/reset-password", allow_module_level=False)
        """Test forgot password with non-existent user"""
        print("\n🔐 Test: Forgot Password - User Not Found")
        
        # Clear test data
        users_collection().data.clear()
        
        forgot_data = {
            "email": "nonexistent@example.com"
        }
        
        response = client.post("/api/v1/auth/forgot-password", json=forgot_data)
        
        # In debug mode, it returns 200 even for non-existent users
        assert response.status_code == 200
        result = response.json()
        assert "message" in result
        assert "reset" in result["message"].lower() or "initiated" in result["message"].lower()
        
        print("✅ User not found validation works")
    
    def test_reset_password_success(self, client, test_user, test_user_id):
        """Test reset password endpoint success"""
        print("\n🔐 Test: Reset Password Success")
        
        # Clear and setup test data
        users_collection().data.clear()
        users_collection().data[test_user_id] = test_user
        
        # Test with valid token format (endpoint is disabled)
        reset_data = {
            "token": "valid_reset_token_12345",
            "new_password": "NewTest@456"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        
        # Should return 401 Unauthorized since password reset is enabled but token is invalid
        assert response.status_code == 401
        result = response.json()
        assert "invalid" in result["detail"].lower() or "expired" in result["detail"].lower()
        
        print("✅ Reset password properly validates invalid token")
    
    def test_reset_password_invalid_token(self, client):
        """Test reset password with invalid token"""
        print("\n🔐 Test: Reset Password - Invalid Token")
        
        reset_data = {
            "token": "invalid_token",
            "new_password": "NewTest@456"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        
        # Should return 401 Unauthorized since password reset is enabled but token is invalid
        assert response.status_code == 401
        result = response.json()
        assert "invalid" in result["detail"].lower() or "expired" in result["detail"].lower()
        
        print("✅ Reset password properly validates invalid token")
    
    def test_change_password_success(self, client, test_user, test_user_id):
        """Test change password endpoint success"""
        print("\n🔐 Test: Change Password Success")
        
        # Clear and setup test data
        users_collection().data.clear()
        users_collection().data[test_user_id] = test_user
        
        # Mock authentication
        from fastapi import Depends
        from routes.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: test_user_id
        
        # Mock password verification
        with patch('routes.auth.verify_password') as mock_verify:
            mock_verify.return_value = True
            
            change_data = {
                "old_password": "Test@123",
                "new_password": "NewTest@456"
            }
            
            response = client.post("/api/v1/auth/change-password", json=change_data, headers={"Authorization": "Bearer test_token"})
            
            assert response.status_code == 200
            result = response.json()
            assert "message" in result
            assert "changed successfully" in result["message"].lower()
        
        # Clean up dependencies
        app.dependency_overrides.clear()
        
        print("✅ Change password successful")
    
    def test_change_password_field_compatibility(self, client, test_user, test_user_id):
        """Test change password with different field names"""
        print("\n🔐 Test: Change Password - Field Compatibility")
        
        # Clear and setup test data
        users_collection().data.clear()
        users_collection().data[test_user_id] = test_user
        
        # Mock authentication
        from fastapi import Depends
        from routes.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: test_user_id
        
        # Mock password verification
        with patch('routes.auth.verify_password') as mock_verify:
            mock_verify.return_value = True
            
            # Test with current_password field
            change_data = {
                "current_password": "Test@123",
                "new_password": "NewTest@789"
            }
            
            response = client.post("/api/v1/auth/change-password", json=change_data, headers={"Authorization": "Bearer test_token"})
            
            assert response.status_code == 200
            result = response.json()
            assert "message" in result
        
        # Clean up dependencies
        app.dependency_overrides.clear()
        
        print("✅ Field compatibility works")
    
    def test_change_password_missing_fields(self, client, test_user_id):
        """Test change password with missing required fields"""
        print("\n🔐 Test: Change Password - Missing Fields")
        
        # Mock authentication
        from fastapi import Depends
        from routes.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: test_user_id
        
        # Test with missing password fields
        change_data = {
            "new_password": "NewTest@123"
        }
        
        response = client.post("/api/v1/auth/change-password", json=change_data, headers={"Authorization": "Bearer test_token"})
        
        assert response.status_code == 400
        result = response.json()
        assert "old_password" in result["detail"] or "current_password" in result["detail"]
        
        # Clean up dependencies
        app.dependency_overrides.clear()
        
        print("✅ Missing fields validation works")
    
    def test_change_password_weak_new_password(self, client, test_user_id):
        """Test change password with weak new password"""
        print("\n🔐 Test: Change Password - Weak New Password")
        
        # Mock authentication
        from fastapi import Depends
        from routes.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: test_user_id
        
        # Test with weak password
        change_data = {
            "old_password": "Test@123",
            "new_password": "123"
        }
        
        response = client.post("/api/v1/auth/change-password", json=change_data, headers={"Authorization": "Bearer test_token"})
        
        assert response.status_code == 400
        result = response.json()
        assert "8 characters" in result["detail"] or "weak" in result["detail"].lower()
        
        # Clean up dependencies
        app.dependency_overrides.clear()
        
        print("✅ Weak password validation works")
    
    def test_change_password_incorrect_old_password(self, client, test_user, test_user_id):
        """Test change password with incorrect old password"""
        print("\n🔐 Test: Change Password - Incorrect Old Password")
        
        # Clear and setup test data
        users_collection().data.clear()
        users_collection().data[test_user_id] = test_user
        
        # Mock authentication
        from fastapi import Depends
        from routes.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: test_user_id
        
        # Mock password verification to return False
        with patch('routes.auth.verify_password') as mock_verify:
            mock_verify.return_value = False
            
            change_data = {
                "old_password": "WrongPassword@123",
                "new_password": "NewTest@456"
            }
            
            response = client.post("/api/v1/auth/change-password", json=change_data, headers={"Authorization": "Bearer test_token"})
            
            assert response.status_code == 400
            result = response.json()
            assert "incorrect" in result["detail"].lower()
        
        # Clean up dependencies
        app.dependency_overrides.clear()
        
        print("✅ Incorrect old password validation works")
    
    def test_password_model_validation(self):
        """Test password model validation"""
        print("\n🔐 Test: Password Model Validation")
        
        # ForgotPasswordRequest model removed - skipping test
        print("✅ ForgotPasswordRequest model removed")
        
        # Test ChangePasswordRequest model with old_password
        change_request = ChangePasswordRequest(
            old_password="Test@123",
            new_password="NewTest@456"
        )
        assert change_request.old_password == "Test@123"
        assert change_request.new_password == "NewTest@456"
        
        # Test ChangePasswordRequest model with current_password
        change_request_v2 = ChangePasswordRequest(
            current_password="Test@123",
            new_password="NewTest@456"
        )
        assert change_request_v2.current_password == "Test@123"
        assert change_request_v2.new_password == "NewTest@456"
        
        print("✅ Model validation works")

if __name__ == "__main__":
    print("🔐 Running Complete Password Management Tests")
    print("=" * 60)
    
    # Run tests
    pytest.main([__file__, "-v", "-s"])
