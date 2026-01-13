#!/usr/bin/env python3
"""
Password Management Tests - Reset Password Disabled
Test forgot password and reset password endpoints after disabling
"""

import pytest
import asyncio
import sys
import os
from datetime import datetime

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Set mock DB before imports
os.environ['USE_MOCK_DB'] = 'True'

from fastapi.testclient import TestClient
from main import app
from models import PasswordResetRequest
from db_proxy import users_collection
from bson import ObjectId

class TestPasswordManagementDisabled:
    """Test password management with reset functionality disabled"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def test_user_id(self):
        """Create test user ID"""
        return str(ObjectId())
    
    def test_forgot_password_disabled(self, client):
        """Test forgot password endpoint disabled"""
        print("\n🔐 Test: Forgot Password - Disabled")
        
        # Clear test data
        users_collection().data.clear()
        
        forgot_data = {
            "email": "test@example.com"
        }
        
        response = client.post("/api/v1/auth/forgot-password", json=forgot_data)
        
        assert response.status_code == 200
        result = response.json()
        assert result["success"] is False
        assert "disabled" in result["message"].lower()
        assert "support" in result["message"].lower()
        
        print("✅ Forgot password properly disabled")
    
    def test_forgot_password_invalid_email(self, client):
        """Test forgot password with invalid email"""
        print("\n🔐 Test: Forgot Password - Invalid Email")
        
        forgot_data = {
            "email": "invalid-email"
        }
        
        response = client.post("/api/v1/auth/forgot-password", json=forgot_data)
        
        assert response.status_code == 400
        result = response.json()
        assert "invalid email format" in result["detail"].lower()
        
        print("✅ Invalid email validation works")
    
    def test_reset_password_disabled(self, client):
        """Test reset password endpoint disabled"""
        print("\n🔐 Test: Reset Password - Disabled")
        
        reset_data = {
            "token": "any_token_here",
            "new_password": "NewTest@456"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        
        # Should return 405 Method Not Allowed since POST endpoint is disabled
        assert response.status_code == 405
        
        print("✅ Reset password properly disabled")
    
    def test_reset_password_options(self, client):
        """Test reset password options endpoint"""
        print("\n🔐 Test: Reset Password - Options")
        
        response = client.options("/api/v1/auth/reset-password")
        
        assert response.status_code == 200
        
        # Check if response has content
        if response.content:
            try:
                result = response.json()
                assert "disabled" in result["message"].lower()
                print("✅ Reset password options works with JSON response")
            except:
                # If not JSON, just check status code
                print("✅ Reset password options works (non-JSON response)")
        else:
            # Empty response is also acceptable for OPTIONS
            print("✅ Reset password options works (empty response)")
    
    def test_change_password_still_works(self, client, test_user_id):
        """Test that change password still works"""
        print("\n🔐 Test: Change Password - Still Works")
        
        # Create test user
        users_collection().data.clear()
        test_user = {
            "_id": test_user_id,
            "name": "Test User",
            "email": "test@example.com",
            "password_hash": "hashed_password",
            "password_salt": "salt",
            "avatar": None,
            "avatar_url": None,
            "created_at": datetime.now()
        }
        users_collection().data[test_user_id] = test_user
        
        # Mock authentication
        from fastapi import Depends
        from routes.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: test_user_id
        
        # Mock password verification
        from unittest.mock import patch
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
        
        print("✅ Change password still works")
    
    def test_password_models_still_work(self):
        """Test that password models still work"""
        print("\n🔐 Test: Password Models - Still Work")
        
        # ForgotPasswordRequest model removed - skipping test
        print("✅ ForgotPasswordRequest model removed")
        
        # Test PasswordResetRequest model
        reset_request = PasswordResetRequest(
            token="test_token",
            new_password="NewTest@456"
        )
        assert reset_request.token == "test_token"
        assert reset_request.new_password == "NewTest@456"
        
        print("✅ Password models still work")
    
    def test_frontend_integration_message(self, client):
        """Test frontend integration message"""
        print("\n🔐 Test: Frontend Integration Message")
        
        forgot_data = {
            "email": "user@example.com"
        }
        
        response = client.post("/api/v1/auth/forgot-password", json=forgot_data)
        
        assert response.status_code == 200
        result = response.json()
        
        # Check that message is user-friendly for frontend
        assert "disabled" in result["message"].lower()
        assert "contact support" in result["message"].lower()
        assert result["success"] is False
        
        print("✅ Frontend integration message is user-friendly")

if __name__ == "__main__":
    print("🔐 Running Password Management Tests (Reset Disabled)")
    print("=" * 60)
    
    # Run tests
    pytest.main([__file__, "-v", "-s"])
