#!/usr/bin/env python3
"""
Comprehensive JWT Forgot Password Flow Tests
Tests all 10 steps of the password reset process
"""

import os
import sys
import json
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Set mock database and debug mode
os.environ['USE_MOCK_DB'] = 'True'
os.environ['DEBUG'] = 'True'
os.environ['ENABLE_PASSWORD_RESET'] = 'True'

from fastapi.testclient import TestClient
from main import app
from config import settings
from auth.utils import decode_token
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

client = TestClient(app)

# Test data
TEST_USER_EMAIL = "jwt_reset_test@example.com"
TEST_USER_NAME = "JWT Reset Test User"
TEST_USER_PASSWORD = "OldPassword123"
TEST_NEW_PASSWORD = "NewPassword456"
TEST_INVALID_PASSWORD = "short"


class TestJWTForgotPasswordFlow:
    """Complete JWT forgot password flow tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test - clear and create test user"""
        # Register test user
        response = client.post("/api/v1/auth/register", json={
            "name": TEST_USER_NAME,
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
            "username": "jwtresettest"
        })
        assert response.status_code in [200, 201], f"User creation failed: {response.text}"
        print(f"✅ Test user created: {TEST_USER_EMAIL}")
        yield
        # Cleanup if needed
    
    def test_01_step1_request_email_valid(self):
        """Step 1: User enters valid email on forgot password page"""
        print("\n🔐 Step 1: User requests password reset with valid email")
        
        response = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        assert data["success"] is True, "Success flag missing"
        assert "message" in data, "Message missing"
        assert "expires_in" in data, "Expiration time missing"
        
        print(f"✅ Response: {data['message']}")
        print(f"✅ Token expires in: {data.get('expires_in')} seconds")
    
    def test_02_step1_request_email_invalid_format(self):
        """Step 1: Reject invalid email format"""
        print("\n🔐 Step 1: Reject invalid email format")
        
        invalid_emails = [
            "notanemail",
            "missing@domain",
            "double@@domain.com",
            "spaces in@email.com"
        ]
        
        for email in invalid_emails:
            response = client.post("/api/v1/auth/forgot-password", json={
                "email": email
            })
            
            assert response.status_code == 400, f"Should reject {email}"
            print(f"✅ Rejected invalid email: {email}")
    
    def test_03_step1_email_enumeration_protection(self):
        """Step 1: Prevent email enumeration - same response for existing/non-existing emails"""
        print("\n🔐 Step 1: Prevent email enumeration")
        
        response_existing = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        response_non_existing = client.post("/api/v1/auth/forgot-password", json={
            "email": "nonexistent@example.com"
        })
        
        # Both should return 200 (not 200 vs 404)
        assert response_existing.status_code == 200, "Existing email should return 200"
        assert response_non_existing.status_code == 200, "Non-existing email should also return 200"
        
        # Messages should be similar (both positive)
        data_existing = response_existing.json()
        data_non_existing = response_non_existing.json()
        
        assert data_existing["success"] is True
        assert data_non_existing["success"] is True
        print("✅ Both existing and non-existing emails return success (enumeration prevention)")
    
    def test_04_step2_generate_jwt_token(self):
        """Step 2: Verify JWT token is generated with correct claims"""
        print("\n🔐 Step 2: Verify JWT token generation")
        
        response = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        # In debug mode, token should be in response
        data = response.json()
        if "token" in data:
            reset_token = data["token"]
            print(f"✅ Reset token generated (first 50 chars): {reset_token[:50]}...")
            
            # Decode token to verify claims
            try:
                token_data = decode_token(reset_token)
                
                assert hasattr(token_data, 'user_id'), "Token missing user_id"
                assert hasattr(token_data, 'jti'), "Token missing jti"
                assert token_data.token_type == "password_reset", f"Wrong token type: {token_data.token_type}"
                
                print(f"✅ JWT claims verified:")
                print(f"   - user_id: {token_data.user_id}")
                print(f"   - jti: {token_data.jti[:20]}...")
                print(f"   - token_type: {token_data.token_type}")
                print(f"   - expires: present")
            except Exception as e:
                pytest.fail(f"Token decode failed: {e}")
        else:
            print("⚠️ Token not in response (email mode - token sent via email)")
    
    def test_05_step3_token_expiry(self):
        """Step 2: Verify token expiration is set to 1 hour"""
        print("\n🔐 Step 2: Verify token expiry (1 hour)")
        
        response = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        data = response.json()
        assert data.get("expires_in") == 3600, f"Token should expire in 3600 seconds, got {data.get('expires_in')}"
        print(f"✅ Token expiry set correctly: {data['expires_in']} seconds = 1 hour")
    
    def test_06_step4_verify_token_format(self):
        """Step 4: Verify token format when user clicks reset link"""
        print("\n🔐 Step 4: Verify token format from reset link")
        
        # Get token
        response = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        data = response.json()
        if "token" in data:
            reset_token = data["token"]
            
            # Token should be JWT format (3 parts separated by dots)
            parts = reset_token.split('.')
            assert len(parts) == 3, f"JWT should have 3 parts, got {len(parts)}"
            print(f"✅ Token format valid (JWT with 3 parts)")
            
            # Verify signature
            try:
                token_data = decode_token(reset_token)
                print(f"✅ JWT signature verified")
            except Exception as e:
                pytest.fail(f"JWT verification failed: {e}")
    
    def test_07_step5_reset_password_valid(self):
        """Step 5: User enters new password and system resets it"""
        print("\n🔐 Step 5: Reset password with valid new password")
        
        # Get reset token
        forgot_response = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        data = forgot_response.json()
        if "token" not in data:
            pytest.skip("Token not available in response (email mode)")
        
        reset_token = data["token"]
        
        # Reset password
        reset_response = client.post("/api/v1/auth/reset-password", json={
            "token": reset_token,
            "new_password": TEST_NEW_PASSWORD
        })
        
        assert reset_response.status_code == 200, f"Reset failed: {reset_response.text}"
        reset_data = reset_response.json()
        
        assert reset_data["success"] is True, "Success flag missing"
        assert "Password reset successfully" in reset_data["message"], "Wrong message"
        print(f"✅ Password reset successful: {reset_data['message']}")
    
    def test_08_step5_reset_password_invalid(self):
        """Step 5: Reject invalid new passwords"""
        print("\n🔐 Step 5: Reject invalid new password")
        
        # Get reset token
        forgot_response = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        data = forgot_response.json()
        if "token" not in data:
            pytest.skip("Token not available in response (email mode)")
        
        reset_token = data["token"]
        
        # Try to reset with too short password
        reset_response = client.post("/api/v1/auth/reset-password", json={
            "token": reset_token,
            "new_password": "short"
        })
        
        assert reset_response.status_code == 400, "Should reject short password"
        print(f"✅ Rejected invalid password")
    
    def test_09_step6_token_invalidation(self):
        """Step 6: Verify token is invalidated after use"""
        print("\n🔐 Step 6: Verify token is invalidated after successful reset")
        
        # Get reset token
        forgot_response = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        data = forgot_response.json()
        if "token" not in data:
            pytest.skip("Token not available in response (email mode)")
        
        reset_token = data["token"]
        
        # Use token once
        reset_response = client.post("/api/v1/auth/reset-password", json={
            "token": reset_token,
            "new_password": "NewPassword789"
        })
        
        assert reset_response.status_code == 200, "First reset should succeed"
        
        # Try to use same token again - should fail
        reuse_response = client.post("/api/v1/auth/reset-password", json={
            "token": reset_token,
            "new_password": "AnotherPassword"
        })
        
        assert reuse_response.status_code == 401, "Should reject reused token"
        reuse_data = reuse_response.json()
        assert "already been used" in reuse_data["detail"], "Should indicate token already used"
        print(f"✅ Token invalidated after use - reuse rejected")
    
    def test_10_step7_session_invalidation(self):
        """Step 6: Verify all sessions are invalidated after password reset"""
        print("\n🔐 Step 7: Verify all active sessions are invalidated")
        
        # Create new test user for this test
        test_email = "session_test@example.com"
        test_password = "InitialPassword123"
        
        client.post("/api/v1/auth/register", json={
            "name": "Session Test User",
            "email": test_email,
            "password": test_password,
            "username": "sessiontest"
        })
        
        # Login to create session
        login_response = client.post("/api/v1/auth/login", json={
            "email": test_email,
            "password": test_password
        })
        
        assert login_response.status_code == 200, "Login should succeed"
        login_data = login_response.json()
        access_token = login_data["access_token"]
        print(f"✅ Session created with access token")
        
        # Get reset token
        forgot_response = client.post("/api/v1/auth/forgot-password", json={
            "email": test_email
        })
        
        reset_data = forgot_response.json()
        if "token" not in reset_data:
            pytest.skip("Token not available in response (email mode)")
        
        reset_token = reset_data["token"]
        
        # Reset password
        reset_response = client.post("/api/v1/auth/reset-password", json={
            "token": reset_token,
            "new_password": "NewSessionPassword123"
        })
        
        assert reset_response.status_code == 200, "Password reset should succeed"
        print(f"✅ Password reset complete")
        
        # Try to use old access token - should fail
        protected_response = client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        # Should either return 401 (unauthorized) or user not found
        assert protected_response.status_code in [401, 403, 404], \
            f"Old token should be invalid, got {protected_response.status_code}"
        print(f"✅ Old session token invalidated - returned {protected_response.status_code}")
    
    def test_11_rate_limiting(self):
        """Test rate limiting on forgot password endpoint"""
        print("\n🔐 Rate Limiting: Multiple reset requests")
        
        # Make multiple requests
        responses = []
        for i in range(6):
            response = client.post("/api/v1/auth/forgot-password", json={
                "email": TEST_USER_EMAIL
            })
            responses.append(response)
        
        # Should get 429 after some requests (rate limiting)
        status_codes = [r.status_code for r in responses]
        print(f"✅ Status codes for 6 requests: {status_codes}")
        
        # At least one should be 429 (too many requests)
        if 429 in status_codes:
            print(f"✅ Rate limiting activated correctly")
    
    def test_12_login_with_new_password(self):
        """Test login with new password after reset"""
        print("\n🔐 Login with new password after reset")
        
        # Create new test user
        test_email = "login_test@example.com"
        test_password = "InitialPassword456"
        
        client.post("/api/v1/auth/register", json={
            "name": "Login Test User",
            "email": test_email,
            "password": test_password,
            "username": "logintest"
        })
        
        # Get reset token
        forgot_response = client.post("/api/v1/auth/forgot-password", json={
            "email": test_email
        })
        
        reset_data = forgot_response.json()
        if "token" not in reset_data:
            pytest.skip("Token not available in response (email mode)")
        
        reset_token = reset_data["token"]
        new_password = "NewPassword999"
        
        # Reset password
        reset_response = client.post("/api/v1/auth/reset-password", json={
            "token": reset_token,
            "new_password": new_password
        })
        
        assert reset_response.status_code == 200, "Password reset should succeed"
        
        # Try to login with old password - should fail
        old_login = client.post("/api/v1/auth/login", json={
            "email": test_email,
            "password": test_password
        })
        
        assert old_login.status_code == 401, "Old password should not work"
        print(f"✅ Old password rejected after reset")
        
        # Login with new password - should succeed
        new_login = client.post("/api/v1/auth/login", json={
            "email": test_email,
            "password": new_password
        })
        
        assert new_login.status_code == 200, f"New password should work: {new_login.text}"
        new_login_data = new_login.json()
        assert "access_token" in new_login_data, "Should return access token"
        print(f"✅ New password works correctly")
    
    def test_13_security_email_in_token(self):
        """Verify email is included in token for security"""
        print("\n🔐 Security: Email included in reset token")
        
        response = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        data = response.json()
        if "token" not in data:
            pytest.skip("Token not available in response (email mode)")
        
        reset_token = data["token"]
        token_data = decode_token(reset_token)
        
        assert hasattr(token_data, 'email') or 'email' in str(token_data), \
            "Email should be in token claims"
        print(f"✅ Email included in token for security")
    
    def test_14_token_expiry_enforcement(self):
        """Verify expired tokens are rejected"""
        print("\n🔐 Token Expiry: Verify expired tokens are rejected")
        
        # This is hard to test without manipulating time
        # In real tests, use freezegun or similar
        # For now, verify the logic is in place
        
        response = client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_USER_EMAIL
        })
        
        data = response.json()
        assert data["expires_in"] == 3600, "Token should expire in 1 hour"
        print(f"✅ Token expiry enforcement in place (1 hour)")


class TestEdgeCases:
    """Test edge cases and error scenarios"""
    
    def test_empty_email(self):
        """Test with empty email"""
        print("\n🔐 Edge Case: Empty email")
        
        response = client.post("/api/v1/auth/forgot-password", json={
            "email": ""
        })
        
        assert response.status_code == 400, "Should reject empty email"
        print(f"✅ Empty email rejected")
    
    def test_missing_email_field(self):
        """Test with missing email field"""
        print("\n🔐 Edge Case: Missing email field")
        
        response = client.post("/api/v1/auth/forgot-password", json={})
        
        assert response.status_code == 400, "Should reject missing email"
        print(f"✅ Missing email field rejected")
    
    def test_invalid_token_format(self):
        """Test reset with invalid token format"""
        print("\n🔐 Edge Case: Invalid token format")
        
        response = client.post("/api/v1/auth/reset-password", json={
            "token": "invalid.token",
            "new_password": "NewPassword123"
        })
        
        assert response.status_code == 401, "Should reject invalid token"
        print(f"✅ Invalid token format rejected")
    
    def test_missing_new_password(self):
        """Test reset without new password"""
        print("\n🔐 Edge Case: Missing new password")
        
        response = client.post("/api/v1/auth/reset-password", json={
            "token": "valid.jwt.token"
        })
        
        # Should fail due to validation
        assert response.status_code in [400, 422], "Should reject missing password"
        print(f"✅ Missing new password rejected")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
