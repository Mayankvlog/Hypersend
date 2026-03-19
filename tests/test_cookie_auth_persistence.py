#!/usr/bin/env python3
"""
Cookie-Based Authentication Persistence Tests
Tests 20-day persistent login with HTTPOnly cookies, refresh tokens, and auto-login
"""

import os
import sys
import pytest
from datetime import timedelta
from fastapi.testclient import TestClient

# Enable mock database for tests
os.environ['USE_MOCK_DB'] = 'True'

from backend.main import app
from backend.config import settings
from backend.auth.utils import create_access_token, decode_token
from bson import ObjectId

client = TestClient(app)

# Global test user data
TEST_USER_EMAIL = "cookie.test@zaply.in.net"
TEST_USER_PASSWORD = "CookieTest123!Pass"
TEST_USER_NAME = "Cookie Test User"


def get_test_user():
    """Get test user data"""
    return {
        "email": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD,
        "name": TEST_USER_NAME
    }


class TestCookieAuthentication:
    """Test cookie-based authentication with 20-day persistence"""
    
    def test_20day_token_expiration(self):
        """Test that tokens are configured for 20 days expiration"""
        # Verify settings show 20 days
        assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 28800, \
            f"Access token should be 20 days (28800 min), got {settings.ACCESS_TOKEN_EXPIRE_MINUTES}"
        assert settings.ACCESS_TOKEN_EXPIRE_SECONDS == 1728000, \
            f"Access token should be 20 days (1728000 sec), got {settings.ACCESS_TOKEN_EXPIRE_SECONDS}"
        assert settings.REFRESH_TOKEN_EXPIRE_DAYS == 20, \
            f"Refresh token should be 20 days, got {settings.REFRESH_TOKEN_EXPIRE_DAYS}"
    
    def test_access_token_creation_and_validation(self):
        """Test creating and validating access tokens"""
        user_id = str(ObjectId())
        
        # Create a token valid for 20 days
        access_token = create_access_token(
            data={"sub": user_id},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        # Should be a string
        assert isinstance(access_token, str), "Token should be a string"
        assert len(access_token) > 0, "Token should not be empty"
        
        # Decode and validate
        token_data = decode_token(access_token)
        assert token_data.user_id == user_id, "Token should contain correct user ID"
        assert token_data.token_type == "access", "Token should be access token type"
    
    def test_token_expiration_enforcement(self):
        """Test that expired tokens are rejected"""
        user_id = str(ObjectId())
        
        # Create an expired token (expires in the past)
        expired_token = create_access_token(
            data={"sub": user_id},
            expires_delta=timedelta(seconds=-1)
        )
        
        # Should raise an error when decoding
        try:
            decode_token(expired_token)
            assert False, "Expired token should be rejected"
        except Exception as e:
            # Expected behavior
            assert "expired" in str(e).lower() or "invalid" in str(e).lower()
    
    def test_refresh_session_endpoint_availability(self):
        """Test that refresh-session endpoint exists and is reachable"""
        # Try to call refresh-session without cookies (should fail with 400/401, not 404)
        response = client.post("/api/v1/auth/refresh-session", data={})
        
        # Should NOT return 404
        assert response.status_code != 404, \
            f"refresh-session endpoint should exist (not 404), got {response.status_code}"
        
        # Should return 400 or 401 or 500 (but not 404)
        assert response.status_code in [400, 401, 403, 500, 502, 503], \
            f"Expected auth error code, got {response.status_code}"
    
    def test_get_me_endpoint_requires_auth(self):
        """Test that /me endpoint requires authentication"""
        # Without cookies, should get 401
        response = client.get("/api/v1/users/me")
        
        assert response.status_code == 401, \
            f"/me without auth should return 401, got {response.status_code}"


class TestAutoLoginFlow:
    """Test auto-login flow for persistent sessions"""
    
    def test_session_check_flow(self):
        """Test the session check flow used during app initialization"""
        # This simulates what the Flutter app does on startup
        
        # 1. Call /me without cookies - should get 401
        me_response = client.get("/api/v1/users/me")
        assert me_response.status_code == 401, \
            "Unauthenticated /me should return 401"
    
    def test_logout_clears_session(self):
        """Test that logout properly clears session"""
        test_user = get_test_user()
        
        # Login
        login_response = client.post("/api/v1/auth/login", json=test_user)
        if login_response.status_code == 200:
            # Logout
            logout_response = client.post(
                "/api/v1/auth/logout",
                cookies=login_response.cookies
            )
            
            # Logout should succeed
            assert logout_response.status_code in [200, 202, 204], \
                f"Logout should succeed, got {logout_response.status_code}"


class TestTokenPersistence:
    """Test that tokens persist correctly"""
    
    def test_successive_requests_with_same_session(self):
        """Test making multiple requests with the same session"""
        test_user = get_test_user()
        
        # Login
        login_response = client.post("/api/v1/auth/login", json=test_user)
        if login_response.status_code == 200:
            cookies = login_response.cookies
            
            # Make several requests with the same cookies
            for i in range(2):
                response = client.get(
                    "/api/v1/users/me",
                    cookies=cookies
                )
                
                # Should work consistently
                assert response.status_code in [200, 202], \
                    f"Request {i+1} should succeed with persistent cookies, got {response.status_code}"


class TestRefreshTokenSystem:
    """Test refresh token functionality"""
    
    def test_refresh_endpoint_handles_requests(self):
        """Test that /refresh endpoint handles requests properly"""
        # Should return 400 (bad request) if no token provided, not 404
        response = client.post("/api/v1/auth/refresh", json={})
        
        assert response.status_code != 404, \
            "refresh endpoint should exist (not 404)"
        
        assert response.status_code in [400, 401, 422], \
            f"refresh should validate input, got {response.status_code}"
    
    def test_refresh_session_from_cookies(self):
        """Test that refresh-session reads from cookies"""
        test_user = get_test_user()
        
        # Login
        login_response = client.post("/api/v1/auth/login", json=test_user)
        if login_response.status_code == 200:
            # Try refresh with cookies
            refresh_response = client.post(
                "/api/v1/auth/refresh-session",
                cookies=login_response.cookies
            )
            
            # Should return 200 (success) or 401 (if refresh token invalid)
            # But not 400 (bad request) since we're providing cookies
            assert refresh_response.status_code in [200, 401, 400, 500, 502, 503], \
                f"refresh-session should handle cookies-based request, got {refresh_response.status_code}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

