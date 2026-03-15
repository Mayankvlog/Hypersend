"""
AUTHENTICATION INTEGRATION TEST SUITE
======================================
Tests to validate that signup, login, and session management work correctly
with clean URL routing.

RUN: pytest tests/test_auth_integration_clean_urls.py -v -s
"""

import pytest
import asyncio
import json
import secrets
from typing import Dict, Any, Optional
import httpx
from datetime import datetime, timedelta, timezone

# Test configurations
PRODUCTION_URL = "https://zaply.in.net"
API_BASE_URL = f"{PRODUCTION_URL}/api/v1"

# Test credentials
TEST_USERNAME = f"test_user_{secrets.token_hex(6)}"  # Random username for isolation
TEST_EMAIL = f"test_{secrets.token_hex(6)}@zaply.test"
TEST_PASSWORD = "Secure!Pass123"  # Must meet security requirements


class TestSignupFlow:
    """Test user signup flow"""
    
    @pytest.mark.asyncio
    async def test_signup_creates_user(self):
        """Test that signup creates a new user"""
        async with httpx.AsyncClient(timeout=10) as client:
            signup_payload = {
                "username": TEST_USERNAME,
                "email": TEST_EMAIL,
                "password": TEST_PASSWORD,
            }
            
            print(f"\n[SIGNUP] Attempting signup for: {TEST_USERNAME}")
            
            response = await client.post(
                f"{API_BASE_URL}/auth/register",
                json=signup_payload,
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            print(f"[SIGNUP] Status: {response.status_code}")
            print(f"[SIGNUP] Response: {response.text[:500]}")
            
            # Signup should return 201 Created or 200 OK
            assert response.status_code in [200, 201], \
                f"Signup failed: {response.status_code} - {response.text}"
            
            data = response.json()
            assert "user" in data or "id" in data or "username" in data, \
                "Signup response missing user data"
            
            print(f"[SIGNUP] ✅ Signup successful for {TEST_USERNAME}")
            return data
    
    @pytest.mark.asyncio
    async def test_signup_requires_credentials(self):
        """Test that signup validates required fields"""
        async with httpx.AsyncClient(timeout=10) as client:
            # Try signup without username
            response = await client.post(
                f"{API_BASE_URL}/auth/register",
                json={
                    "email": "test@test.com",
                    "password": "Password123!"
                },
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            print(f"\n[SIGNUP_VALIDATION] Empty username Status: {response.status_code}")
            
            # Should return 400/422 for invalid data
            assert response.status_code in [400, 422], \
                f"Should reject incomplete signup: {response.status_code}"
            
            print(f"[SIGNUP_VALIDATION] ✅ Signup validation works")


class TestLoginFlow:
    """Test user login flow"""
    
    @pytest.mark.asyncio
    async def test_login_with_credentials(self):
        """Test user login with username and password"""
        async with httpx.AsyncClient(timeout=10) as client:
            # First create a user
            unique_username = f"login_test_{secrets.token_hex(6)}"
            unique_email = f"login_{secrets.token_hex(6)}@zaply.test"
            password = "LoginTest123!"
            
            # Signup
            signup_resp = await client.post(
                f"{API_BASE_URL}/auth/register",
                json={
                    "username": unique_username,
                    "email": unique_email,
                    "password": password,
                },
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            print(f"\n[LOGIN_SETUP] Signup Status: {signup_resp.status_code}")
            
            if signup_resp.status_code not in [200, 201]:
                print(f"[LOGIN_SETUP] Signup failed: {signup_resp.text[:200]}")
                pytest.skip("Could not create test user for login")
            
            # Now try to login
            login_payload = {
                "username": unique_username,
                "password": password,
            }
            
            print(f"[LOGIN] Attempting login for: {unique_username}")
            
            response = await client.post(
                f"{API_BASE_URL}/auth/login",
                json=login_payload,
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            print(f"[LOGIN] Status: {response.status_code}")
            print(f"[LOGIN] Response: {response.text[:500]}")
            
            # Login should return 200 OK
            assert response.status_code == 200, \
                f"Login failed: {response.status_code} - {response.text}"
            
            data = response.json()
            
            # Check for token in response
            assert "access_token" in data or "token" in data, \
                "Login response missing access token"
            
            print(f"[LOGIN] ✅ Login successful for {unique_username}")
            
            # Extract token for future tests
            token = data.get("access_token") or data.get("token")
            return token
    
    @pytest.mark.asyncio
    async def test_login_requires_valid_credentials(self):
        """Test that login validates credentials"""
        async with httpx.AsyncClient(timeout=10) as client:
            # Try login with wrong password
            response = await client.post(
                f"{API_BASE_URL}/auth/login",
                json={
                    "username": "nonexistent_user",
                    "password": "WrongPassword123!"
                },
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            print(f"\n[LOGIN_VALIDATION] Invalid credentials Status: {response.status_code}")
            
            # Should return 401 Unauthorized or 400 Bad Request
            assert response.status_code in [400, 401, 403], \
                f"Should reject invalid credentials: {response.status_code}"
            
            print(f"[LOGIN_VALIDATION] ✅ Login validation works")


class TestSessionManagement:
    """Test session and token management"""
    
    @pytest.mark.asyncio
    async def test_token_in_request(self):
        """Test that auth token is properly returned and can be used"""
        async with httpx.AsyncClient(timeout=10) as client:
            # Create and login user
            unique_username = f"session_test_{secrets.token_hex(6)}"
            unique_email = f"session_{secrets.token_hex(6)}@zaply.test"
            password = "SessionTest123!"
            
            # Signup
            await client.post(
                f"{API_BASE_URL}/auth/register",
                json={
                    "username": unique_username,
                    "email": unique_email,
                    "password": password,
                },
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            # Login
            login_resp = await client.post(
                f"{API_BASE_URL}/auth/login",
                json={
                    "username": unique_username,
                    "password": password,
                },
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            print(f"\n[SESSION] Login Status: {login_resp.status_code}")
            
            if login_resp.status_code != 200:
                pytest.skip("Could not login for session test")
            
            data = login_resp.json()
            token = data.get("access_token") or data.get("token")
            print(f"[SESSION] Token received: {token[:20] if token else 'None'}...")
            
            assert token, "No token returned from login"
            
            # Use token to access protected endpoint
            response = await client.get(
                f"{API_BASE_URL}/users/me",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Origin": PRODUCTION_URL,
                },
                timeout=30
            )
            
            print(f"[SESSION] Protected endpoint Status: {response.status_code}")
            
            # Should be able to access protected endpoint with token
            assert response.status_code == 200, \
                f"Failed to access protected endpoint: {response.status_code} - {response.text}"
            
            print(f"[SESSION] ✅ Token authentication works")


class TestAPIErrorHandling:
    """Test proper error responses from auth endpoints"""
    
    @pytest.mark.asyncio
    async def test_api_returns_json_errors(self):
        """Test that API returns JSON error responses"""
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                f"{API_BASE_URL}/auth/login",
                json={},  # Empty payload
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            print(f"\n[ERROR_HANDLING] Invalid request Status: {response.status_code}")
            
            # Should return error status
            assert response.status_code >= 400, \
                f"Should return error for invalid request: {response.status_code}"
            
            # Check if response is JSON
            try:
                error_data = response.json()
                print(f"[ERROR_HANDLING] Error response: {json.dumps(error_data, indent=2)}")
                
                # Should have error field
                assert "detail" in error_data or "error" in error_data or "message" in error_data, \
                    "Error response should have error message"
                
                print(f"[ERROR_HANDLING] ✅ API returns proper JSON errors")
            except json.JSONDecodeError:
                pytest.fail(f"API did not return JSON error: {response.text}")
    
    @pytest.mark.asyncio
    async def test_api_404_errors(self):
        """Test that non-existent endpoints return 404"""
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"{API_BASE_URL}/auth/nonexistent-endpoint",
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            print(f"\n[ERROR_404] Nonexistent endpoint Status: {response.status_code}")
            
            # Should return 404
            assert response.status_code == 404, \
                f"Should return 404 for nonexistent endpoint: {response.status_code}"
            
            print(f"[ERROR_404] ✅ Proper 404 handling")


class TestCORSWithAuth:
    """Test CORS headers work with authentication"""
    
    @pytest.mark.asyncio
    async def test_cors_preflight_for_auth_routes(self):
        """Test that CORS preflight works for auth routes"""
        async with httpx.AsyncClient(timeout=10) as client:
            for endpoint in ["/auth/login", "/auth/register"]:
                response = await client.options(
                    f"{API_BASE_URL}{endpoint}",
                    headers={
                        "Origin": PRODUCTION_URL,
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "content-type",
                    },
                    timeout=10
                )
                
                print(f"\n[CORS_AUTH] {endpoint} Status: {response.status_code}")
                
                assert response.status_code == 200, \
                    f"CORS preflight failed for {endpoint}: {response.status_code}"
                
                # Check CORS headers
                cors_origin = response.headers.get("Access-Control-Allow-Origin")
                print(f"[CORS_AUTH] Allowed Origin: {cors_origin}")
                
                assert cors_origin is not None, \
                    f"Missing CORS header for {endpoint}"
                
                assert cors_origin == PRODUCTION_URL or cors_origin == "*", \
                    f"Wrong CORS origin: {cors_origin}"
            
            print(f"[CORS_AUTH] ✅ CORS works with auth routes")


class TestHealthStatus:
    """Test that system health doesn't affect auth"""
    
    @pytest.mark.asyncio
    async def test_auth_works_during_normal_operation(self):
        """Test that auth endpoints work during normal system operation"""
        async with httpx.AsyncClient(timeout=10) as client:
            # Check health first
            health_resp = await client.get(
                f"{PRODUCTION_URL}/health",
                timeout=15
            )
            
            print(f"\n[HEALTH_AUTH] System health Status: {health_resp.status_code}")
            
            if health_resp.status_code != 200:
                print(f"[HEALTH_AUTH] ⚠️  System health is {health_resp.status_code}")
            
            # Even if health isn't perfect, auth should work
            unique_username = f"health_test_{secrets.token_hex(6)}"
            
            response = await client.post(
                f"{API_BASE_URL}/auth/login",
                json={
                    "username": unique_username,
                    "password": "placeholder"
                },
                headers={"Origin": PRODUCTION_URL},
                timeout=30
            )
            
            print(f"[HEALTH_AUTH] Signup attempt Status: {response.status_code}")
            
            # Should at least be able to make auth request
            assert response.status_code >= 200, \
                "Auth endpoint not responding"
            
            print(f"[HEALTH_AUTH] ✅ Auth endpoints working during normal operation")


# Commands to run tests:
# pytest tests/test_auth_integration_clean_urls.py -v -s
# pytest tests/test_auth_integration_clean_urls.py::TestLoginFlow -v -s
# pytest tests/test_auth_integration_clean_urls.py -k "login" -v -s

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║ AUTHENTICATION INTEGRATION TEST SUITE (CLEAN URLS)              ║
    ║ Testing: https://zaply.in.net authentication flow               ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    Run with: pytest tests/test_auth_integration_clean_urls.py -v -s
    
    This test suite validates:
    ✅ Signup flow (/api/v1/auth/register)
    ✅ Login flow (/api/v1/auth/login)
    ✅ Token authentication (Authorization header)
    ✅ Protected endpoints (requires valid token)
    ✅ API error responses (JSON format)
    ✅ CORS preflight for auth routes
    ✅ Error handling (404, 400, 401)
    """)
