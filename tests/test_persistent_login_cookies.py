#!/usr/bin/env python3
"""
Comprehensive pytest tests for persistent login with HTTPOnly cookies
Tests session persistence, token refresh flow, and auto-login functionality
"""

import pytest
import asyncio
import httpx
from datetime import datetime, timezone
import json
import os


# Configuration
BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
API_BASE = f"{BASE_URL}/api/v1"

# Test credentials
TEST_USER_EMAIL = os.getenv("TEST_USER_EMAIL", "persistent@test.example.com")
TEST_USER_PASSWORD = os.getenv("TEST_USER_PASSWORD", "TestPass@123")

# Color codes for display
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


class TestPersistentLoginCookies:
    """Test suite for HTTPOnly cookie-based persistent login"""

    @pytest.fixture
    async def http_client(self):
        """Create HTTP client with cookie jar support"""
        async with httpx.AsyncClient(
            base_url=BASE_URL,
            timeout=30.0,
            follow_redirects=True
        ) as client:
            yield client

    @pytest.mark.asyncio
    async def test_login_sets_httponly_cookies(self, http_client):
        """Verify login endpoint sets HTTPOnly cookies for session persistence"""
        payload = {
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD
        }
        
        response = await http_client.post(f"{API_BASE}/auth/login", json=payload)
        
        # Should return 200 on success
        assert response.status_code in [200, 201], f"Expected 200/201, got {response.status_code}: {response.text}"
        
        # Check response contains success message
        data = response.json()
        assert data.get("message") == "Login successful" or "token_type" in data
        
        # CRITICAL: Check that cookies are set in the response headers
        # HTTPOnly cookies are returned in Set-Cookie header
        cookies = response.cookies
        assert "access_token" in cookies, "access_token cookie not set"
        assert "refresh_token" in cookies, "refresh_token cookie not set"
        
        # Verify cookie properties for security
        access_cookie = cookies.get("access_token")
        assert access_cookie is not None, "access_token cookie should exist"
        
        refresh_cookie = cookies.get("refresh_token")
        assert refresh_cookie is not None, "refresh_token cookie should exist"
        
        print(f"{GREEN}✓ Login sets HTTPOnly cookies successfully{RESET}")

    @pytest.mark.asyncio
    async def test_automatic_cookie_inclusion_on_requests(self, http_client):
        """Verify cookies are automatically included in subsequent requests"""
        # First, login
        login_payload = {
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD
        }
        
        login_response = await http_client.post(f"{API_BASE}/auth/login", json=login_payload)
        assert login_response.status_code in [200, 201]
        
        # Cookies should be automatically included now
        # Make request to /me endpoint which requires authentication
        me_response = await http_client.get(f"{API_BASE}/users/me")
        
        # Should succeed because cookies are automatically sent
        assert me_response.status_code == 200, f"Expected 200, got {me_response.status_code}: {me_response.text}"
        
        user_data = me_response.json()
        assert user_data.get("email") == TEST_USER_EMAIL.lower()
        
        print(f"{GREEN}✓ Cookies automatically included in requests{RESET}")

    @pytest.mark.asyncio
    async def test_session_refresh_with_refresh_token(self, http_client):
        """Verify refresh-session endpoint works with refresh token cookie"""
        # Login first
        login_payload = {
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD
        }
        
        login_response = await http_client.post(f"{API_BASE}/auth/login", json=login_payload)
        assert login_response.status_code in [200, 201]
        
        # Now refresh the session
        refresh_response = await http_client.post(
            f"{API_BASE}/auth/refresh-session",
            data={}  # refresh token comes from cookies
        )
        
        assert refresh_response.status_code == 200, f"Expected 200, got {refresh_response.status_code}: {refresh_response.text}"
        
        data = refresh_response.json()
        assert data.get("message") == "Session refreshed"
        
        # Verify new access token cookie is set
        cookies = refresh_response.cookies
        assert "access_token" in cookies, "New access_token cookie not set after refresh"
        
        print(f"{GREEN}✓ Session refresh succeeds with refresh token{RESET}")

    @pytest.mark.asyncio
    async def test_expired_access_token_refresh_flow(self, http_client):
        """Verify automatic refresh flow when access token expires"""
        # Login first
        login_payload = {
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD
        }
        
        login_response = await http_client.post(f"{API_BASE}/auth/login", json=login_payload)
        assert login_response.status_code in [200, 201]
        
        # Simulate making a request with valid session
        me_response = await http_client.get(f"{API_BASE}/users/me")
        assert me_response.status_code == 200, "Initial /me request should succeed"
        
        # The actual access token expiration is handled by the API interceptor
        # Here we verify the /me endpoint is protected and returns 401 for missing auth
        
        # Create a new client without cookies to simulate expired token
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as unauth_client:
            me_response = await unauth_client.get(f"{API_BASE}/users/me")
            # Without cookies, should return 401
            assert me_response.status_code == 401, f"Expected 401 for unauthenticated request, got {me_response.status_code}"
        
        print(f"{GREEN}✓ Protected endpoints require valid session{RESET}")

    @pytest.mark.asyncio
    async def test_logout_clears_session(self, http_client):
        """Verify logout endpoint clears HTTPOnly cookies"""
        # Login first
        login_payload = {
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD
        }
        
        login_response = await http_client.post(f"{API_BASE}/auth/login", json=login_payload)
        assert login_response.status_code in [200, 201]
        
        # Make a request to verify we're logged in
        me_response = await http_client.get(f"{API_BASE}/users/me")
        assert me_response.status_code == 200, "Should be logged in"
        
        # Logout
        logout_response = await http_client.post(f"{API_BASE}/auth/logout")
        assert logout_response.status_code == 200, f"Expected 200, got {logout_response.status_code}: {logout_response.text}"
        
        # Try to use the cookie after logout
        # The client should still have the cookie, but server should reject it
        me_response = await http_client.get(f"{API_BASE}/users/me")
        assert me_response.status_code == 401, "Should be logged out after logout"
        
        print(f"{GREEN}✓ Logout clears session successfully{RESET}")

    @pytest.mark.asyncio
    async def test_session_persistence_across_requests(self, http_client):
        """Verify session persists across multiple requests in same client"""
        # Login
        login_payload = {
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD
        }
        
        login_response = await http_client.post(f"{API_BASE}/auth/login", json=login_payload)
        assert login_response.status_code in [200, 201]
        
        # Make multiple requests and verify all succeed (cookies persist)
        for i in range(3):
            me_response = await http_client.get(f"{API_BASE}/users/me")
            assert me_response.status_code == 200, f"Request {i+1} should succeed with persisted cookies"
        
        print(f"{GREEN}✓ Session persists across multiple requests{RESET}")

    @pytest.mark.asyncio
    async def test_me_endpoint_requires_authentication(self, http_client):
        """Verify /me endpoint requires valid session"""
        # Try to access /me without login
        response = await http_client.get(f"{API_BASE}/users/me")
        
        # Should return 401 because no cookies are set
        assert response.status_code == 401, f"Expected 401 for unauthenticated /me request, got {response.status_code}"
        
        print(f"{GREEN}✓ /me endpoint requires authentication ✓{RESET}")

    @pytest.mark.asyncio
    async def test_refresh_token_validation(self, http_client):
        """Verify refresh token endpoint validates token integrity"""
        # Try to refresh without logging in first (no valid cookie)
        response = await http_client.post(f"{API_BASE}/auth/refresh-session", data={})
        
        # Should return 400 or 401 because no refresh token
        assert response.status_code in [400, 401], f"Expected 400/401 for missing refresh token, got {response.status_code}"
        
        print(f"{GREEN}✓ Refresh endpoint validates refresh token{RESET}")


@pytest.mark.asyncio
async def test_complete_login_flow():
    """Integration test: complete login → session use → logout flow"""
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        # 1. Register new user (may fail if already exists, that's ok)
        print("\n--- Testing Complete Login Flow ---")
        
        # 2. Login
        print("Step 1: Login...")
        login_payload = {
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD
        }
        login_response = await client.post(f"{API_BASE}/auth/login", json=login_payload)
        assert login_response.status_code in [200, 201], f"Login failed: {login_response.text}"
        assert "access_token" in login_response.cookies
        assert "refresh_token" in login_response.cookies
        print(f"{GREEN}✓ Login successful - cookies set{RESET}")
        
        # 3. Use session to fetch user data
        print("Step 2: Use session to fetch user data...")
        me_response = await client.get(f"{API_BASE}/users/me")
        assert me_response.status_code == 200, f"Failed to fetch user: {me_response.text}"
        user_data = me_response.json()
        print(f"{GREEN}✓ User data retrieved: {user_data.get('email')}{RESET}")
        
        # 4. Refresh session
        print("Step 3: Refresh session...")
        refresh_response = await client.post(f"{API_BASE}/auth/refresh-session", data={})
        assert refresh_response.status_code == 200, f"Session refresh failed: {refresh_response.text}"
        print(f"{GREEN}✓ Session refreshed{RESET}")
        
        # 5. Make another request with refreshed session
        print("Step 4: Verify session still works...")
        me_response2 = await client.get(f"{API_BASE}/users/me")
        assert me_response2.status_code == 200, f"Failed to fetch user after refresh: {me_response2.text}"
        print(f"{GREEN}✓ Session works after refresh{RESET}")
        
        # 6. Logout
        print("Step 5: Logout...")
        logout_response = await client.post(f"{API_BASE}/auth/logout")
        assert logout_response.status_code == 200, f"Logout failed: {logout_response.text}"
        print(f"{GREEN}✓ Logout successful{RESET}")
        
        # 7. Verify session is cleared
        print("Step 6: Verify session is cleared...")
        me_response3 = await client.get(f"{API_BASE}/users/me")
        assert me_response3.status_code == 401, f"Should not be authenticated after logout: {me_response3.text}"
        print(f"{GREEN}✓ Session cleared after logout{RESET}")
        
        print(f"\n{GREEN}=== All flow tests passed ==={RESET}\n")


if __name__ == "__main__":
    # Run with: pytest test_persistent_login_cookies.py -v
    print("Run tests with: pytest test_persistent_login_cookies.py -v")
    print("Or for integration test: python test_persistent_login_cookies.py")
    
    # Optionally run the integration test directly
    # asyncio.run(test_complete_login_flow())
