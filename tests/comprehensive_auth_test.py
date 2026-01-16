#!/usr/bin/env python3
"""
Comprehensive test script to validate all authentication and session management fixes
"""

import httpx
import asyncio
import json
import os
from datetime import datetime
import sys

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"

# Test user credentials from environment variables (security: never hardcode credentials)
TEST_USER_EMAIL = os.getenv("TEST_USER_EMAIL", "")
TEST_USER_PASSWORD = os.getenv("TEST_USER_PASSWORD", "")

# Validate credentials are provided
if not TEST_USER_EMAIL or not TEST_USER_PASSWORD:
    print("WARNING: Using default test credentials")
    TEST_USER_EMAIL = "test@example.com"
    TEST_USER_PASSWORD = "Test@123456"

# Color codes for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

def print_success(message):
    print(f"{GREEN}✓ {message}{RESET}")

def print_error(message):
    print(f"{RED}✗ {message}{RESET}")

def print_warning(message):
    print(f"{YELLOW}⚠ {message}{RESET}")

def print_info(message):
    print(f"{BOLD}ℹ {message}{RESET}")

async def check_health():
    """Test backend health"""
    print_info("Testing backend health...")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{BASE_URL}/health")
            if response.status_code == 200:
                print_success("Backend is running")
                return True
            else:
                print_error(f"Health check failed: {response.status_code}")
                return False
    except Exception as e:
        print_error(f"Cannot connect to backend: {str(e)}")
        return False

async def check_login_with_email():
    """Test login with email address"""
    print_info("Testing login with email address...")
    
    payload = {
        "email": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{API_BASE}/auth/login", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                access_token = data.get("access_token")
                refresh_token = data.get("refresh_token")
                
                if access_token and refresh_token:
                    print_success("Login successful with email")
                    return True, access_token, refresh_token
                else:
                    print_error("Login response missing tokens")
                    return False, None, None
            elif response.status_code == 422:
                print_error(f"Validation error (422) - check model fields")
                try:
                    print(f"Response: {response.json()}")
                except (json.JSONDecodeError, ValueError):
                    print(f"Response: {response.text}")
                return False, None, None
            elif response.status_code == 401:
                print_error(f"Authentication failed (401) - invalid credentials")
                return False, None, None
            else:
                print_error(f"Unexpected status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False, None, None
    except Exception as e:
        print_error(f"Login request failed: {str(e)}")
        return False, None, None

async def check_user_profile(access_token):
    """Test getting user profile with access token"""
    print_info("Testing user profile retrieval...")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await client.get(f"{API_BASE}/users/me", headers=headers)
            
            if response.status_code == 200:
                user_data = response.json()
                print_success("User profile retrieved")
                print(f"  Name: {user_data.get('name')}")
                print(f"  Email: {user_data.get('email')}")
                return True, user_data
            elif response.status_code == 401:
                print_error("Access token is invalid or expired")
                return False, None
            else:
                print_error(f"Profile retrieval failed: {response.status_code}")
                return False, None
    except Exception as e:
        print_error(f"Profile request failed: {str(e)}")
        return False, None

async def check_refresh_token(refresh_token):
    """Test refreshing access token without expiring session"""
    print_info("Testing token refresh (should extend session)...")
    
    payload = {"refresh_token": refresh_token}
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{API_BASE}/auth/refresh", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                new_access_token = data.get("access_token")
                
                if new_access_token:
                    print_success("Token refreshed successfully - session extended!")
                    print(f"  Old token expiry: Unknown")
                    print(f"  New token available: {new_access_token[:20]}...")
                    return True, new_access_token
                else:
                    print_error("Refresh response missing new access token")
                    return False, None
            elif response.status_code == 401:
                print_error("Refresh token is invalid or expired")
                return False, None
            else:
                print_error(f"Token refresh failed: {response.status_code}")
                print(f"Response: {response.text}")
                return False, None
    except Exception as e:
        print_error(f"Refresh request failed: {str(e)}")
        return False, None

async def check_session_refresh(refresh_token):
    """Test session refresh endpoint"""
    print_info("Testing session refresh endpoint...")
    
    payload = {"refresh_token": refresh_token}
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{API_BASE}/auth/refresh-session", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                new_access_token = data.get("access_token")
                
                if new_access_token:
                    print_success("Session refreshed successfully!")
                    return True, new_access_token
                else:
                    print_error("Session refresh response missing access token")
                    return False, None
            elif response.status_code == 401:
                print_error("Refresh token is invalid or expired")
                return False, None
            else:
                print_error(f"Session refresh failed: {response.status_code}")
                return False, None
    except Exception as e:
        print_error(f"Session refresh request failed: {str(e)}")
        return False, None

async def main():
    """Run all tests"""
    print(f"\n{BOLD}{'='*60}")
    print(f"Hypersend Authentication Fix Validation")
    print(f"{'='*60}{RESET}\n")
    
    all_passed = True
    
    # Test 1: Health check
    print(f"\n{BOLD}Test 1: Backend Health{RESET}")
    print("-" * 40)
    if not await check_health():
        print_error("Backend is not running. Please start the backend server.")
        sys.exit(1)
    
    # Test 2: Login with email
    print(f"\n{BOLD}Test 2: Login with Email (422 Error Fix){RESET}")
    print("-" * 40)
    login_success, access_token, refresh_token = await check_login_with_email()
    if not login_success:
        print_error("Login failed - this is the critical issue we're trying to fix")
        all_passed = False
    
    # Only continue with other tests if login was successful
    if login_success and access_token:
        # Test 3: User profile
        print(f"\n{BOLD}Test 3: User Profile Retrieval{RESET}")
        print("-" * 40)
        profile_success, user_data = await check_user_profile(access_token)
        if not profile_success:
            all_passed = False
        
        # Test 4: Token refresh
        print(f"\n{BOLD}Test 4: Token Refresh (No Session Expiry){RESET}")
        print("-" * 40)
        refresh_success, refresh_new_token = await check_refresh_token(refresh_token)
        if not refresh_success:
            print_warning("Token refresh failed - session might expire on page refresh")
            all_passed = False
        
        # Test 5: Session refresh
        print(f"\n{BOLD}Test 5: Session Refresh Endpoint{RESET}")
        print("-" * 40)
        session_success, session_new_token = await check_session_refresh(refresh_token)
        if not session_success:
            print_warning("Session refresh endpoint failed")
            all_passed = False
        
        # Test 6: Verify new token works (prefer session token if available, fall back to refresh token)
        final_test_token = session_new_token if session_new_token else refresh_new_token
        if final_test_token:
            print(f"\n{BOLD}Test 6: Verify New Token Works{RESET}")
            print("-" * 40)
            profile_success, _ = await check_user_profile(final_test_token)
            if not profile_success:
                all_passed = False
    
    # Summary
    print(f"\n{BOLD}{'='*60}")
    if all_passed:
        print_success("All tests passed!")
        print(f"{'='*60}{RESET}\n")
        sys.exit(0)
    else:
        print_error("Some tests failed")
        print(f"{'='*60}{RESET}\n")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
