#!/usr/bin/env python3
"""Test script to verify the login endpoint fix for email-based authentication"""

import httpx
import asyncio
import json
import os
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"
AUTH_ENDPOINT = f"{API_BASE}/auth/login"

# Test credentials from environment variables (security: never hardcode credentials)
TEST_EMAIL = os.getenv("TEST_EMAIL", "")
TEST_PASSWORD = os.getenv("TEST_PASSWORD", "")

# Validate credentials are provided
if not TEST_EMAIL or not TEST_PASSWORD:
    print("ERROR: TEST_EMAIL and TEST_PASSWORD environment variables must be set")
    print("Usage: export TEST_EMAIL='user@example.com' TEST_PASSWORD='password' && python test_login_fix.py")
    exit(1)

async def test_login():
    """Test the login endpoint with email"""
    print(f"[{datetime.now().isoformat()}] Starting login test...")
    print(f"Testing endpoint: {AUTH_ENDPOINT}")
    print(f"Test email: {TEST_EMAIL}")
    print()
    
    # Create the request payload
    payload = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    }
    
    print(f"Request payload: {json.dumps(payload, indent=2)}")
    print()
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            print(f"[{datetime.now().isoformat()}] Sending POST request...")
            response = await client.post(AUTH_ENDPOINT, json=payload)
            
            print(f"[{datetime.now().isoformat()}] Response Status: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print()
            
            # SECURITY FIX: Parse JSON once to avoid redundant calls and handle errors properly
            response_json = None
            try:
                response_json = response.json()
                print(f"Response Body (JSON):")
                print(json.dumps(response_json, indent=2))
            except (json.JSONDecodeError, ValueError) as e:
                print(f"Response Body (Text):")
                print(response.text)
            
            # Check if login was successful
            if response.status_code == 200 and response_json:
                print()
                print("✓ LOGIN SUCCESSFUL!")
                access_token = response_json.get("access_token")
                refresh_token = response_json.get("refresh_token")
                print(f"Access Token (first 50 chars): {access_token[:50]}..." if access_token else "No access token")
                print(f"Refresh Token (first 50 chars): {refresh_token[:50]}..." if refresh_token else "No refresh token")
                return True
            elif response.status_code == 422 and response_json:
                print()
                print("✗ VALIDATION ERROR (422) - This suggests the model still expects different fields")
                if "detail" in response_json:
                    for error in response_json["detail"]:
                        print(f"  Field: {error.get('loc', [])}")
                        print(f"  Error: {error.get('msg', '')}")
                return False
            elif response.status_code == 401:
                print()
                print("✗ AUTHENTICATION ERROR (401) - Credentials are invalid or user doesn't exist")
                return False
            else:
                print()
                print(f"✗ UNEXPECTED STATUS CODE: {response.status_code}")
                return False
    
    except httpx.ConnectError as e:
        print(f"✗ CONNECTION ERROR: Could not connect to {BASE_URL}")
        print(f"  Make sure the backend is running at {BASE_URL}")
        return False
    except Exception as e:
        print(f"✗ ERROR: {type(e).__name__}: {str(e)}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_login())
    exit(0 if success else 1)
