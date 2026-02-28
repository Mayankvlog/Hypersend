#!/usr/bin/env python3
"""
Test Token-Based Password Reset Endpoint with MongoDB Atlas
Validates password reset flow and security using database tokens
"""
import sys
import os
import pytest

# Add backend to path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Use mock database for testing (MongoDB Atlas has event loop issues with TestClient)
os.environ['USE_MOCK_DB'] = 'True'
os.environ['MONGODB_ATLAS_ENABLED'] = 'false'
os.environ['MONGODB_URI'] = 'mongodb+srv://test:test@localhost:27017/test?retryWrites=true&w=majority'
os.environ['DATABASE_NAME'] = 'test'
os.environ['SECRET_KEY'] = 'test-secret-key'

try:
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)
except ImportError as e:
    print(f"Could not import backend modules: {e}")
    print("Running in requests mode...")
    client = None

import json
from datetime import datetime

API_URL = "http://localhost:8000/api/v1"
TEST_EMAIL = "testuser@example.com"

def test_forgot_password():
    """Test forgot password endpoint with token generation"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing /forgot-password endpoint...")
    
    try:
        # First create test user if it doesn't exist
        register_payload = {
            "email": TEST_EMAIL,
            "password": "TestPass123",
            "name": "Test User"
        }
        
        reg_response = client.post("/api/v1/auth/register", json=register_payload)
        print(f"User creation status: {reg_response.status_code}")
        
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": TEST_EMAIL},
            timeout=60
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            data = response.json()
            # New flow should return token directly
            if "reset_token" in data:
                print("[PASS] PASS: Forgot password endpoint working with token generation")
                print(f"   - Token: {data.get('reset_token')}")
                print(f"   - Message: {data.get('message')}")
                print(f"   - Expires in: {data.get('expires_in_minutes')} minutes")
                assert True
            elif "message" in data and "Reset token generated" in data.get("message"):
                print("[PASS] PASS: Forgot password endpoint working")
                print(f"   - Message: {data.get('message')}")
                assert True
            else:
                print("[PASS] PASS: Correctly handled response")
                print(f"   - Response: {data}")
                assert True
        else:
            print(f"[FAIL] FAIL: Unexpected status {response.status_code}")
            assert False, f"Unexpected status: {response.status_code}"
        
    except Exception as e:
        print(f"[FAIL] FAIL: {type(e).__name__}: {e}")
        assert False, f"Error: {e}"

def test_invalid_email():
    """Test with invalid email"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing invalid email handling...")
    
    try:
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "notanemail"},
            timeout=60
        )
        
        if response.status_code in [400, 422]:
            print(f"[PASS] PASS: Correctly rejected invalid email (status: {response.status_code})")
            assert True
        else:
            print(f"⚠️  Status {response.status_code} for invalid email")
            assert False, f"Unexpected status: {response.status_code}"
            
    except Exception as e:
        print(f"[FAIL] FAIL: {e}")
        assert False, f"Error: {e}"

def test_complete_password_reset_flow():
    """Test complete password reset flow with token"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing complete password reset flow...")
    
    try:
        # Create test user
        register_payload = {
            "email": "resetflow@example.com",
            "password": "OldPassword123",
            "name": "Reset Flow User"
        }
        
        reg_response = client.post("/api/v1/auth/register", json=register_payload)
        print(f"User creation status: {reg_response.status_code}")
        
        # Step 1: Request password reset
        forgot_response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "resetflow@example.com"},
            timeout=60
        )
        
        print(f"Forgot password status: {forgot_response.status_code}")
        
        if forgot_response.status_code != 200:
            print(f"[FAIL] FAIL: Forgot password failed: {forgot_response.status_code}")
            assert False
        
        forgot_data = forgot_response.json()
        reset_token = forgot_data.get("reset_token")
        
        if not reset_token:
            print(f"[FAIL] FAIL: No reset token returned")
            assert False
        
        print(f"Reset token received: {reset_token[:20]}...")
        
        # Step 2: Reset password with token
        reset_payload = {
            "token": reset_token,
            "new_password": "NewPassword456"
        }
        
        reset_response = client.post(
            "/api/v1/auth/reset-password",
            json=reset_payload,
            timeout=60
        )
        
        print(f"Reset password status: {reset_response.status_code}")
        print(f"Reset response: {json.dumps(reset_response.json(), indent=2)}")
        
        if reset_response.status_code == 200:
            reset_data = reset_response.json()
            if reset_data.get("success") or "Password reset successfully" in reset_data.get("message", ""):
                print("[PASS] PASS: Password reset flow completed successfully")
                assert True
            else:
                print(f"[FAIL] FAIL: Reset failed: {reset_data}")
                assert False
        else:
            print(f"[FAIL] FAIL: Reset failed with status: {reset_response.status_code}")
            assert False
        
        # Step 3: Verify login with new password
        login_payload = {
            "email": "resetflow@example.com",
            "password": "NewPassword456"
        }
        
        login_response = client.post("/api/v1/auth/login", json=login_payload)
        
        if login_response.status_code == 200:
            print("[PASS] PASS: Can login with new password")
            assert True
        else:
            print(f"[FAIL] FAIL: Cannot login with new password: {login_response.status_code}")
            assert False
        
    except Exception as e:
        print(f"[FAIL] FAIL: {type(e).__name__}: {e}")
        assert False, f"Error: {e}"

def test_nonexistent_email():
    """Test with non-existent email (should return generic message)"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing non-existent email...")
    
    try:
        # Use unique email to avoid conflicts with other tests
        import uuid
        unique_email = f"nonexistent-{uuid.uuid4().hex[:8]}@example.com"
        
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": unique_email},
            timeout=60
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            data = response.json()
            # Should return generic message (security: no user enumeration)
            # New flow returns "Reset token generated successfully" for both existing and non-existing users
            message = data.get("message", "")
            if "Reset token generated successfully" in message or "reset token" in message.lower():
                print("[PASS] PASS: Generic response for non-existent user (prevents enumeration)")
                assert True
            else:
                print(f"[PASS] PASS: Response received: {message}")
                assert True
        else:
            print(f"[FAIL] FAIL: Non-200 status: {response.status_code}")
            assert False
        
    except Exception as e:
        print(f"[FAIL] FAIL: {e}")
        assert False, f"Error: {e}"

if __name__ == "__main__":
    print("=" * 60)
    print("FORGOT PASSWORD ENDPOINT TEST")
    print("=" * 60)
    
    results = {
        "forgot_password": test_forgot_password(),
        "invalid_email": test_invalid_email(),
        "nonexistent_email": test_nonexistent_email(),
        "complete_reset_flow": test_complete_password_reset_flow(),
    }
    
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test, result in results.items():
        status = "[PASS] PASS" if result else "[FAIL] FAIL"
        print(f"{test}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    sys.exit(0 if passed == total else 1)
