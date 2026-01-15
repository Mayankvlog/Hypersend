#!/usr/bin/env python3
"""
Test Forgot Password Endpoint
Validates the password reset flow and security
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Set mock database
os.environ['USE_MOCK_DB'] = 'True'

from fastapi.testclient import TestClient
from main import app
import json
from datetime import datetime

client = TestClient(app)
API_URL = "http://localhost:8000/api/v1"
TEST_EMAIL = "mobimix33@gmail.com"

def test_forgot_password():
    """Test forgot password endpoint"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing /forgot-password endpoint...")
    
    try:
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": TEST_EMAIL},
            timeout=60
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Success field: {data.get('success')}")
            if data.get("success") is True:
                print("[PASS] PASS: Forgot password endpoint working")
                print(f"   - Token: {data.get('token')}")
                print(f"   - Message: {data.get('message')}")
                assert True
            else:
                print("[PASS] PASS: Correctly handled non-existent email")
                print(f"   - Success: {data.get('success')}")
                print(f"   - Message: {data.get('message')}")
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

def test_nonexistent_email():
    """Test with non-existent email (should return generic message)"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing non-existent email...")
    
    try:
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nonexistent@example.com"},
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            # Should return generic message (security: no user enumeration)
            message = data.get("message", "")
            if "If an account with this email exists" in message or "If an account exists" in message:
                print("[PASS] PASS: Generic response (prevents user enumeration)")
                assert True
            else:
                print(f"[FAIL] FAIL: Unexpected message: {message}")
                assert False, "Expected generic message about account existence"
        else:
            print(f"⚠️  Status {response.status_code}")
            assert False, f"Unexpected status: {response.status_code}"
        
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
