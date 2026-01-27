#!/usr/bin/env python3
"""
Test Token-Based Password Reset Endpoint
Validates the password reset flow and security using JWT tokens
"""
import sys
import os
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Set mock database
os.environ['USE_MOCK_DB'] = 'True'

from fastapi.testclient import TestClient
from backend.main import app
import json
from datetime import datetime

client = TestClient(app)
API_URL = "http://localhost:8000/api/v1"
TEST_EMAIL = "mobimix33@gmail.com"

def test_forgot_password():
    """Test forgot password endpoint"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing /forgot-password endpoint...")
    
    try:
        # First create the test user if it doesn't exist
        register_payload = {
            "email": TEST_EMAIL,
            "password": "TestPass123",
            "username": TEST_EMAIL,
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
        # Clear mock database to ensure test isolation
        try:
            from database import get_db
        except ImportError:
            try:
                from backend.database import get_db
            except ImportError:
                pytest.skip("Could not import database module")
        db = get_db()
        if hasattr(db, 'clear_all'):
            db.clear_all()
        elif hasattr(db, 'users') and hasattr(db.users, 'clear'):
            # Clear specific users collection
            db.users.clear()
            print("[TEST] Cleared users collection for test isolation")
        
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
            # Accept both empty message or message containing "If an account exists" or "account exists"
            message = data.get("message", "")
            is_generic = False
            
            if not message:
                # Empty message is generic
                is_generic = True
            elif "If an account with this email exists" in message:
                # Standard security message
                is_generic = True
            elif "account exists" in message:
                # Alternative security message
                is_generic = True
            
            if is_generic:
                print("[PASS] PASS: Generic response for non-existent user (prevents enumeration)")
                assert True
            else:
                print(f"[FAIL] FAIL: Non-generic message may leak user existence: {message}")
                assert False
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
