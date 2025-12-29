#!/usr/bin/env python3
"""
Test Forgot Password Endpoint
Validates the password reset flow and security
"""
import requests
import json
import sys
from datetime import datetime

API_URL = "http://localhost:8000/api/v1"
TEST_EMAIL = "mobimix33@gmail.com"

def test_forgot_password():
    """Test forgot-password endpoint"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing /forgot-password endpoint...")
    
    try:
        response = requests.post(
            f"{API_URL}/auth/forgot-password",
            json={"email": TEST_EMAIL},
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                print("✅ PASS: Forgot password endpoint working")
                print(f"   - Email sent: {data.get('email_sent')}")
                print(f"   - Message: {data.get('message')}")
                return True
        
        print(f"❌ FAIL: Unexpected status {response.status_code}")
        return False
        
    except requests.exceptions.ConnectionError:
        print("❌ FAIL: Cannot connect to server. Is it running?")
        print(f"   URL: {API_URL}")
        return False
    except Exception as e:
        print(f"❌ FAIL: {type(e).__name__}: {e}")
        return False

def test_invalid_email():
    """Test with invalid email"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing invalid email handling...")
    
    try:
        response = requests.post(
            f"{API_URL}/auth/forgot-password",
            json={"email": "notanemail"},
            timeout=10
        )
        
        if response.status_code in [400, 422]:
            print(f"✅ PASS: Correctly rejected invalid email (status: {response.status_code})")
            return True
        else:
            print(f"⚠️  Status {response.status_code} for invalid email")
            return False
            
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

def test_nonexistent_email():
    """Test with non-existent email (should return generic message)"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Testing non-existent email...")
    
    try:
        response = requests.post(
            f"{API_URL}/auth/forgot-password",
            json={"email": "nonexistent@example.com"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            # Should return generic message (security: no user enumeration)
            if "If an account exists" in data.get("message", ""):
                print("✅ PASS: Generic response (prevents user enumeration)")
                return True
        
        print(f"⚠️  Status {response.status_code}")
        return False
        
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

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
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    sys.exit(0 if passed == total else 1)
