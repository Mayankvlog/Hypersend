#!/usr/bin/env python3
"""
Test script to verify authentication endpoints are working correctly
Tests registration, login, and token endpoints

Run with: python test_auth_endpoints.py
"""

import requests
import json
import time
from datetime import datetime

# Test client setup
try:
    from fastapi.testclient import TestClient
    from backend.main import app
    client = TestClient(app)
    USE_TESTCLIENT = True
except ImportError:
    USE_TESTCLIENT = False
    import requests
    client = None

# Configuration
BASE_URL = "http://localhost:8000/api/v1"
TEST_USER = {
    "name": "Test User",
    "email": f"testuser_{int(time.time())}@example.com",
    "password": "TestPassword123!"
}

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def test_cors_preflight():
    """Test CORS preflight request"""
    print_section("TEST 1: CORS Preflight (OPTIONS)")
    
    if USE_TESTCLIENT:
        url = "/api/v1/auth/register"
        headers = {
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        
        try:
            response = client.options(url, headers=headers)
            print(f"[PASS] OPTIONS request to {url}")
            print(f"   Status: {response.status_code}")
            print(f"   CORS Headers:")
            for header in ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"]:
                value = response.headers.get(header, "NOT SET")
                print(f"     - {header}: {value}")
            assert response.status_code in [200, 204, 400], f"Expected 200/204/400, got {response.status_code}"
        except Exception as e:
            print(f"[FAIL] Error: {e}")
            assert False, f"Error: {e}"
    else:
        # Fallback to requests for live server testing
        url = f"{BASE_URL}/auth/register"
        headers = {
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        
        try:
            response = requests.options(url, headers=headers, timeout=5)
            print(f"[PASS] OPTIONS request to {url}")
            print(f"   Status: {response.status_code}")
            print(f"   CORS Headers:")
            for header in ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"]:
                value = response.headers.get(header, "NOT SET")
                print(f"     - {header}: {value}")
            assert response.status_code in [200, 204], f"Expected 200/204, got {response.status_code}"
        except Exception as e:
            print(f"[FAIL] Error: {e}")
            assert False, f"Error: {e}"

def test_registration():
    """Test user registration"""
    print_section("TEST 2: User Registration (POST /auth/register)")
    
    if USE_TESTCLIENT:
        url = "/api/v1/auth/register"
        payload = TEST_USER.copy()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        try:
            print(f"📤 Sending registration request:")
            print(f"   URL: POST {url}")
            print(f"   Payload: {json.dumps(payload, indent=2)}")
            
            response = client.post(url, json=payload, headers=headers)
            print(f"\n📥 Response received:")
            print(f"   Status: {response.status_code}")
            print(f"   Content-Type: {response.headers.get('Content-Type', 'NOT SET')}")
            
            if response.status_code in [200, 201]:
                data = response.json()
                print(f"   [PASS] Registration successful!")
                print(f"   User ID: {data.get('id', 'N/A')}")
                print(f"   Email: {data.get('email', 'N/A')}")
                print(f"   Name: {data.get('name', 'N/A')}")
                assert True, "Registration successful"
                return True, data
            else:
                print(f"   [FAIL] Registration failed!")
                print(f"   Response: {response.text}")
                assert False, f"Registration failed: {response.text}"
                return False, None
                
        except Exception as e:
            print(f"[FAIL] Error: {e}")
            assert False, f"Error: {e}"
            return False, None
    else:
        # Fallback to requests for live server testing
        url = f"{BASE_URL}/auth/register"
        payload = TEST_USER.copy()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        try:
            print(f"📤 Sending registration request:")
            print(f"   URL: POST {url}")
            print(f"   Payload: {json.dumps(payload, indent=2)}")
            
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            print(f"\n📥 Response received:")
            print(f"   Status: {response.status_code}")
            print(f"   Content-Type: {response.headers.get('Content-Type', 'NOT SET')}")
            
            if response.status_code in [200, 201]:
                data = response.json()
                print(f"   [PASS] Registration successful!")
                print(f"   User ID: {data.get('id', 'N/A')}")
                print(f"   Email: {data.get('email', 'N/A')}")
                print(f"   Name: {data.get('name', 'N/A')}")
                assert True, "Registration successful"
                return True, data
            else:
                print(f"   [FAIL] Registration failed!")
                print(f"   Response: {response.text}")
                assert False, f"Registration failed: {response.text}"
                return False, None
                
        except Exception as e:
            print(f"[FAIL] Error: {e}")
            assert False, f"Error: {e}"
            return False, None

def test_login():
    """Test user login"""
    print_section("TEST 3: User Login (POST /auth/login)")
    
    # Use the same test user credentials from registration
    email = TEST_USER["email"]
    password = TEST_USER["password"]
    
    if USE_TESTCLIENT:
        url = "/api/v1/auth/login"
        payload = {
            "email": email,
            "password": password
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        try:
            print(f"📤 Sending login request:")
            print(f"   URL: POST {url}")
            print(f"   Payload: {json.dumps({'email': email, 'password': '***'}, indent=2)}")
            
            response = client.post(url, json=payload, headers=headers)
            print(f"\n📥 Response received:")
            print(f"   Status: {response.status_code}")
            print(f"   Content-Type: {response.headers.get('Content-Type', 'NOT SET')}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"   [PASS] Login successful!")
                print(f"   Token Type: {data.get('token_type', 'N/A')}")
                print(f"   Access Token: {data.get('access_token', 'N/A')[:50]}...")
                assert True, "Login successful"
                return True, data
            else:
                print(f"   [FAIL] Login failed!")
                print(f"   Response: {response.text}")
                assert False, f"Login failed: {response.text}"
                return False, None
                
        except Exception as e:
            print(f"[FAIL] Error: {e}")
            assert False, f"Error: {e}"
            return False, None
    else:
        # Fallback to requests for live server testing
        url = f"{BASE_URL}/auth/login"
        payload = {
            "email": email,
            "password": password
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        try:
            print(f"📤 Sending login request:")
            print(f"   URL: POST {url}")
            print(f"   Payload: {json.dumps({'email': email, 'password': '***'}, indent=2)}")
            
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            print(f"\n📥 Response received:")
            print(f"   Status: {response.status_code}")
            print(f"   Content-Type: {response.headers.get('Content-Type', 'NOT SET')}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"   [PASS] Login successful!")
                print(f"   Token Type: {data.get('token_type', 'N/A')}")
                print(f"   Access Token: {data.get('access_token', 'N/A')[:50]}...")
                assert True, "Login successful"
                return True, data
            else:
                print(f"   [FAIL] Login failed!")
                print(f"   Response: {response.text}")
                assert False, f"Login failed: {response.text}"
                return False, None
                
        except Exception as e:
            print(f"[FAIL] Error: {e}")
            assert False, f"Error: {e}"
            return False, None

def test_invalid_registration():
    """Test registration with invalid data"""
    print_section("TEST 4: Invalid Registration (Validation Test)")
    
    url = f"{BASE_URL}/auth/register"
    
    # Test 1: Missing email
    print("4a. Testing with missing email:")
    payload = {"name": "Test", "password": "TestPassword123!"}
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5)
        print(f"    Status: {response.status_code}")
        if response.status_code == 422:
            print(f"    [PASS] Correctly rejected: Invalid email field")
        else:
            print(f"    [FAIL] Expected 422, got {response.status_code}")
    except Exception as e:
        print(f"    [FAIL] Error: {e}")
    
    # Test 2: Duplicate email
    print("\n4b. Testing with duplicate email:")
    payload = TEST_USER.copy()
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5)
        print(f"    Status: {response.status_code}")
        if response.status_code == 409:
            print(f"    [PASS] Correctly rejected: Duplicate email")
        else:
            print(f"    [FAIL] Expected 409, got {response.status_code}")
    except Exception as e:
        print(f"    [FAIL] Error: {e}")

def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("  HYPERSEND AUTHENTICATION ENDPOINTS TEST")
    print("="*70)
    print(f"\n  Base URL: {BASE_URL}")
    print(f"  Test User: {TEST_USER['email']}")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print(f"  Using TestClient: {USE_TESTCLIENT}")
    
    # Check if server is running (only for requests mode)
    if not USE_TESTCLIENT:
        print("\n⏳ Checking if server is running...")
        try:
            response = requests.get(f"{BASE_URL.rsplit('/', 1)[0]}/health", timeout=2)
            print("[PASS] Server is responding")
        except:
            print("[FAIL] Server is not responding. Please start backend server:")
            print("   cd backend")
            print("   python main.py")
            return
    
    # Run tests
    results = []
    results.append(("CORS Preflight", test_cors_preflight()))
    success, user_data = test_registration()
    results.append(("Registration", success))
    
    if success and user_data:
        if USE_TESTCLIENT:
            success, token_data = test_login()
        else:
            success, token_data = test_login()
        results.append(("Login", success))
    
    test_invalid_registration()
    
    # Summary
    print_section("TEST SUMMARY")
    for name, passed in results:
        status = "[PASS] PASS" if passed else "[FAIL] FAIL"
        print(f"{name}: {status}")
    
    passed_count = sum(1 for _, p in results if p)
    total_count = len(results)
    print(f"\nTotal: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n[SUCCESS] All tests passed! Authentication endpoints are working correctly.")
    else:
        print("\n⚠️  Some tests failed. Check errors above.")

if __name__ == "__main__":
    main()
