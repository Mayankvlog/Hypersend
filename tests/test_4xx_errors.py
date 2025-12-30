#!/usr/bin/env python3
"""Test 4xx HTTP error handling - 401 Unauthorized and 409 Conflict"""
import requests
import json
from datetime import datetime
import time

BASE_URL = "http://localhost:8000/api/v1"
errors_tested = []

def test_error(code, name, method, endpoint, **kwargs):
    """Test an error code"""
    print(f"\n[{code}] Testing {name}...")
    try:
        if method == "GET":
            r = requests.get(f"{BASE_URL}{endpoint}", timeout=5, **kwargs)
        elif method == "POST":
            r = requests.post(f"{BASE_URL}{endpoint}", timeout=5, **kwargs)
        
        if r.status_code == code:
            print(f"  [PASS] Got {code} as expected")
            data = r.json()
            print(f"  Error: {data.get('error')}")
            print(f"  Detail: {data.get('detail')}")
            errors_tested.append((code, True, data))
        else:
            print(f"  [FAIL] Got {r.status_code} instead of {code}")
            errors_tested.append((code, False, {"status": r.status_code}))
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        errors_tested.append((code, False, {"error": str(e)}))

print("=" * 80)
print("4xx CLIENT ERROR TESTING - 401 & 409 FOCUS")
print(f"Testing: {BASE_URL}")
print("=" * 80)

# Wait for server to be ready
print("\n[SCAN] Checking server availability...")
for attempt in range(3):
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=2)
        print("[PASS] Server is ready")
        break
    except:
        if attempt < 2:
            print(f"⏳ Waiting for server... (attempt {attempt+1}/3)")
            time.sleep(2)
        else:
            print("[FAIL] Server not responding - aborting tests")
            exit(1)

# Test 400 Bad Request
test_error(400, "Bad Request", "POST", "/auth/register",
    json={"name": "User", "email": "invalid-email", "password": "Pass123!"},
    headers={"Content-Type": "application/json"})

# Test 401 Unauthorized - Missing token
test_error(401, "Unauthorized (Missing Token)", "GET", "/users/me",
    headers={})

# Test 401 Unauthorized - Invalid token
test_error(401, "Unauthorized (Invalid Token)", "GET", "/users/me",
    headers={"Authorization": "Bearer invalid.token.here"})

# Test 404 Not Found
test_error(404, "Not Found", "GET", "/chats/nonexistent_id",
    headers={"Authorization": "Bearer fake-token"})

# Test 409 Conflict (duplicate email)
print("\n--- Testing 409 Conflict (Duplicate Email) ---")
email = f"test_{int(datetime.now().timestamp())}@example.com"
print(f"Registering first user with email: {email}")
try:
    r1 = requests.post(f"{BASE_URL}/auth/register",
        json={"name": "User1", "email": email, "password": "Pass123!"},
        headers={"Content-Type": "application/json"},
        timeout=5)
    print(f"First registration: {r1.status_code}")
    
    if r1.status_code == 201:
        print(f"[PASS] First user created successfully")
        print(f"Now attempting duplicate email registration...")
        test_error(409, "Conflict (Duplicate Email)", "POST", "/auth/register",
            json={"name": "User2", "email": email, "password": "Different123!"},
            headers={"Content-Type": "application/json"})
    else:
        print(f"⚠ First registration failed: {r1.status_code}")
except Exception as e:
    print(f"Error testing 409: {e}")

# Test 413 Payload Too Large
test_error(413, "Payload Too Large", "POST", "/files/init",
    headers={"Content-Length": "6000000000", "Authorization": "Bearer fake-token"},
    json={})

# Test 414 URI Too Long
long_url = "x" * 9000
test_error(414, "URI Too Long", "GET", f"/chats?q={long_url}",
    headers={"Authorization": "Bearer fake-token"})

# Test 422 Unprocessable Entity
test_error(422, "Unprocessable Entity", "POST", "/auth/register",
    json={"name": "User", "email": "user@example.com"},  # Missing password
    headers={"Content-Type": "application/json"})

print("\n" + "=" * 80)
print("TEST SUMMARY")
print("=" * 80)
passed_count = sum(1 for _, passed, _ in errors_tested if passed)
failed_count = sum(1 for _, passed, _ in errors_tested if not passed)
print(f"[PASS] Passed: {passed_count}")
print(f"[FAIL] Failed: {failed_count}")
print(f"Total: {len(errors_tested)}")
print("=" * 80)
