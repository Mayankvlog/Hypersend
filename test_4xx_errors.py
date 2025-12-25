#!/usr/bin/env python3
"""Test 4xx HTTP error handling"""
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000/api/v1"
errors_tested = []

def test_error(code, name, method, endpoint, **kwargs):
    """Test an error code"""
    print(f"\n[{code}] Testing {name}...")
    try:
        if method == "GET":
            r = requests.get(f"{BASE_URL}{endpoint}", **kwargs)
        elif method == "POST":
            r = requests.post(f"{BASE_URL}{endpoint}", **kwargs)
        
        if r.status_code == code:
            print(f"  ✓ Got {code} as expected")
            print(f"  Response: {r.json()}")
            errors_tested.append((code, True))
        else:
            print(f"  ✗ Got {r.status_code} instead of {code}")
            errors_tested.append((code, False))
    except Exception as e:
        print(f"  ✗ Error: {e}")
        errors_tested.append((code, False))

print("=" * 80)
print("4xx CLIENT ERROR TESTING")
print(f"Testing: {BASE_URL}")
print("=" * 80)

# Test 400 Bad Request
test_error(400, "Bad Request", "POST", "/auth/register",
    json={"name": "User", "email": "invalid-email", "password": "Pass123!"},
    headers={"Content-Type": "application/json"})

# Test 401 Unauthorized
test_error(401, "Unauthorized", "GET", "/users/me",
    headers={})

# Test 404 Not Found
test_error(404, "Not Found", "GET", "/chats/nonexistent_id",
    headers={"Authorization": "Bearer fake-token"})

# Test 409 Conflict (duplicate email)
test_error(409, "Conflict", "POST", "/auth/register",
    json={"name": "User", "email": "duplicate@test.com", "password": "Pass123!"},
    headers={"Content-Type": "application/json"})

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
print("SUMMARY")
print("=" * 80)
for code, passed in errors_tested:
    status = "✓" if passed else "✗"
    print(f"{status} {code}")
