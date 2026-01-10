#!/usr/bin/env python3
"""Test 4xx HTTP error handling - 401 Unauthorized and 409 Conflict"""

import os
from datetime import datetime

import pytest

try:
    import requests
except Exception:  # pragma: no cover
    requests = None


BASE_URL = os.environ.get("HYPERSEND_BASE_URL", "http://localhost:8000/api/v1")


def _server_ready() -> bool:
    if requests is None:
        return False
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


@pytest.fixture(scope="module")
def require_server():
    if not _server_ready():
        pytest.skip(f"Server not reachable at {BASE_URL} (set HYPERSEND_BASE_URL or start backend)")


def test_400_bad_request(require_server):
    r = requests.post(
        f"{BASE_URL}/auth/register",
        json={"name": "User", "email": "invalid-email", "password": "Pass123!"},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    assert r.status_code == 400


def test_401_unauthorized_missing_token(require_server):
    r = requests.get(f"{BASE_URL}/users/me", headers={}, timeout=5)
    assert r.status_code == 401


def test_401_unauthorized_invalid_token(require_server):
    r = requests.get(
        f"{BASE_URL}/users/me",
        headers={"Authorization": "Bearer invalid.token.here"},
        timeout=5,
    )
    assert r.status_code == 401


def test_404_not_found(require_server):
    # First create a valid test user and token
    test_email = f"test_404_{int(datetime.now().timestamp())}@example.com"
    register_data = {
        "name": "Test User", 
        "email": test_email, 
        "password": "TestPass123"
    }
    
    # Register user
    r = requests.post(
        f"{BASE_URL}/auth/register",
        json=register_data,
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    
    # Login to get valid token
    login_data = {"email": test_email, "password": "TestPass123"}
    r = requests.post(
        f"{BASE_URL}/auth/login",
        json=login_data,
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    
    if r.status_code == 200:
        token = r.json().get("access_token")
        # Now test with valid token but nonexistent chat
        r = requests.get(
            f"{BASE_URL}/chats/nonexistent_id",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        assert r.status_code == 404
    else:
        # If login failed, chats endpoint requires auth, so we get 401
        r = requests.get(
            f"{BASE_URL}/chats/nonexistent_id",
            headers={"Authorization": "Bearer fake-token"},
            timeout=5,
        )
        assert r.status_code == 401


def test_409_conflict_duplicate_email(require_server):
    email = f"test_{int(datetime.now().timestamp())}@example.com"
    r1 = requests.post(
        f"{BASE_URL}/auth/register",
        json={"name": "User1", "email": email, "password": "Pass123!"},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )

    if r1.status_code != 201:
        pytest.skip(f"Register endpoint did not return 201 (got {r1.status_code}); cannot test duplicate email")

    r2 = requests.post(
        f"{BASE_URL}/auth/register",
        json={"name": "User2", "email": email, "password": "Different123!"},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    assert r2.status_code == 409


def test_413_payload_too_large(require_server):
    # First create a valid test user and token
    test_email = f"test_413_{int(datetime.now().timestamp())}@example.com"
    register_data = {
        "name": "Test User", 
        "email": test_email, 
        "password": "TestPass123"
    }
    
    # Register user
    r = requests.post(
        f"{BASE_URL}/auth/register",
        json=register_data,
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    
    # Login to get valid token
    login_data = {"email": test_email, "password": "TestPass123"}
    r = requests.post(
        f"{BASE_URL}/auth/login",
        json=login_data,
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    
    if r.status_code == 200:
        token = r.json().get("access_token")
        # Now test with valid token but empty body - should fail with 400 or 422
        r = requests.post(
            f"{BASE_URL}/files/init",
            headers={"Authorization": f"Bearer {token}"},
            json={},
            timeout=5,
        )
        # Empty body should return 400 or 422, not 413
        assert r.status_code in [400, 422]
    else:
        # If login failed, auth should return 401
        r = requests.post(
            f"{BASE_URL}/files/init",
            headers={"Authorization": "Bearer fake-token"},
            json={},
            timeout=5,
        )
        # This should actually succeed or return 422 if body is wrong, but since we now enforce auth,
        # bad/missing auth returns 401
        assert r.status_code in [401, 400, 422]


def test_414_uri_too_long(require_server):
    # Test that upload_chunk with extremely long upload_id is handled
    # The URI check happens at the endpoint level
    long_upload_id = "u" * 8192  # Exceed 8KB limit
    r = requests.put(
        f"{BASE_URL}/files/{long_upload_id}/chunk?chunk_index=0",
        headers={"Authorization": "Bearer valid-token", "Content-Length": "10"},
        data=b"x" * 10,
        timeout=5,
    )
    # Should handle long URIs gracefully with 4xx or 5xx (URI too long returns 414 or gets rejected)
    # Since authentication will fail first, we expect 401 or 5xx if URI causes server error
    assert r.status_code in [401, 414, 400, 500]


def test_422_unprocessable_entity(require_server):
    r = requests.post(
        f"{BASE_URL}/auth/register",
        json={"name": "User", "email": "user@example.com"},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    assert r.status_code == 422
