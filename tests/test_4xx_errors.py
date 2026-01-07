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
    r = requests.get(
        f"{BASE_URL}/chats/nonexistent_id",
        headers={"Authorization": "Bearer fake-token"},
        timeout=5,
    )
    assert r.status_code == 404


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
    r = requests.post(
        f"{BASE_URL}/files/init",
        headers={"Content-Length": "6000000000", "Authorization": "Bearer fake-token"},
        json={},
        timeout=5,
    )
    assert r.status_code == 413


def test_414_uri_too_long(require_server):
    long_url = "x" * 9000
    r = requests.get(
        f"{BASE_URL}/chats?q={long_url}",
        headers={"Authorization": "Bearer fake-token"},
        timeout=5,
    )
    assert r.status_code == 414


def test_422_unprocessable_entity(require_server):
    r = requests.post(
        f"{BASE_URL}/auth/register",
        json={"name": "User", "email": "user@example.com"},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    assert r.status_code == 422
