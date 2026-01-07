import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth.utils import hash_password, verify_password


client = TestClient(app)


def test_read_root():
    response = client.get("/")
    assert response.status_code == 200


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_favicon():
    response = client.get("/favicon.ico")
    assert response.status_code in [200, 204]


def test_password_hash_generation():
    password = "TestPassword123!"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    assert hash1 != hash2
    assert "$" in hash1
    assert "$" in hash2

    parts1 = hash1.split("$")
    assert len(parts1) == 2
    assert len(parts1[0]) == 32
    assert len(parts1[1]) == 64


def test_password_verification_success():
    password = "MySecurePassword123"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True


def test_password_verification_failure():
    password = "MySecurePassword123"
    wrong_password = "WrongPassword123"
    hashed = hash_password(password)
    assert verify_password(wrong_password, hashed) is False


def test_password_verification_invalid_hash():
    password = "MySecurePassword123"
    invalid_hash = "not_a_valid_hash"
    assert verify_password(password, invalid_hash) is False


def test_password_verification_empty_password():
    hashed = hash_password("SomePassword")
    assert verify_password("", hashed) is False
    assert verify_password(None, hashed) is False