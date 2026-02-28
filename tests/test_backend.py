import pytest
from import_helper import get_test_app, get_auth_utils
from fastapi.testclient import TestClient

# Get test app and auth utilities
app = get_test_app()
hash_password, verify_password, get_current_user = get_auth_utils()


client = TestClient(app) if app else None


def test_read_root():
    if not client:
        pytest.skip("Test client not available")
    response = client.get("/")
    assert response.status_code == 200


def test_health_check():
    if not client:
        pytest.skip("Test client not available")
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] in ["healthy", "degraded", "unhealthy"]
    assert "services" in data
    assert "database" in data["services"]
    assert "cache" in data["services"]


def test_favicon():
    if not client:
        pytest.skip("Test client not available")
    response = client.get("/favicon.ico")
    assert response.status_code in [200, 204]


def test_password_hash_generation():
    if not hash_password:
        pytest.skip("hash_password function not available")
    
    password = "TestPassword123!"
    
    # Use the already imported hash_password function
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
    """Test password verification success"""
    # Skip if auth utilities not available
    if not hash_password or not verify_password:
        pytest.skip("Password utilities not available")
    
    password = "MySecurePassword123"
    
    # Use the already imported functions
    combined = hash_password(password)
    assert verify_password(password, combined) is True


def test_password_verification_failure():
    """Test password verification failure"""
    # Skip if auth utilities not available
    if not hash_password or not verify_password:
        pytest.skip("Password utilities not available")
    
    password = "MySecurePassword123"
    wrong_password = "WrongPassword123"
    
    # Use the already imported functions
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