"""
Debug test to identify authentication flow issues
"""
import pytest
import json
from backend.auth.utils import (
    create_access_token, decode_token, verify_password, hash_password
)
from backend.config import settings
from datetime import timedelta


def test_token_creation_and_validation():
    """Test that tokens created with one SECRET_KEY can be validated with the same key"""
    print(f"\n[DEBUG] SECRET_KEY length: {len(settings.SECRET_KEY)}")
    print(f"[DEBUG] ALGORITHM: {settings.ALGORITHM}")
    
    # Verify SECRET_KEY is properly configured
    assert len(settings.SECRET_KEY) >= 32, "SECRET_KEY should be at least 32 characters"
    
    # Create a test token
    test_user_id = "507f1f77bcf86cd799439011"  # Valid MongoDB ObjectId format
    token = create_access_token(
        data={"sub": test_user_id},
        expires_delta=timedelta(minutes=30)
    )
    
    print(f"[DEBUG] Created token: {token[:50]}...")
    
    # Try to decode it immediately with the same settings
    try:
        token_data = decode_token(token)
        print(f"[DEBUG] Token decoded successfully: user_id={token_data.user_id}, type={token_data.token_type}")
        assert token_data.user_id == test_user_id
        assert token_data.token_type == "access"
    except Exception as e:
        print(f"[ERROR] Token validation failed: {type(e).__name__}: {e}")
        raise


def test_password_hashing_and_verification():
    """Test password hashing and verification"""
    password = "Test@123"
    
    # Hash password
    password_hash, salt = hash_password(password)
    print("[DEBUG] Password hashing completed")
    
    # Verify hashing succeeded
    assert password_hash is not None, "Password hash should not be None"
    assert salt is not None, "Salt should not be None"
    assert len(password_hash) > 0, "Password hash should not be empty"
    assert len(salt) > 0, "Salt should not be empty"
    
    # Verify with same password
    is_valid = verify_password(password, password_hash, salt, user_id="test_user")
    print(f"[DEBUG] Password verification (correct password): {is_valid}")
    assert is_valid, "Password verification should succeed with correct password"
    
    # Verify with wrong password
    is_valid_wrong = verify_password("WrongPassword", password_hash, salt, user_id="test_user")
    print(f"[DEBUG] Password verification (wrong password): {is_valid_wrong}")
    assert not is_valid_wrong, "Password verification should fail with wrong password"


def test_combined_password_format():
    """Test combined password format (salt$hash)"""
    password = "Test@123"
    password_hash, salt = hash_password(password)
    
    # Combine into legacy format
    combined = f"{salt}${password_hash}"
    print(f"\n[DEBUG] Combined password format: {combined[:50]}...")
    
    # Verify with combined format (None for salt parameter)
    is_valid = verify_password(password, combined, None, user_id="test_user")
    print(f"[DEBUG] Combined format verification: {is_valid}")
    assert is_valid, "Combined format should still verify correctly"


if __name__ == "__main__":
    test_token_creation_and_validation()
    test_password_hashing_and_verification()
    test_combined_password_format()
    print("\n[DEBUG] All local tests passed!")
