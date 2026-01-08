"""
Quick validation test to verify all models are working correctly
Run this to test: python backend/test_validation.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

try:
    from models import (
        UserCreate, UserLogin, UserInDB, ProfileUpdate,
        EmailChangeRequest, ForgotPasswordRequest
    )
except ImportError:
    pytest.skip("Models not available", allow_module_level=True)

from datetime import datetime
import pytest

def test_user_create():
    """Test UserCreate validation"""
    print("Testing UserCreate...")
    
    # Valid case
    try:
        user = UserCreate(
            name="John Doe",
            email="john@example.com",
            password="MyPassword123"
        )
        print(f"  [PASS] Valid user created: {user.email}")
    except Exception as e:
        assert False, f"Error: {e}"
    
    # Invalid email
    with pytest.raises(Exception):
        UserCreate(
            name="John",
            email="invalid-email",
            password="password"
        )
    print(f"  [PASS] Correctly rejected invalid email")

def test_user_login():
    """Test UserLogin validation"""
    print("\nTesting UserLogin...")
    
    # Valid case
    try:
        login = UserLogin(
            email="john@example.com",
            password="MyPassword123"
        )
        print(f"  [PASS] Valid login: {login.email}")
    except Exception as e:
        assert False, f"Error: {e}"

def test_profile_update():
    """Test ProfileUpdate validation"""
    print("\nTesting ProfileUpdate...")
    
    # Valid case - only update name with username
    try:
        update = ProfileUpdate(
            name="Jane Doe",
            username="janedoe",
            email=None
        )
        print(f"  [PASS] Valid profile update: name={update.name}")
    except Exception as e:
        assert False, f"Error: {e}"
    
    # Valid case - update email with username
    try:
        update = ProfileUpdate(
            email="newemail@example.com",
            username="janedoe"
        )
        print(f"  [PASS] Valid email update: {update.email}")
    except Exception as e:
        assert False, f"Error: {e}"
    
    # Invalid username (too short)
    with pytest.raises(Exception):
        ProfileUpdate(
            username="ab",  # Only 2 chars, needs 3+
            name="Test User"
        )
    print(f"  [PASS] Correctly rejected short username")

def test_email_change():
    """Test EmailChangeRequest validation"""
    print("\nTesting EmailChangeRequest...")
    
    # Valid case
    try:
        request = EmailChangeRequest(
            email="newemail@example.com",
            password="CurrentPassword123"
        )
        print(f"  [PASS] Valid email change request: {request.email}")
    except Exception as e:
        assert False, f"Error: {e}"

def test_forgot_password():
    """Test ForgotPasswordRequest validation"""
    print("\nTesting ForgotPasswordRequest...")
    
    # Valid case
    try:
        request = ForgotPasswordRequest(
            email="john@example.com"
        )
        print(f"  [PASS] Valid forgot password request: {request.email}")
    except Exception as e:
        assert False, f"Error: {e}"

if __name__ == "__main__":
    print("=" * 60)
    print("VALIDATION TESTS FOR ALL MODELS")
    print("=" * 60)
    
    results = []
    results.append(("UserCreate", test_user_create()))
    results.append(("UserLogin", test_user_login()))
    results.append(("ProfileUpdate", test_profile_update()))
    results.append(("EmailChangeRequest", test_email_change()))
    results.append(("ForgotPasswordRequest", test_forgot_password()))
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    for model_name, passed in results:
        status = "[PASS] PASSED" if passed else "[FAIL] FAILED"
        print(f"{model_name}: {status}")
    
    all_passed = all(r[1] for r in results)
    print("\n" + ("=" * 60))
    if all_passed:
        print("[PASS] ALL TESTS PASSED - Models are working correctly!")
    else:
        print("[FAIL] SOME TESTS FAILED - Check errors above")
    print("=" * 60)
    
    sys.exit(0 if all_passed else 1)
