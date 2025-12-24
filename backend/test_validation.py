"""
Quick validation test to verify all models are working correctly
Run this to test: python backend/test_validation.py
"""

import sys
sys.path.insert(0, '.')

from backend.models import (
    UserCreate, UserLogin, UserInDB, ProfileUpdate,
    EmailChangeRequest, ForgotPasswordRequest
)
from datetime import datetime

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
        print(f"  ✅ Valid user created: {user.email}")
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
    
    # Invalid email
    try:
        user = UserCreate(
            name="John",
            email="invalid-email",
            password="password"
        )
        print(f"  ❌ Invalid email should have failed!")
        return False
    except Exception as e:
        print(f"  ✅ Correctly rejected invalid email: {e}")
    
    return True

def test_user_login():
    """Test UserLogin validation"""
    print("\nTesting UserLogin...")
    
    # Valid case
    try:
        login = UserLogin(
            email="john@example.com",
            password="MyPassword123"
        )
        print(f"  ✅ Valid login: {login.email}")
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
    
    return True

def test_profile_update():
    """Test ProfileUpdate validation"""
    print("\nTesting ProfileUpdate...")
    
    # Valid case - only update name
    try:
        update = ProfileUpdate(
            name="Jane Doe",
            username=None,
            email=None
        )
        print(f"  ✅ Valid profile update: name={update.name}")
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
    
    # Valid case - update email
    try:
        update = ProfileUpdate(
            email="newemail@example.com"
        )
        print(f"  ✅ Valid email update: {update.email}")
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
    
    # Invalid username (too short)
    try:
        update = ProfileUpdate(
            username="ab"  # Only 2 chars, needs 3+
        )
        print(f"  ❌ Short username should have failed!")
        return False
    except Exception as e:
        print(f"  ✅ Correctly rejected short username")
    
    return True

def test_email_change():
    """Test EmailChangeRequest validation"""
    print("\nTesting EmailChangeRequest...")
    
    # Valid case
    try:
        request = EmailChangeRequest(
            email="newemail@example.com",
            password="CurrentPassword123"
        )
        print(f"  ✅ Valid email change request: {request.email}")
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
    
    return True

def test_forgot_password():
    """Test ForgotPasswordRequest validation"""
    print("\nTesting ForgotPasswordRequest...")
    
    # Valid case
    try:
        request = ForgotPasswordRequest(
            email="john@example.com"
        )
        print(f"  ✅ Valid forgot password request: {request.email}")
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
    
    return True

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
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{model_name}: {status}")
    
    all_passed = all(r[1] for r in results)
    print("\n" + ("=" * 60))
    if all_passed:
        print("✅ ALL TESTS PASSED - Models are working correctly!")
    else:
        print("❌ SOME TESTS FAILED - Check errors above")
    print("=" * 60)
    
    sys.exit(0 if all_passed else 1)
