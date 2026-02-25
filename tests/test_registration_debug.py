#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models import UserCreate
from auth.utils import hash_password

def test_registration_components():
    print("Testing registration components...")
    
    # Test UserCreate model
    try:
        user_data = {
            "email": "test@example.com",
            "password": "TestPassword123",
            "username": "testuser"
        }
        user = UserCreate(**user_data)
        print(f"✅ UserCreate model works: {user}")
    except Exception as e:
        print(f"❌ UserCreate model failed: {e}")
        return
    
    # Test password hashing
    try:
        password_hash, salt = hash_password(user.password)
        print(f"✅ Password hashing works: hash_len={len(password_hash)}, salt_len={len(salt)}")
    except Exception as e:
        print(f"❌ Password hashing failed: {e}")
        return
    
    print("✅ All components work individually")

if __name__ == "__main__":
    test_registration_components()
