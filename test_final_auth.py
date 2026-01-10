#!/usr/bin/env python3
"""
Comprehensive test to verify all authentication fixes
"""
import asyncio
import sys
import os
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

# Test with production-like settings
os.environ["USE_MOCK_DB"] = "False"
os.environ["DEBUG"] = "True"

async def test_comprehensive_auth():
    """Test comprehensive authentication flow"""
    print("🔍 Testing comprehensive authentication fixes...")
    
    try:
        from routes.auth import register, login
        from models import UserCreate, UserLogin
        from fastapi import Request
        
        print("\n1️⃣ Testing user registration...")
        test_user = UserCreate(
            name="Test User",
            email="test@zaply.in", 
            password="TestPass123"
        )
        
        class MockRequest:
            def __init__(self):
                self.client = type('Client', (), {'host': 'testclient'})()
        
        request = MockRequest()
        
        try:
            result = await register(test_user)
            print(f"✅ Registration successful: {result.email}")
            user_id = result.id
        except Exception as e:
            error_msg = str(e)
            if "Future" in error_msg or "get" in error_msg:
                print(f"❌ CRITICAL: Future object error: {error_msg}")
                return False
            elif "Database" in error_msg or "connection" in error_msg.lower():
                print(f"⚠️ Database connection issue (expected in test): {error_msg}")
                user_id = "test-id"  # Mock for testing login
            else:
                print(f"⚠️ Other registration issue: {error_msg}")
                return False
        
        print("\n2️⃣ Testing user login...")
        login_data = UserLogin(
            email="test@zaply.in",
            password="TestPass123"
        )
        
        try:
            token_result = await login(login_data, request)
            print(f"✅ Login successful: Token received")
            print(f"   Token type: {token_result.token_type}")
            print(f"   Access token length: {len(token_result.access_token)}")
        except Exception as e:
            error_msg = str(e)
            if "Future" in error_msg or "get" in error_msg:
                print(f"❌ CRITICAL: Future object error in login: {error_msg}")
                return False
            else:
                print(f"⚠️ Login issue: {error_msg}")
                return False
        
        print("\n3️⃣ Testing login with wrong password...")
        wrong_login = UserLogin(
            email="test@zaply.in",
            password="WrongPass123"
        )
        
        try:
            await login(wrong_login, request)
            print("❌ Should have rejected wrong password")
            return False
        except Exception as e:
            error_msg = str(e)
            if "Invalid email or password" in error_msg:
                print("✅ Wrong password correctly rejected")
            else:
                print(f"⚠️ Unexpected error: {error_msg}")
                return False
        
        print("\n🎉 All authentication tests passed!")
        print("✅ No Future object errors")
        print("✅ Registration logic working")
        print("✅ Login logic working")
        print("✅ Error handling working")
        return True
        
    except Exception as e:
        print(f"❌ Test setup failed: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_comprehensive_auth())
    if success:
        print("\n🚀 Authentication system is ready for production!")
    else:
        print("\n❌ Issues still present")
    sys.exit(0 if success else 1)
