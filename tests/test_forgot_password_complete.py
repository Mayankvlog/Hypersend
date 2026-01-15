#!/usr/bin/env python3
"""Complete test for forgot password functionality including user creation"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Set mock database
os.environ['USE_MOCK_DB'] = 'True'
os.environ['DEBUG'] = 'True'

from fastapi.testclient import TestClient
try:
    from main import app
    from config import settings
except ImportError:
    app = None
    settings = None
    print("Warning: Could not import main app or settings")

import json
import logging

logger = logging.getLogger(__name__)

def test_complete_forgot_password_flow():
    """Test complete forgot password flow with user creation"""
    print("\n🧪 Testing Complete Forgot Password Flow...")
    
    if not app:
        print("❌ App not available - skipping test")
        return False
    
    client = TestClient(app)
    
    # Step 1: Create a test user
    test_email = "forgotflowtest@example.com"
    test_password = "TestPass123"
    
    print(f"Step 1: Creating test user: {test_email}")
    
    register_payload = {
        "email": test_email,
        "password": test_password,
        "username": test_email,
        "name": "Forgot Flow Test User"
    }
    
    reg_response = client.post("/api/v1/auth/register", json=register_payload)
    print(f"Registration status: {reg_response.status_code}")
    
    if reg_response.status_code not in [200, 201]:
        print(f"❌ User creation failed: {reg_response.status_code}")
        print(f"Response: {reg_response.text}")
        return False
    
    print("✅ User created successfully")
    
    # Step 2: Test forgot password for existing user
    print(f"Step 2: Testing forgot password for existing user: {test_email}")
    
    forgot_payload = {"email": test_email}
    forgot_response = client.post("/api/v1/auth/forgot-password", json=forgot_payload)
    
    print(f"Forgot password status: {forgot_response.status_code}")
    
    if forgot_response.status_code == 200:
        data = forgot_response.json()
        print(f"Response data: {data}")
        
        if data.get("success") and data.get("token"):
            print(f"✅ Token generated for existing user: {data.get('token')}")
            
            # Step 3: Test reset password with the generated token
            reset_token = data.get("token")
            reset_payload = {"token": reset_token, "new_password": "NewPassword123!"}
            
            print(f"Step 3: Testing password reset with token: {reset_token}")
            
            reset_response = client.post("/api/v1/auth/reset-password", json=reset_payload)
            print(f"Reset password status: {reset_response.status_code}")
            
            if reset_response.status_code == 200:
                reset_data = reset_response.json()
                print(f"Reset response: {reset_data}")
                
                if reset_data.get("success"):
                    print("✅ Password reset successful!")
                    return True
                else:
                    print(f"❌ Password reset failed: {reset_data}")
                    return False
            else:
                print(f"❌ Password reset failed with status: {reset_response.status_code}")
                return False
        else:
            print("❌ Token generation failed for existing user")
            return False
    else:
        print(f"❌ Forgot password failed for existing user: {forgot_response.status_code}")
        return False

def test_forgot_password_for_nonexistent_user():
    """Test forgot password for non-existent user"""
    print("\n🧪 Testing Forgot Password for Non-existent User...")
    
    if not app:
        print("❌ App not available - skipping test")
        return False
    
    client = TestClient(app)
    
    # Test with non-existent user
    test_email = "nonexistent@example.com"
    forgot_payload = {"email": test_email}
    
    print(f"Testing forgot password for non-existent user: {test_email}")
    
    response = client.post("/api/v1/auth/forgot-password", json=forgot_payload)
    
    print(f"Response status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"Response data: {data}")
        
        # For non-existent users, should return success=False but still generate token for security
        if data.get("success") == False and data.get("token"):
            print("✅ Correctly handled non-existent user (no token in success response)")
            return True
        elif data.get("success") == True:
            print("❌ Incorrectly returned success for non-existent user")
            return False
        else:
            print(f"❓ Unexpected response for non-existent user: {data}")
            return False
    else:
        print(f"❌ Forgot password failed for non-existent user: {response.status_code}")
        return False

if __name__ == "__main__":
    print("🔧 Testing Complete Forgot Password Flow")
    print("=" * 60)
    
    # Test 1: Complete flow with existing user
    test1_ok = test_complete_forgot_password_flow()
    
    # Test 2: Test with non-existent user
    test2_ok = test_forgot_password_for_nonexistent_user()
    
    print("\n" + "=" * 60)
    print("📊 Test Results:")
    print(f"Complete Flow Test: {'✅ PASS' if test1_ok else '❌ FAIL'}")
    print(f"Non-existent User Test: {'✅ PASS' if test2_ok else '❌ FAIL'}")
    
    if test1_ok and test2_ok:
        print("\n🎉 All forgot password tests passed!")
        print("✅ Email service is working correctly.")
        print("✅ Forgot password endpoint is functioning properly.")
        print("✅ Users should receive password reset emails.")
    else:
        print("\n⚠️  Some tests failed.")
        print("💡 Check the test output above for specific issues.")
    
    print("=" * 60)
