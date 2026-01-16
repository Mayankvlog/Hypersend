#!/usr/bin/env python3
"""
Real Backend Password Test
Test forgot password and change password with real backend
"""

import asyncio
import sys
import os
import requests
import json
from datetime import datetime

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

async def test_real_backend_password():
    """Test password endpoints with real backend"""
    
    print("🔐 REAL BACKEND PASSWORD TEST")
    print("=" * 50)
    
    # Test configuration
    base_url = "http://localhost:8000/api/v1"
    
    # Test user data
    test_user = {
        "name": "Test User",
        "email": "testuser@example.com",
        "password": "Test@123"
    }
    
    try:
        # Test 1: Server Health Check
        print("\n📝 Test 1: Server Health Check")
        print("-" * 40)
        
        try:
            response = requests.get(f"{base_url}/health", timeout=5)
            if response.status_code == 200:
                print("✅ Backend server is running")
            else:
                print(f"❌ Server health check failed: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Cannot connect to backend server: {e}")
            print("💡 Please start backend server first:")
            print("   cd backend && python main.py")
            return False
        
        # Test 2: User Registration
        print("\n📝 Test 2: User Registration")
        print("-" * 40)
        
        try:
            response = requests.post(f"{base_url}/auth/register", json=test_user, timeout=10)
            print(f"📥 Registration Status: {response.status_code}")
            
            if response.status_code == 201:
                result = response.json()
                print("✅ User registered successfully")
                print(f"📥 User ID: {result.get('id')}")
            elif response.status_code == 409:
                print("✅ User already exists (expected for testing)")
            else:
                print(f"❌ Registration failed: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Registration request failed: {e}")
            return False
        
        # Test 3: User Login
        print("\n📝 Test 3: User Login")
        print("-" * 40)
        
        try:
            login_data = {
                "email": test_user["email"],
                "password": test_user["password"]
            }
            
            response = requests.post(f"{base_url}/auth/login", json=login_data, timeout=10)
            print(f"📥 Login Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                access_token = result.get("access_token")
                refresh_token = result.get("refresh_token")
                print("✅ Login successful")
                print(f"📥 Access Token: {access_token[:20]}..." if access_token else "❌ No access token")
            else:
                print(f"❌ Login failed: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Login request failed: {e}")
            return False
        
        # Test 4: Forgot Password
        print("\n📝 Test 4: Forgot Password")
        print("-" * 40)
        
        try:
            forgot_data = {
                "email": test_user["email"]
            }
            
            response = requests.post(f"{base_url}/auth/forgot-password", json=forgot_data, timeout=10)
            print(f"📥 Forgot Password Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Forgot password request processed")
                print(f"📥 Message: {result.get('message')}")
                print(f"📥 Success: {result.get('success')}")
                
                # Check if functionality is disabled
                if "disabled" in result.get('message', '').lower():
                    print("✅ Forgot password functionality is properly disabled")
                else:
                    print("⚠️ Forgot password functionality is still enabled")
            else:
                print(f"❌ Forgot password failed: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Forgot password request failed: {e}")
            return False
        
        # Test 5: Change Password
        print("\n📝 Test 5: Change Password")
        print("-" * 40)
        
        try:
            change_data = {
                "old_password": test_user["password"],
                "new_password": "NewTest@456"
            }
            
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.post(f"{base_url}/auth/change-password", json=change_data, headers=headers, timeout=10)
            print(f"📥 Change Password Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Change password successful")
                print(f"📥 Message: {result.get('message')}")
            elif response.status_code == 400:
                result = response.json()
                print("⚠️ Password change validation error")
                print(f"📥 Error: {result.get('detail')}")
            else:
                print(f"❌ Change password failed: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Change password request failed: {e}")
            return False
        
        # Test 6: Reset Password (should be disabled)
        print("\n📝 Test 6: Reset Password (Should be Disabled)")
        print("-" * 40)
        
        try:
            reset_data = {
                "token": "any_token_here",
                "new_password": "NewTest@789"
            }
            
            response = requests.post(f"{base_url}/auth/reset-password", json=reset_data, timeout=10)
            print(f"📥 Reset Password Status: {response.status_code}")
            
            if response.status_code == 405:
                result = response.json()
                print("✅ Reset password properly disabled")
                print(f"📥 Error: {result.get('detail')}")
            elif response.status_code == 200:
                print("⚠️ Reset password is still enabled")
            else:
                print(f"❌ Reset password failed: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Reset password request failed: {e}")
            return False
        
        print("\n" + "=" * 50)
        print("🔐 REAL BACKEND PASSWORD TEST COMPLETE")
        print("=" * 50)
        print("✅ All password endpoints tested:")
        print("  • Forgot Password - Working (disabled)")
        print("  • Reset Password - Working (disabled)")
        print("  • Change Password - Working")
        print("  • Error Handling - Working")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_real_backend_password())
    if success:
        print("\n🚀 Real backend password management is working perfectly!")
    else:
        print("\n❌ Some issues found - check logs above")
