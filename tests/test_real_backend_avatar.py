#!/usr/bin/env python3
"""
Real Backend Avatar Test
Test avatar functionality with real backend
"""

import asyncio
import sys
import os
import requests
import json
from datetime import datetime

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

async def test_real_backend_avatar():
    """Test avatar functionality with real backend"""
    
    print("🖼️ REAL BACKEND AVATAR TEST")
    print("=" * 50)
    
    # Test configuration
    base_url = "http://localhost:8000/api/v1"
    
    # Test user data
    test_user = {
        "name": "Test User",
        "username": "testuser123",
        "email": "testuser123@example.com",
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
                print(f"📥 Avatar: {result.get('avatar')}")
                print(f"📥 Avatar URL: {result.get('avatar_url')}")
                
                # Check if avatar is empty (should be None or empty)
                avatar = result.get('avatar')
                if avatar is None or avatar == "":
                    print("✅ Avatar initials are properly disabled")
                else:
                    print(f"❌ Avatar initials found: {avatar}")
                    return False
                    
            elif response.status_code == 409:
                print("✅ User already exists (expected for testing)")
                
                # Get existing user to check avatar
                login_response = requests.post(f"{base_url}/auth/login", json={
                    "email": test_user["email"],
                    "password": test_user["password"]
                }, timeout=10)
                
                if login_response.status_code == 200:
                    login_result = login_response.json()
                    access_token = login_result.get("access_token")
                    
                    # Get user profile
                    headers = {"Authorization": f"Bearer {access_token}"}
                    profile_response = requests.get(f"{base_url}/users/me", headers=headers, timeout=10)
                    
                    if profile_response.status_code == 200:
                        profile = profile_response.json()
                        print(f"📥 Existing User Avatar: {profile.get('avatar')}")
                        print(f"📥 Existing User Avatar URL: {profile.get('avatar_url')}")
                        
                        # Check if avatar is empty
                        avatar = profile.get('avatar')
                        if avatar is None or avatar == "":
                            print("✅ Existing user avatar initials are properly disabled")
                        else:
                            print(f"❌ Existing user avatar initials found: {avatar}")
                            return False
                else:
                    print(f"❌ Login failed: {login_response.text}")
                    return False
            else:
                print(f"❌ Registration failed: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Registration request failed: {e}")
            return False
        
        # Test 3: Get User Profile
        print("\n📝 Test 3: Get User Profile")
        print("-" * 40)
        
        try:
            # Login first
            login_response = requests.post(f"{base_url}/auth/login", json={
                "email": test_user["email"],
                "password": test_user["password"]
            }, timeout=10)
            
            if login_response.status_code == 200:
                login_result = login_response.json()
                access_token = login_result.get("access_token")
                
                # Get user profile
                headers = {"Authorization": f"Bearer {access_token}"}
                profile_response = requests.get(f"{base_url}/users/me", headers=headers, timeout=10)
                
                print(f"📥 Profile Status: {profile_response.status_code}")
                
                if profile_response.status_code == 200:
                    profile = profile_response.json()
                    print("✅ User profile retrieved successfully")
                    print(f"📥 Name: {profile.get('name')}")
                    print(f"📥 Username: {profile.get('username')}")
                    print(f"📥 Avatar: {profile.get('avatar')}")
                    print(f"📥 Avatar URL: {profile.get('avatar_url')}")
                    
                    # Check avatar field
                    avatar = profile.get('avatar')
                    if avatar is None or avatar == "":
                        print("✅ Profile avatar initials are properly disabled")
                    else:
                        print(f"❌ Profile avatar initials found: {avatar}")
                        return False
                else:
                    print(f"❌ Profile retrieval failed: {profile_response.text}")
                    return False
            else:
                print(f"❌ Login failed: {login_response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Profile request failed: {e}")
            return False
        
        # Test 4: Update Profile (without avatar)
        print("\n📝 Test 4: Update Profile (without avatar)")
        print("-" * 40)
        
        try:
            # Login first
            login_response = requests.post(f"{base_url}/auth/login", json={
                "email": test_user["email"],
                "password": test_user["password"]
            }, timeout=10)
            
            if login_response.status_code == 200:
                login_result = login_response.json()
                access_token = login_result.get("access_token")
                
                # Update profile
                headers = {"Authorization": f"Bearer {access_token}"}
                update_data = {
                    "name": "Updated Name",
                    "bio": "Updated bio"
                }
                
                update_response = requests.put(f"{base_url}/users/profile", json=update_data, headers=headers, timeout=10)
                
                print(f"📥 Update Status: {update_response.status_code}")
                
                if update_response.status_code == 200:
                    update_result = update_response.json()
                    print("✅ Profile updated successfully")
                    print(f"📥 Updated Avatar: {update_result.get('avatar')}")
                    print(f"📥 Updated Avatar URL: {update_result.get('avatar_url')}")
                    
                    # Check avatar field
                    avatar = update_result.get('avatar')
                    if avatar is None or avatar == "":
                        print("✅ Updated profile avatar initials are properly disabled")
                    else:
                        print(f"❌ Updated profile avatar initials found: {avatar}")
                        return False
                else:
                    print(f"❌ Profile update failed: {update_response.text}")
                    return False
            else:
                print(f"❌ Login failed: {login_response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Profile update request failed: {e}")
            return False
        
        print("\n" + "=" * 50)
        print("🖼️ REAL BACKEND AVATAR TEST COMPLETE")
        print("=" * 50)
        print("✅ All avatar tests passed:")
        print("  • User Registration - No avatar initials")
        print("  • User Profile - No avatar initials")
        print("  • Profile Update - No avatar initials")
        print("  • Avatar field is always None or empty")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_real_backend_avatar())
    if success:
        print("\n🚀 Real backend avatar management is working perfectly!")
    else:
        print("\n❌ Some avatar issues found - check logs above")
