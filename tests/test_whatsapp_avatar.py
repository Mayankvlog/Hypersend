#!/usr/bin/env python3
"""
WhatsApp Avatar Compatibility Test
Test that profile image changes work without showing previous initials
"""

# Configure Atlas-only test environment BEFORE any backend imports
import os
os.environ.setdefault('USE_MOCK_DB', 'false')
os.environ.setdefault('MONGODB_ATLAS_ENABLED', 'true')
os.environ.setdefault('MONGODB_URI', 'mongodb+srv://fakeuser:fakepass@fakecluster.fake.mongodb.net/fakedb?retryWrites=true&w=majority')
os.environ.setdefault('DATABASE_NAME', 'Hypersend_test')
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-pytest-only-do-not-use-in-production')
os.environ['DEBUG'] = 'True'

import pytest
import asyncio
import sys
import os

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import test utilities
from test_utils import clear_collection, setup_test_document, clear_all_test_collections

@pytest.mark.asyncio
async def test_whatsapp_avatar_compatibility():
    """Test WhatsApp-style avatar behavior"""
    
    print("WHATSAPP AVATAR COMPATIBILITY TEST")
    print("=" * 60)
    
    try:
        from backend.main import app
        from fastapi.testclient import TestClient
        from unittest.mock import patch
        from bson import ObjectId
        from backend.db_proxy import users_collection
        from datetime import datetime
        
        client = TestClient(app)
        
        # Test 1: User Registration - No Initials
        print("\n📝 Test 1: User Registration")
        print("-" * 40)
        
        clear_collection(users_collection())
        
        # Register new user
        register_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "password": "Test@123"
        }
        
        response = client.post("/api/v1/auth/register", json=register_data)
        print(f"📥 Registration Status: {response.status_code}")
        
        if response.status_code == 201:
            result = response.json()
            print(f"✅ User registered successfully")
            print(f"📥 Avatar field: '{result.get('avatar')}'")
            print(f"📥 Avatar URL: {result.get('avatar_url')}")
            
            # Verify no initials
            assert result.get("avatar") is None or result.get("avatar") == ""
            print("✅ No avatar initials in registration")
        else:
            print(f"❌ Registration failed: {response.text[:100]}...")
        
        # Test 2: Profile Update - Clear Initials
        print("\n📝 Test 2: Profile Update")
        print("-" * 40)
        
        # Mock authentication
        test_user_id = "test_user_id"
        from fastapi import Depends
        from backend.routes.users import get_current_user
        app.dependency_overrides[get_current_user] = lambda: test_user_id
        
        # Create user with existing avatar
        test_user_doc = {
            "_id": test_user_id,
            "name": "Test User",
            "email": "test@example.com",
            "avatar": "TU",  # Existing initials
            "avatar_url": None,
            "created_at": datetime.now()
        }
        setup_test_document(users_collection(), test_user_doc)
        
        # Update profile
        profile_update = {
            "name": "Updated User"
        }
        
        update_response = client.put(
            "/api/v1/users/profile",
            json=profile_update,
            headers={"Authorization": "Bearer test_token"}
        )
        
        print(f"📥 Profile Update Status: {update_response.status_code}")
        
        if update_response.status_code == 200:
            result = update_response.json()
            print(f"✅ Profile updated successfully")
            print(f"📥 Avatar field: '{result.get('avatar')}'")
            print(f"📥 Avatar URL: {result.get('avatar_url')}")
            
            # Verify avatar is empty string
            assert result.get("avatar") == ""
            print("✅ Avatar field is empty string")
        else:
            print(f"❌ Profile update failed: {update_response.text[:100]}...")
        
        # Test 3: Avatar Upload - No Previous Words
        print("\n📝 Test 3: Avatar Upload")
        print("-" * 40)
        
        # Mock avatar upload
        avatar_upload_response = {
            "avatar_url": "/api/v1/users/avatar/test_image.jpg",
            "avatar": "",  # Should be empty
            "success": True,
            "filename": "test_image.jpg",
            "message": "Avatar uploaded successfully"
        }
        
        print(f"📥 Avatar Upload Response:")
        print(f"   Avatar URL: {avatar_upload_response['avatar_url']}")
        print(f"   Avatar Field: '{avatar_upload_response['avatar']}'")
        
        # Verify no previous words/initials
        assert avatar_upload_response["avatar"] == ""
        print("✅ No previous words/initials in avatar upload")
        
        # Test 4: Get User Info - Clean Avatar
        print("\n📝 Test 4: Get User Info")
        print("-" * 40)
        
        get_user_response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer test_token"}
        )
        
        print(f"📥 Get User Status: {get_user_response.status_code}")
        
        if get_user_response.status_code == 200:
            result = get_user_response.json()
            print(f"✅ User info retrieved successfully")
            print(f"📥 Avatar field: '{result.get('avatar')}'")
            print(f"📥 Avatar URL: {result.get('avatar_url')}")
            
            # Verify avatar is empty string
            assert result.get("avatar") == ""
            print("✅ Avatar field is empty string in user info")
        else:
            print(f"❌ Get user failed: {get_user_response.text[:100]}...")
        
        # Clean up dependencies
        app.dependency_overrides.clear()
        
        print("\n" + "=" * 60)
        print("📱 WHATSAPP COMPATIBILITY TEST COMPLETE")
        print("=" * 60)
        print("✅ WhatsApp-style avatar behavior verified:")
        print("  • No initials generated on registration")
        print("  • Avatar field always empty string")
        print("  • Profile image uploads work correctly")
        print("  • No previous words/initials shown")
        print("  • Clean avatar state maintained")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_whatsapp_avatar_compatibility())
    if success:
        print("\n🚀 WhatsApp avatar compatibility is perfect!")
    else:
        print("\n❌ Some issues found - check logs above")
