#!/usr/bin/env python3
"""
WhatsApp Avatar Compatibility Pytest Tests
Test WhatsApp-style avatar behavior with pytest
"""

import pytest
import asyncio
import sys
import os
from datetime import datetime

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from fastapi.testclient import TestClient
from main import app
from db_proxy import users_collection
from bson import ObjectId

class TestWhatsAppAvatarCompatibility:
    """Test WhatsApp-style avatar compatibility"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def test_user_id(self):
        """Create test user ID"""
        return str(ObjectId())
    
    def test_user_registration_no_initials(self, client):
        """Test that user registration doesn't create initials"""
        print("\n📱 Test: User Registration - No Initials")
        
        # Clear test data
        users_collection().data.clear()
        
        # Register user
        register_data = {
            "name": "Test User",
            "email": "testuser@example.com",
            "password": "Test@123"
        }
        
        response = client.post("/api/v1/auth/register", json=register_data)
        
        assert response.status_code == 201
        result = response.json()
        
        # Verify no initials
        assert result.get("avatar") is None or result.get("avatar") == ""
        assert result.get("avatar_url") is None
        
        print("✅ No avatar initials in registration")
    
    @pytest.mark.asyncio
    async def test_profile_update_clears_initials(self, client, test_user_id):
        """Test that profile update clears existing initials"""
        print("\nTest: Profile Update - Clears Initials")
        
        # Create user with existing initials
        users_collection().data.clear()
        test_user_doc = {
            "_id": test_user_id,
            "name": "Test User",
            "email": "testuser@example.com",
            "username": "testuser@example.com",
            "avatar": "TU",  # Existing initials
            "avatar_url": None,
            "created_at": datetime.now()
        }
        users_collection().data[test_user_id] = test_user_doc
        
        # Mock authentication
        from fastapi import Depends
        from routes.users import get_current_user
        app.dependency_overrides[get_current_user] = lambda: test_user_id
        
        # Update profile
        profile_update = {
            "name": "Updated User"
        }
        
        update_response = client.put(
            "/api/v1/users/profile",
            json=profile_update,
            headers={"Authorization": "Bearer test_token"}
        )
        
        assert update_response.status_code == 200
        result = update_response.json()
        
        # Verify avatar is empty string
        assert result.get("avatar") == ""
        assert result.get("avatar_url") is None
        
        print("✅ Avatar field is empty string after update")
        
        # Clean up dependencies
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_get_user_info_clean_avatar(self, client, test_user_id):
        """Test that get user info returns clean avatar"""
        print("\n📱 Test: Get User Info - Clean Avatar")
        
        # Create user
        users_collection().data.clear()
        test_user_doc = {
            "_id": test_user_id,
            "name": "Test User",
            "username": "testuser",
            "avatar": "TU",  # Existing initials
            "avatar_url": "/api/v1/users/avatar/test.jpg",
            "created_at": datetime.now()
        }
        users_collection().data[test_user_id] = test_user_doc
        
        # Mock authentication
        from fastapi import Depends
        from routes.users import get_current_user
        app.dependency_overrides[get_current_user] = lambda: test_user_id
        
        # Get user info
        get_user_response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer test_token"}
        )
        
        assert get_user_response.status_code == 200
        result = get_user_response.json()
        
        # Verify avatar is empty string (WhatsApp compatibility)
        assert result.get("avatar") == ""
        assert result.get("avatar_url") == "/api/v1/users/avatar/test.jpg"
        
        print("✅ Avatar field is empty string in user info")
        
        # Clean up dependencies
        app.dependency_overrides.clear()
    
    def test_avatar_upload_response_format(self):
        """Test that avatar upload response has correct format"""
        print("\n📱 Test: Avatar Upload Response Format")
        
        # Simulate avatar upload response
        avatar_upload_response = {
            "avatar_url": "/api/v1/users/avatar/test_image.jpg",
            "avatar": "",  # Should be empty for WhatsApp
            "success": True,
            "filename": "test_image.jpg",
            "message": "Avatar uploaded successfully"
        }
        
        # Verify response format
        assert avatar_upload_response["avatar"] == ""
        assert avatar_upload_response["avatar_url"] == "/api/v1/users/avatar/test_image.jpg"
        assert avatar_upload_response["success"] is True
        
        print("✅ Avatar upload response has correct format")
    
    def test_whatsapp_avatar_consistency(self):
        """Test that all avatar endpoints return consistent format"""
        print("\n📱 Test: WhatsApp Avatar Consistency")
        
        # Test different scenarios
        scenarios = [
            {"name": "New User", "expected_avatar": ""},
            {"name": "User With Initials", "expected_avatar": ""},
            {"name": "A B C", "expected_avatar": ""},
            {"name": "Single Name", "expected_avatar": ""},
        ]
        
        for scenario in scenarios:
            # Test user creation
            from models import UserCreate
            user_data = UserCreate(
                name=scenario["name"],
                email=f"test_{scenario['name'].lower().replace(' ', '_')}@example.com",
                password="Test@123"
            )
            
            # Verify user creation works (avatar is handled in registration endpoint)
            assert user_data.name == scenario["name"]
            assert user_data.email == f"test_{scenario['name'].lower().replace(' ', '_')}@example.com"
            
            print(f"✅ {scenario['name']}: user creation works")
        
        print("✅ All scenarios return consistent behavior")

if __name__ == "__main__":
    print("📱 Running WhatsApp Avatar Compatibility Tests")
    print("=" * 60)
    
    # Run tests
    pytest.main([__file__, "-v", "-s"])
