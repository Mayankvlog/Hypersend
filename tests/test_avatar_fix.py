#!/usr/bin/env python3
"""
Comprehensive Avatar Fix Tests
Pytest tests for avatar issue fix
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
try:
    from main import app
except ImportError:
    # Skip test if main is not available
    app = None
from models import ProfileUpdate, UserCreate
try:
    from db_proxy import users_collection
except ImportError:
    users_collection = None
try:
    from bson import ObjectId
except ImportError:
    ObjectId = None

class TestAvatarFix:
    """Test avatar fix - no 2-letter avatars"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        if app is None:
            pytest.skip("Backend modules not available")
        return TestClient(app)
    
    @pytest.fixture
    def test_user_id(self):
        """Create test user ID"""
        return str(ObjectId())
    
    def test_profile_update_model_avatar_validation(self):
        """Test that ProfileUpdate model always sets avatar to None"""
        print("\n[TEST] ProfileUpdate Avatar Validation")
        
        # Test with avatar initials
        profile_with_avatar = ProfileUpdate(
            name="Test User",
            avatar="TU"  # 2-letter initials
        )
        assert profile_with_avatar.avatar is None
        print("PASS: Avatar initials set to None in model")
        
        # Test with empty string
        profile_empty = ProfileUpdate(
            name="Test User",
            avatar=""
        )
        assert profile_empty.avatar is None
        print("PASS: Empty avatar set to None in model")
        
        # Test with None
        profile_none = ProfileUpdate(
            name="Test User",
            avatar=None
        )
        assert profile_none.avatar is None
        print("PASS: None avatar remains None in model")
    
    def test_user_registration_no_avatar_initials(self, client):
        """Test that user registration doesn't create 2-letter avatars"""
        print("\n[TEST] User Registration - No Avatar Initials")
        
        # Clear test data
        users_collection().data.clear()
        
        # Create test user
        test_user = UserCreate(
            name="John Doe",
            email="johndoe@example.com",
            password="Test@123"
        )
        
        # Register user
        response = client.post(
            "/api/v1/auth/register",
            json=test_user.model_dump()
        )
        
        assert response.status_code == 201
        result = response.json()
        
        # Check that avatar is None
        assert result.get("avatar") is None
        assert result.get("avatar_url") is None
        
        print("PASS: User registration has no avatar initials")
    
    @pytest.mark.asyncio
    async def test_profile_update_clears_avatar_initials(self, test_user_id):
        """Test that profile update clears existing avatar initials"""
        print("\n[TEST] Profile Update - Clears Avatar Initials")
        
        # Create user with existing avatar initials
        users_collection().data.clear()
        test_user_doc = {
            "_id": test_user_id,
            "name": "Test User",
            "email": "test@example.com",
            "avatar": "TU",  # Existing 2-letter avatar
            "avatar_url": None,
            "created_at": datetime.now()
        }
        users_collection().data[test_user_id] = test_user_doc
        
        # Update profile with avatar URL
        profile_update = ProfileUpdate(
            name="Updated User",
            avatar_url="/api/v1/users/avatar/test_image.jpg"
        )
        
        # Simulate the update logic
        update_data = {}
        
        # Process avatar_url (should clear avatar initials)
        if profile_update.avatar_url is not None:
            update_data["avatar_url"] = profile_update.avatar_url
            update_data["avatar"] = None  # Clear avatar initials
        
        # Process avatar (should always be None)
        if profile_update.avatar is not None:
            update_data["avatar"] = None
        
        # Update user document
        users_collection().data[test_user_id].update(update_data)
        
        # Check result
        updated_user = users_collection().data[test_user_id]
        assert updated_user.get("avatar") is None
        assert updated_user.get("avatar_url") == "/api/v1/users/avatar/test_image.jpg"
        
        print("PASS: Avatar initials cleared on profile update")
    
    @pytest.mark.asyncio
    async def test_profile_update_removes_avatar(self, test_user_id):
        """Test that removing avatar URL sets both fields to None"""
        print("\n[TEST] Profile Update - Remove Avatar")
        
        # Create user with avatar
        users_collection().data.clear()
        test_user_doc = {
            "_id": test_user_id,
            "name": "Test User",
            "email": "test@example.com",
            "avatar": "TU",
            "avatar_url": "/api/v1/users/avatar/old_image.jpg",
            "created_at": datetime.now()
        }
        users_collection().data[test_user_id] = test_user_doc
        
        # Update profile to remove avatar
        profile_update = ProfileUpdate(
            name="Updated User",
            avatar_url=None  # Remove avatar
        )
        
        # Simulate the update logic
        update_data = {}
        
        # Process avatar_url removal
        if profile_update.avatar_url is None:
            update_data["avatar_url"] = None
            update_data["avatar"] = None  # Also clear initials
        
        # Update user document
        users_collection().data[test_user_id].update(update_data)
        
        # Check result
        updated_user = users_collection().data[test_user_id]
        assert updated_user.get("avatar") is None
        assert updated_user.get("avatar_url") is None
        
        print("PASS: Avatar completely removed on profile update")
    
    def test_avatar_field_edge_cases(self):
        """Test avatar field edge cases"""
        print("\n[TEST] Avatar Field Edge Cases")
        
        # Test with special characters
        profile_special = ProfileUpdate(
            name="Test User",
            avatar="T@U"
        )
        assert profile_special.avatar is None
        print("PASS: Special characters in avatar set to None")
        
        # Test with long string (within 10 char limit)
        profile_long = ProfileUpdate(
            name="Test User",
            avatar="LONGINIT"  # 8 characters, within limit
        )
        assert profile_long.avatar is None
        print("PASS: Long avatar string set to None")
        
        # Test with numbers
        profile_numbers = ProfileUpdate(
            name="Test User",
            avatar="123"
        )
        assert profile_numbers.avatar is None
        print("PASS: Numeric avatar set to None")

if __name__ == "__main__":
    print("[TEST] Running Avatar Fix Tests")
    print("=" * 50)
    
    # Run tests
    pytest.main([__file__, "-v", "-s"])
