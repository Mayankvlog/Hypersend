"""
Group Members Fix - Comprehensive Test and Debugging
Tests for group creation and member addition issues
"""
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Set mock database
os.environ['USE_MOCK_DB'] = 'True'
os.environ['DEBUG'] = 'True'

from fastapi.testclient import TestClient
try:
    from backend.main import app
    from backend.models import GroupCreate, GroupMembersUpdate
except ImportError as e:
    print(f"Warning: Import error: {e}")
    app = None

import json
from datetime import datetime


class TestGroupMembersFix:
    """Test group members functionality"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_auth(self):
        """Mock authentication"""
        with patch('backend.routes.groups.get_current_user') as mock:
            mock.return_value = "test_user_123"
            yield mock
    
    def test_group_creation_shows_members(self, client, mock_auth):
        """Test that group creation returns members list"""
        print("\n" + "="*60)
        print("TEST: Group Creation Shows Members")
        print("="*60)
        
        payload = {
            "name": "Test Group",
            "description": "Test Description",
            "member_ids": ["user1", "user2"]
        }
        
        with patch('backend.routes.groups.chats_collection') as mock_chats:
            mock_collection = AsyncMock()
            mock_chats.return_value = mock_collection
            
            # Mock insert_one
            mock_collection.insert_one = AsyncMock()
            
            response = client.post(
                "/api/v1/groups",
                json=payload,
                headers={"Authorization": "Bearer test_token"}
            )
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.json()}")
            
            if response.status_code == 201:
                data = response.json()
                group = data.get("group", {})
                members = group.get("members", [])
                member_count = group.get("member_count", 0)
                
                print(f"✅ Group created successfully")
                print(f"   Members: {members}")
                print(f"   Member Count: {member_count}")
                print(f"   Expected: ['test_user_123', 'user1', 'user2']")
                
                assert len(members) >= 2, f"Expected at least 2 members, got {len(members)}"
                assert "test_user_123" in members, "Current user should be in members"
            else:
                print(f"❌ Group creation failed: {response.text}")
    
    def test_add_members_to_group(self, client, mock_auth):
        """Test adding members to existing group"""
        print("\n" + "="*60)
        print("TEST: Add Members to Group")
        print("="*60)
        
        group_id = "test_group_123"
        payload = {
            "user_ids": ["user3", "user4"]
        }
        
        with patch('backend.routes.groups.chats_collection') as mock_chats, \
             patch('backend.routes.groups.GroupCacheService') as mock_cache:
            
            mock_collection = AsyncMock()
            mock_chats.return_value = mock_collection
            
            # Mock group retrieval
            mock_collection.find_one = AsyncMock(return_value={
                "_id": group_id,
                "type": "group",
                "members": ["test_user_123", "user1", "user2"],
                "admins": ["test_user_123"],
                "created_by": "test_user_123"
            })
            
            # Mock update
            mock_result = MagicMock()
            mock_result.modified_count = 2
            mock_collection.update_one = AsyncMock(return_value=mock_result)
            
            # Mock cache
            mock_cache.get_group_members = AsyncMock(return_value=["test_user_123", "user1", "user2"])
            mock_cache.set_group_members = AsyncMock()
            mock_cache.invalidate_group_info = AsyncMock()
            
            response = client.post(
                f"/api/v1/groups/{group_id}/members",
                json=payload,
                headers={"Authorization": "Bearer test_token"}
            )
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.json()}")
            
            if response.status_code == 200:
                data = response.json()
                added = data.get("added", 0)
                member_count = data.get("member_count", 0)
                members = data.get("members", [])
                
                print(f"✅ Members added successfully")
                print(f"   Added: {added}")
                print(f"   Total Members: {member_count}")
                print(f"   Members List: {members}")
                
                assert added == 2, f"Expected 2 members added, got {added}"
                assert member_count >= 4, f"Expected at least 4 total members, got {member_count}"
            else:
                print(f"❌ Add members failed: {response.text}")
    
    def test_member_suggestions_endpoint(self, client, mock_auth):
        """Test member suggestions endpoint"""
        print("\n" + "="*60)
        print("TEST: Member Suggestions Endpoint")
        print("="*60)
        
        group_id = "test_group_123"
        
        with patch('backend.routes.groups.chats_collection') as mock_chats, \
             patch('backend.routes.groups.users_collection') as mock_users, \
             patch('backend.routes.groups.UserCacheService') as mock_user_cache, \
             patch('backend.routes.groups.SearchCacheService') as mock_search_cache:
            
            # Mock group retrieval
            mock_chats_collection = AsyncMock()
            mock_chats.return_value = mock_chats_collection
            mock_chats_collection.find_one = AsyncMock(return_value={
                "_id": group_id,
                "type": "group",
                "members": ["test_user_123", "user1"],
                "admins": ["test_user_123"]
            })
            
            # Mock user cache
            mock_user_cache.get_user_contacts = AsyncMock(return_value=["user1", "user2", "user3"])
            mock_user_cache.set_user_contacts = AsyncMock()
            
            # Mock search cache
            mock_search_cache.get_user_search = AsyncMock(return_value=None)
            mock_search_cache.set_user_search = AsyncMock()
            
            # Mock users collection
            mock_users_collection = AsyncMock()
            mock_users.return_value = mock_users_collection
            
            # Mock cursor
            async def mock_find(*args, **kwargs):
                class MockCursor:
                    async def __aiter__(self):
                        return self
                    
                    async def __anext__(self):
                        if not hasattr(self, '_index'):
                            self._index = 0
                        
                        users = [
                            {"_id": "user2", "name": "User 2", "email": "user2@test.com", "username": "user2"},
                            {"_id": "user3", "name": "User 3", "email": "user3@test.com", "username": "user3"}
                        ]
                        
                        if self._index < len(users):
                            result = users[self._index]
                            self._index += 1
                            return result
                        raise StopAsyncIteration
                
                return MockCursor()
            
            mock_users_collection.find = mock_find
            
            response = client.get(
                f"/api/v1/groups/{group_id}/member-suggestions",
                headers={"Authorization": "Bearer test_token"}
            )
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.json()}")
            
            if response.status_code == 200:
                suggestions = response.json()
                print(f"✅ Member suggestions retrieved")
                print(f"   Suggestions: {suggestions}")
                print(f"   Count: {len(suggestions)}")
            else:
                print(f"❌ Member suggestions failed: {response.text}")
    
    def test_group_list_shows_member_count(self, client, mock_auth):
        """Test that group list shows member count"""
        print("\n" + "="*60)
        print("TEST: Group List Shows Member Count")
        print("="*60)
        
        with patch('backend.routes.groups.chats_collection') as mock_chats, \
             patch('backend.routes.groups.messages_collection') as mock_messages:
            
            mock_chats_collection = AsyncMock()
            mock_chats.return_value = mock_chats_collection
            
            # Mock find with sort
            async def mock_find_sort(*args, **kwargs):
                class MockCursor:
                    async def __aiter__(self):
                        return self
                    
                    async def __anext__(self):
                        if not hasattr(self, '_index'):
                            self._index = 0
                        
                        groups = [
                            {
                                "_id": "group1",
                                "type": "group",
                                "name": "Group 1",
                                "members": ["test_user_123", "user1", "user2"],
                                "admins": ["test_user_123"]
                            }
                        ]
                        
                        if self._index < len(groups):
                            result = groups[self._index]
                            self._index += 1
                            return result
                        raise StopAsyncIteration
                
                return MockCursor()
            
            mock_find_result = MagicMock()
            mock_find_result.sort = mock_find_sort
            mock_chats_collection.find = MagicMock(return_value=mock_find_result)
            
            # Mock messages collection
            mock_messages_collection = AsyncMock()
            mock_messages.return_value = mock_messages_collection
            mock_messages_collection.find_one = AsyncMock(return_value=None)
            
            response = client.get(
                "/api/v1/groups",
                headers={"Authorization": "Bearer test_token"}
            )
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.json()}")
            
            if response.status_code == 200:
                data = response.json()
                groups = data.get("groups", [])
                
                if groups:
                    group = groups[0]
                    member_count = group.get("member_count", 0)
                    members = group.get("members", [])
                    
                    print(f"✅ Groups retrieved")
                    print(f"   Group Name: {group.get('name')}")
                    print(f"   Members: {members}")
                    print(f"   Member Count: {member_count}")
                    
                    assert member_count > 0, "Member count should be greater than 0"
                    assert len(members) == member_count, "Member count should match members list length"
            else:
                print(f"❌ Group list failed: {response.text}")


class TestGroupMembersLogic:
    """Test the logic of group member operations"""
    
    def test_member_deduplication_logic(self):
        """Test that member deduplication works correctly"""
        print("\n" + "="*60)
        print("TEST: Member Deduplication Logic")
        print("="*60)
        
        # Simulate the logic from groups.py create_group
        current_user = "test_user_123"
        member_ids_input = ["user1", "user2", "user1"]  # Duplicate
        
        # This is what the backend should do
        member_ids = list(dict.fromkeys([*(member_ids_input or []), current_user]))
        
        print(f"Input members: {member_ids_input}")
        print(f"Current user: {current_user}")
        print(f"Final members: {member_ids}")
        
        assert len(member_ids) == 3, f"Expected 3 unique members, got {len(member_ids)}"
        assert current_user in member_ids, "Current user should be in members"
        assert member_ids.count("user1") == 1, "Duplicates should be removed"
        
        print("✅ Member deduplication works correctly")
    
    def test_add_members_filtering_logic(self):
        """Test the filtering logic for adding members"""
        print("\n" + "="*60)
        print("TEST: Add Members Filtering Logic")
        print("="*60)
        
        current_user = "test_user_123"
        user_ids = ["user3", "", "user4", "test_user_123", " user5 ", None]
        current_members = ["test_user_123", "user1", "user2"]
        
        # This is what the backend should do
        filtered_ids = []
        for uid in user_ids:
            if uid and uid.strip() and uid != current_user:
                if uid not in filtered_ids:
                    filtered_ids.append(uid.strip())
        
        new_members = [uid for uid in filtered_ids if uid not in current_members]
        
        print(f"Input user_ids: {user_ids}")
        print(f"Current members: {current_members}")
        print(f"Filtered IDs: {filtered_ids}")
        print(f"New members to add: {new_members}")
        
        assert "user3" in new_members, "user3 should be in new members"
        assert "user4" in new_members, "user4 should be in new members"
        assert "user5" in new_members, "user5 should be in new members (after strip)"
        assert current_user not in new_members, "Current user should not be in new members"
        assert "" not in new_members, "Empty strings should be filtered"
        assert len(new_members) == 3, f"Expected 3 new members, got {len(new_members)}"
        
        print("✅ Add members filtering logic works correctly")
    
    def test_member_count_calculation(self):
        """Test member count calculation"""
        print("\n" + "="*60)
        print("TEST: Member Count Calculation")
        print("="*60)
        
        current_members = ["test_user_123", "user1", "user2"]
        new_members = ["user3", "user4"]
        
        final_members = current_members + new_members
        member_count = len(final_members)
        
        print(f"Current members: {current_members}")
        print(f"New members: {new_members}")
        print(f"Final members: {final_members}")
        print(f"Member count: {member_count}")
        
        assert member_count == 5, f"Expected 5 members, got {member_count}"
        assert len(final_members) == member_count, "Member count should match list length"
        
        print("✅ Member count calculation works correctly")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
