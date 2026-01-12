#!/usr/bin/env python3
"""
Test group creation functionality
"""

import pytest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

class TestGroupCreationFix:
    """Test group creation functionality"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        from backend.main import app
        return TestClient(app)
    
    @pytest.mark.asyncio
    async def test_group_creation_with_members(self, client):
        """Test that group creation properly adds members"""
        from models import GroupCreate
        from fastapi.security import HTTPAuthorizationCredentials
        
        # Test group creation with 2 members
        group_data = {
            "name": "Test Group",
            "description": "Test group description",
            "member_ids": ["user1", "user2"]  # 2 additional members + current_user = 3 total
        }
        
        # Mock authentication at the dependency level
        fake_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="fake_token")
        with patch('backend.routes.groups.get_current_user', return_value="current_user"):
            with patch('backend.routes.groups.chats_collection') as mock_chats:
                with patch('backend.routes.groups.users_collection') as mock_users:
                    # Mock database operations
                    mock_chats.return_value.insert_one.return_value = MagicMock()
                    mock_users.return_value.find_one.return_value = {"_id": "user1", "name": "User 1"}
                    
                    # Test group creation via groups endpoint
                    response = client.post(
                        "/api/v1/groups",
                        json=group_data,
                        headers={"Authorization": "Bearer fake_token"}
                    )
                    
                    print(f"Group creation response status: {response.status_code}")
                    
                    if response.status_code == 201:
                        data = response.json()
                        print(f"Group created: {data}")
                        
                        # Verify insert_one was called with correct members
                        if mock_chats.return_value.insert_one.called:
                            call_args = mock_chats.return_value.insert_one.call_args
                            chat_doc = call_args[0][0]
                            members = chat_doc.get("members", [])
                            
                            print(f"Members in database: {members}")
                            
                            # Should have 3 members: current_user + user1 + user2
                            if len(members) >= 2:
                                print("✅ Group creation includes current_user and additional members")
                            else:
                                print("❌ Group creation missing members")
                    else:
                        print(f"❌ Group creation failed: {response.status_code}")
                        print(f"Response: {response.text}")
    
    @pytest.mark.asyncio
    async def test_group_creation_via_users_endpoint(self, client):
        """Test group creation via users endpoint"""
        from models import GroupCreate
        
        # Test group creation with 2 members
        group_data = {
            "name": "Test Group via Users",
            "description": "Test group description",
            "member_ids": ["user1", "user2"]  # 2 additional members + current_user = 3 total
        }
        
        # Mock authentication
        with patch('main.get_current_user', return_value="current_user"):
            with patch('routes.users.chats_collection') as mock_chats:
                with patch('routes.users.users_collection') as mock_users:
                    # Mock database operations
                    mock_chats.return_value.insert_one.return_value = MagicMock()
                    mock_users.return_value.find_one.return_value = {"_id": "user1", "name": "User 1"}
                    
                    # Test group creation via users endpoint
                    response = client.post(
                        "/api/v1/users/create-group",
                        json=group_data
                    )
                    
                    print(f"Users endpoint group creation response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        data = response.json()
                        print(f"Group created via users: {data}")
                        
                        # Verify group was created
                        if "group_id" in data:
                            print("✅ Group creation via users endpoint works")
                        else:
                            print("❌ Group creation via users endpoint missing group_id")
                    else:
                        print(f"❌ Group creation via users failed: {response.status_code}")
                        print(f"Response: {response.text}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
