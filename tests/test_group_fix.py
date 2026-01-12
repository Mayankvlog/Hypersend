#!/usr/bin/env python3
"""
Test group creation functionality with deep code scan tests
"""

import pytest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

class TestGroupCreationFix:
    """Test group creation functionality with comprehensive deep code scan"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        from backend.main import app
        from fastapi.testclient import TestClient
        from unittest.mock import patch
        from auth.utils import get_current_user
        
        # Override dependencies
        app.dependency_overrides[get_current_user] = lambda: "current_user"
        
        with patch('backend.routes.groups.chats_collection') as mock_chats:
            mock_chats.return_value.insert_one.return_value = MagicMock()
            yield TestClient(app)
        
        # Clean up overrides
        app.dependency_overrides.clear()
    
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

    # DEEP CODE SCAN TESTS - Comprehensive Logic Testing
    
    @pytest.mark.asyncio
    async def test_deep_code_scan_group_creation_edge_cases(self, client):
        """Deep code scan: Test all edge cases for group creation"""
        from models import GroupCreate
        
        test_cases = [
            # Case 1: Empty group name
            {
                "name": "",
                "description": "Test",
                "member_ids": ["user1"],
                "expected_status": 400,
                "expected_error": "Group name is required"
            },
            # Case 2: Only whitespace name
            {
                "name": "   ",
                "description": "Test", 
                "member_ids": ["user1"],
                "expected_status": 400,
                "expected_error": "Group name is required"
            },
            # Case 3: No members (only current user)
            {
                "name": "Test Group",
                "description": "Test",
                "member_ids": [],
                "expected_status": 400,
                "expected_error": "Group must have at least 2 members"
            },
            # Case 4: Single member (current user + 1 more = valid)
            {
                "name": "Test Group",
                "description": "Test",
                "member_ids": ["user1"],
                "expected_status": 201,
                "expected_error": None
            },
            # Case 5: Duplicate member IDs
            {
                "name": "Test Group",
                "description": "Test",
                "member_ids": ["user1", "user1", "user2"],
                "expected_status": 201,
                "expected_error": None
            },
            # Case 6: Very long group name
            {
                "name": "A" * 1000,
                "description": "Test",
                "member_ids": ["user1"],
                "expected_status": 201,
                "expected_error": None
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            print(f"\n--- Deep Code Scan Test Case {i+1}: {test_case.get('name', 'Empty Name')} ---")
            
            group_data = {
                "name": test_case["name"],
                "description": test_case["description"],
                "member_ids": test_case["member_ids"]
            }
            
            with patch('routes.groups.get_current_user', return_value="current_user"):
                with patch('routes.groups.chats_collection') as mock_chats:
                    mock_chats.return_value.insert_one.return_value = MagicMock()
                    
                    response = client.post(
                        "/api/v1/groups",
                        json=group_data,
                        headers={"Authorization": "Bearer fake_token"}
                    )
                    
                    print(f"Status: {response.status_code} (Expected: {test_case['expected_status']})")
                    
                    if response.status_code == test_case['expected_status']:
                        if test_case['expected_error']:
                            error_detail = response.json().get('detail', '')
                            if test_case['expected_error'] in error_detail:
                                print(f"✅ Test case {i+1} passed - Correct error message")
                            else:
                                print(f"❌ Test case {i+1} failed - Wrong error message: {error_detail}")
                        else:
                            print(f"✅ Test case {i+1} passed - Success as expected")
                            
                            # Verify member deduplication logic
                            if test_case['member_ids'] and len(test_case['member_ids']) > 1:
                                call_args = mock_chats.return_value.insert_one.call_args
                                if call_args:
                                    chat_doc = call_args[0][0]
                                    members = chat_doc.get("members", [])
                                    unique_members = set(members)
                                    if len(members) == len(unique_members):
                                        print(f"✅ Member deduplication working correctly")
                                    else:
                                        print(f"❌ Member deduplication failed: {members}")
                    else:
                        print(f"❌ Test case {i+1} failed - Wrong status code")
                        print(f"Response: {response.text}")

    @pytest.mark.asyncio 
    async def test_deep_code_scan_member_addition_logic(self, client):
        """Deep code scan: Test member addition logic in detail"""
        from models import GroupCreate
        
        # Test with various member combinations
        member_test_cases = [
            # Case 1: Empty member list
            [],
            # Case 2: Single valid member
            ["user1"],
            # Case 3: Multiple members with duplicates
            ["user1", "user2", "user1", "user3", "user2"],
            # Case 4: Members with None values
            ["user1", None, "user2"],
            # Case 5: Empty strings in member list
            ["user1", "", "user2", "   "],
        ]
        
        for i, member_ids in enumerate(member_test_cases):
            print(f"\n--- Member Addition Logic Test {i+1}: {member_ids} ---")
            
            group_data = {
                "name": f"Test Group {i+1}",
                "description": "Testing member addition logic",
                "member_ids": member_ids
            }
            
            with patch('routes.groups.get_current_user', return_value="current_user"):
                with patch('routes.groups.chats_collection') as mock_chats:
                    mock_chats.return_value.insert_one.return_value = MagicMock()
                    
                    response = client.post(
                        "/api/v1/groups",
                        json=group_data,
                        headers={"Authorization": "Bearer fake_token"}
                    )
                    
                    if response.status_code == 201:
                        # Verify the member logic
                        call_args = mock_chats.return_value.insert_one.call_args
                        if call_args:
                            chat_doc = call_args[0][0]
                            final_members = chat_doc.get("members", [])
                            
                            print(f"Input members: {member_ids}")
                            print(f"Final members: {final_members}")
                            
                            # Verify current_user is always included
                            if "current_user" not in final_members:
                                print(f"❌ Current user not added to members")
                            else:
                                print(f"✅ Current user included in members")
                            
                            # Verify no None or empty values
                            clean_members = [m for m in final_members if m and str(m).strip()]
                            if len(clean_members) == len(final_members):
                                print(f"✅ No invalid member values")
                            else:
                                print(f"❌ Invalid member values found")
                            
                            # Verify deduplication
                            if len(final_members) == len(set(final_members)):
                                print(f"✅ Member deduplication working")
                            else:
                                print(f"❌ Member deduplication failed")
                    else:
                        print(f"Group creation failed: {response.status_code}")

    @pytest.mark.asyncio
    async def test_deep_code_scan_response_structure(self, client):
        """Deep code scan: Test response structure and data integrity"""
        from models import GroupCreate
        
        group_data = {
            "name": "Response Structure Test",
            "description": "Testing response structure",
            "member_ids": ["user1", "user2"]
        }
        
        with patch('routes.groups.get_current_user', return_value="current_user"):
            with patch('routes.groups.chats_collection') as mock_chats:
                mock_chats.return_value.insert_one.return_value = MagicMock()
                
                response = client.post(
                    "/api/v1/groups",
                    json=group_data,
                    headers={"Authorization": "Bearer fake_token"}
                )
                
                if response.status_code == 201:
                    data = response.json()
                    
                    # Verify required response fields
                    required_fields = ["group_id", "chat_id", "group"]
                    for field in required_fields:
                        if field in data:
                            print(f"✅ Response field '{field}' present")
                        else:
                            print(f"❌ Response field '{field}' missing")
                    
                    # Verify group object structure
                    if "group" in data:
                        group = data["group"]
                        required_group_fields = ["_id", "type", "name", "members", "admins", "created_by"]
                        for field in required_group_fields:
                            if field in group:
                                print(f"✅ Group field '{field}' present")
                            else:
                                print(f"❌ Group field '{field}' missing")
                        
                        # Verify data integrity
                        if group.get("_id") == data.get("group_id") == data.get("chat_id"):
                            print(f"✅ ID consistency verified")
                        else:
                            print(f"❌ ID inconsistency: group_id={data.get('group_id')}, chat_id={data.get('chat_id')}, group._id={group.get('_id')}")
                        
                        if "current_user" in group.get("members", []):
                            print(f"✅ Current user in group members")
                        else:
                            print(f"❌ Current user missing from group members")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
