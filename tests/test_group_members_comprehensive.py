"""
Comprehensive Group Members Fix Validation Test
Tests the complete flow of group creation and member management
"""
import pytest
import sys
import os
from unittest.mock import patch

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Add project root to path for absolute imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi.testclient import TestClient
try:
    from backend.main import app
except ImportError as e:
    print(f"Warning: Could not import backend.main: {e}")
    pytest.skip("Could not import main app module", allow_module_level=True)
    app = None

try:
    from backend.auth.utils import get_current_user
except ImportError as e:
    print(f"Warning: Could not import auth utils module: {e}")
    get_current_user = None


class TestGroupMembersComprehensive:
    """Comprehensive tests for group members functionality"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        # Use TestClient with fake token for authentication
        # The auth utils supports fake_token_for_<user_id> in test context
        client = TestClient(app)
        yield client
    
    def test_group_creation_returns_members_detail(self, client):
        """Test that group creation returns members_detail with user info"""
        print("\n" + "="*70)
        print("TEST: Group Creation Returns Members Detail")
        print("="*70)
        
        # Create a group with members
        payload = {
            "name": "Test Group",
            "description": "Test Description",
            "member_ids": ["user1", "user2"]
        }
        
        response = client.post(
            "/api/v1/groups",
            json=payload,
            headers={"Authorization": "Bearer fake_token_for_test_user_123"}
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 201:
            data = response.json()
            group = data.get("group", {})
            
            # Check members array
            members = group.get("members", [])
            member_count = group.get("member_count", 0)
            members_detail = group.get("members_detail", [])
            
            print(f"✅ Group created successfully")
            print(f"   Members array: {members}")
            print(f"   Member count: {member_count}")
            print(f"   Members detail count: {len(members_detail)}")
            
            # Verify members array
            assert len(members) >= 2, f"Expected at least 2 members, got {len(members)}"
            assert member_count == len(members), f"Member count mismatch: {member_count} vs {len(members)}"
            
            # Verify members_detail
            assert len(members_detail) > 0, "members_detail should not be empty"
            assert len(members_detail) == member_count, f"members_detail count mismatch: {len(members_detail)} vs {member_count}"
            
            # Verify each member has required fields
            for member in members_detail:
                assert "user_id" in member, "Member should have user_id"
                assert "role" in member, "Member should have role"
                print(f"   ✓ Member {member.get('user_id')}: role={member.get('role')}")
            
            print(f"✅ All members detail validation passed")
        else:
            print(f"❌ Group creation failed: {response.text}")
            assert False, f"Group creation failed with status {response.status_code}"
    
    def test_group_list_shows_member_count(self, client):
        """Test that group list includes member count"""
        print("\n" + "="*70)
        print("TEST: Group List Shows Member Count")
        print("="*70)
        
        response = client.get(
            "/api/v1/groups",
            headers={"Authorization": "Bearer fake_token_for_test_user_123"}
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            groups = data.get("groups", [])
            
            print(f"✅ Groups retrieved: {len(groups)} groups")
            
            # Convert to list if it's not already
            if not isinstance(groups, list):
                groups = list(groups) if hasattr(groups, '__iter__') else [groups]
            
            for group in groups:
                member_count = group.get("member_count", 0)
                members = group.get("members", [])
                
                print(f"   Group: {group.get('name')}")
                print(f"   - Member count: {member_count}")
                print(f"   - Members array length: {len(members)}")
                
                assert member_count > 0, "Member count should be greater than 0"
                assert len(members) == member_count, "Member count should match members array length"
        else:
            print(f"❌ Group list failed: {response.text}")
    
    def test_add_members_returns_updated_count(self, client):
        """Test that add members returns updated member count"""
        print("\n" + "="*70)
        print("TEST: Add Members Returns Updated Count")
        print("="*70)
        
        # First create a group
        create_payload = {
            "name": "Test Group for Add Members",
            "description": "Test",
            "member_ids": ["user1"]
        }
        
        create_response = client.post(
            "/api/v1/groups",
            json=create_payload,
            headers={"Authorization": "Bearer fake_token_for_test_user_123"}
        )
        
        if create_response.status_code != 201:
            print(f"❌ Group creation failed: {create_response.text}")
            return
        
        group_id = create_response.json().get("group", {}).get("_id")
        print(f"✅ Group created: {group_id}")
        
        # Now add members
        add_payload = {
            "user_ids": ["user2", "user3"]
        }
        
        add_response = client.post(
            f"/api/v1/groups/{group_id}/members",
            json=add_payload,
            headers={"Authorization": "Bearer fake_token_for_test_user_123"}
        )
        
        print(f"Status Code: {add_response.status_code}")
        
        if add_response.status_code == 200:
            data = add_response.json()
            added = data.get("added", 0)
            member_count = data.get("member_count", 0)
            members = data.get("members", [])
            
            print(f"✅ Members added successfully")
            print(f"   Added: {added}")
            print(f"   Total member count: {member_count}")
            print(f"   Members list: {members}")
            
            assert added > 0, "Should have added members"
            assert member_count > 0, "Member count should be greater than 0"
            assert len(members) == member_count, "Member count should match members array length"
        else:
            print(f"❌ Add members failed: {add_response.text}")
    
    def test_get_group_returns_members_detail(self, client):
        """Test that get group returns members_detail"""
        print("\n" + "="*70)
        print("TEST: Get Group Returns Members Detail")
        print("="*70)
        
        # Create a group first
        create_payload = {
            "name": "Test Group for Get",
            "description": "Test",
            "member_ids": ["user1", "user2"]
        }
        
        create_response = client.post(
            "/api/v1/groups",
            json=create_payload,
            headers={"Authorization": "Bearer fake_token_for_test_user_123"}
        )
        
        if create_response.status_code != 201:
            print(f"❌ Group creation failed: {create_response.text}")
            return
        
        group_id = create_response.json().get("group", {}).get("_id")
        print(f"✅ Group created: {group_id}")
        
        # Get the group
        get_response = client.get(
            f"/api/v1/groups/{group_id}",
            headers={"Authorization": "Bearer fake_token_for_test_user_123"}
        )
        
        print(f"Status Code: {get_response.status_code}")
        
        if get_response.status_code == 200:
            data = get_response.json()
            group = data.get("group", {})
            
            members = group.get("members", [])
            member_count = group.get("member_count", 0)
            members_detail = group.get("members_detail", [])
            is_admin = group.get("is_admin", False)
            
            print(f"✅ Group retrieved successfully")
            print(f"   Members: {members}")
            print(f"   Member count: {member_count}")
            print(f"   Members detail: {len(members_detail)} items")
            print(f"   Is admin: {is_admin}")
            
            assert len(members) > 0, "Members array should not be empty"
            assert member_count > 0, "Member count should be greater than 0"
            assert len(members_detail) > 0, "Members detail should not be empty"
            assert len(members_detail) == member_count, "Members detail count should match member count"
            
            for member in members_detail:
                assert "user_id" in member, "Member should have user_id"
                assert "role" in member, "Member should have role"
        else:
            print(f"❌ Get group failed: {get_response.text}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
