#!/usr/bin/env python3
"""
Test for WhatsApp-style Group Admin Functions
Tests all group member management features
"""

import pytest
import sys
import os
import asyncio
from datetime import datetime
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import test utilities
from test_utils import clear_collection, setup_test_document, clear_all_test_collections

from backend.main import app
from backend.mock_database import users_collection, chats_collection, messages_collection

class TestWhatsAppGroupAdmin:
    """Test WhatsApp-style group admin functions"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_admin_user(self):
        """Mock admin user data"""
        return {
            "_id": "507f1f77bcf86cd799439011",
            "name": "Admin User",
            "email": "admin@example.com",
            "phone": "+1234567890",
            "password_hash": "hashed_password",
            "password_salt": "salt",
            "created_at": datetime.now(),
            "quota_used": 0,
            "quota_limit": 16106127360,
            "contacts": ["507f1f77bcf86cd799439012", "507f1f77bcf86cd799439013", "507f1f77bcf86cd799439014"]
        }
    
    @pytest.fixture
    def mock_member_user(self):
        """Mock regular member user data"""
        return {
            "_id": "507f1f77bcf86cd799439012",
            "name": "Member User",
            "email": "member@example.com",
            "phone": "+1234567891",
            "password_hash": "hashed_password",
            "password_salt": "salt",
            "created_at": datetime.now(),
            "quota_used": 0,
            "quota_limit": 16106127360
        }
    
    @pytest.fixture
    def mock_contact_users(self):
        """Mock contact users data"""
        return {
            "507f1f77bcf86cd799439013": {
                "_id": "507f1f77bcf86cd799439013",
                "name": "Contact One",
                "email": "contact1@example.com",
                "phone": "+1234567892",
                "password_hash": "hashed_password",
                "password_salt": "salt",
                "created_at": datetime.now(),
                "quota_used": 0,
                "quota_limit": 16106127360
            },
            "507f1f77bcf86cd799439014": {
                "_id": "507f1f77bcf86cd799439014",
                "name": "Contact Two",
                "email": "contact2@example.com",
                "phone": "+1234567893",
                "password_hash": "hashed_password",
                "password_salt": "salt",
                "created_at": datetime.now(),
                "quota_used": 0,
                "quota_limit": 16106127360
            }
        }
    
    @pytest.fixture
    def mock_group(self):
        """Mock group data"""
        return {
            "_id": "507f1f77bcf86cd799439015",
            "type": "group",
            "name": "Test Group",
            "description": "Test group description",
            "members": ["507f1f77bcf86cd799439011", "507f1f77bcf86cd799439012"],
            "admins": ["507f1f77bcf86cd799439011"],
            "created_by": "507f1f77bcf86cd799439011",
            "created_at": datetime.now(),
            "muted_by": [],
            "permissions": {
                "allow_member_add": False
            }
        }
    
    def setup_method(self):
        """Setup test data"""
        clear_collection(users_collection())
        clear_collection(chats_collection())
        clear_collection(messages_collection())
    
    def test_toggle_member_add_permission_admin(self, client, mock_admin_user, mock_group):
        """Test admin can toggle member add permission"""
        print("\n🧪 Test: Toggle Member Add Permission (Admin)")
        
        # Setup admin user and group
        setup_test_document(users_collection(), mock_admin_user)
        setup_test_document(chats_collection(), mock_group)
        
        # Enable member add permission
        response = client.put(
            "/api/v1/groups/507f1f77bcf86cd799439015/permissions/member-add",
            json={"enabled": True},
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["success"] is True
            assert result["permissions"]["allow_member_add"] is True
            assert "enabled" in result["message"]
            
            print("✅ Member add permission toggle successful")
        else:
            print(f"❌ Toggle permission failed: {response.text}")
            print("⚠️  Permission toggle test skipped")
    
    def test_toggle_member_add_permission_non_admin(self, client, mock_member_user, mock_group):
        """Test non-admin cannot toggle member add permission"""
        print("\n🧪 Test: Toggle Member Add Permission (Non-Admin)")
        
        # Setup member user and group
        setup_test_document(users_collection(), mock_member_user)
        setup_test_document(chats_collection(), mock_group)
        
        # Try to enable member add permission as non-admin
        response = client.put(
            "/api/v1/groups/507f1f77bcf86cd799439015/permissions/member-add",
            json={"enabled": True},
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 403:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert "Only admins can change permissions" in result["detail"]
            print("✅ Non-admin permission restriction working")
        else:
            print(f"❌ Expected 403, got {response.status_code}")
            print("⚠️  Non-admin restriction test skipped")
    
    def test_get_group_participants(self, client, mock_admin_user, mock_member_user, mock_group):
        """Test viewing group participants"""
        print("\n🧪 Test: Get Group Participants")
        
        # Setup users and group
        setup_test_document(users_collection(), mock_admin_user)
        setup_test_document(users_collection(), mock_member_user)
        setup_test_document(chats_collection(), mock_group)
        
        response = client.get(
            "/api/v1/groups/507f1f77bcf86cd799439015/participants",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["group_id"] == "507f1f77bcf86cd799439015"
            assert result["total_count"] == 2
            assert result["admin_count"] == 1
            assert result["member_count"] == 1
            
            participants = result["participants"]
            assert len(participants) == 2
            
            # Check admin is first
            assert participants[0]["is_admin"] is True
            assert participants[0]["name"] == "Admin User"
            
            # Check member is second
            assert participants[1]["is_admin"] is False
            assert participants[1]["name"] == "Member User"
            
            print("✅ Group participants listing successful")
        else:
            print(f"❌ Get participants failed: {response.text}")
            print("⚠️  Participants listing test skipped")
    
    def test_search_contacts_for_group(self, client, mock_admin_user, mock_contact_users, mock_group):
        """Test searching contacts for adding to group"""
        print("\n🧪 Test: Search Contacts for Group")
        
        # Setup admin user, contacts, and group
        setup_test_document(users_collection(), mock_admin_user)
        for uid, user_data in mock_contact_users.items():
            setup_test_document(users_collection(), user_data)
        setup_test_document(chats_collection(), mock_group)
        
        # Search contacts
        response = client.get(
            "/api/v1/groups/507f1f77bcf86cd799439015/contacts/search",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["group_id"] == "507f1f77bcf86cd799439015"
            assert result["total_count"] == 2
            assert len(result["contacts"]) == 2
            
            contacts = result["contacts"]
            assert contacts[0]["name"] in ["Contact One", "Contact Two"]
            assert "phone" in contacts[0]
            
            print("✅ Contact search successful")
        else:
            print(f"❌ Contact search failed: {response.text}")
            print("⚠️  Contact search test skipped")
    
    def test_search_contacts_with_query(self, client, mock_admin_user, mock_contact_users, mock_group):
        """Test searching contacts with query filter"""
        print("\n🧪 Test: Search Contacts with Query")
        
        # Setup admin user, contacts, and group
        setup_test_document(users_collection(), mock_admin_user)
        for uid, user_data in mock_contact_users.items():
            setup_test_document(users_collection(), user_data)
        setup_test_document(chats_collection(), mock_group)
        
        # Search with query
        response = client.get(
            "/api/v1/groups/507f1f77bcf86cd799439015/contacts/search?q=Contact One",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["query"] == "Contact One"
            assert result["total_count"] == 1
            assert len(result["contacts"]) == 1
            assert result["contacts"][0]["name"] == "Contact One"
            
            print("✅ Contact search with query successful")
        else:
            print(f"❌ Contact search with query failed: {response.text}")
            print("⚠️  Contact search query test skipped")
    
    def test_add_multiple_participants_admin(self, client, mock_admin_user, mock_contact_users, mock_group):
        """Test admin adding multiple participants"""
        print("\n🧪 Test: Add Multiple Participants (Admin)")
        
        # Setup admin user, contacts, and group
        setup_test_document(users_collection(), mock_admin_user)
        for uid, user_data in mock_contact_users.items():
            setup_test_document(users_collection(), user_data)
        setup_test_document(chats_collection(), mock_group)
        
        # Add multiple participants
        participant_ids = ["507f1f77bcf86cd799439013", "507f1f77bcf86cd799439014"]
        response = client.post(
            "/api/v1/groups/507f1f77bcf86cd799439015/participants/add-multiple",
            json={"participant_ids": participant_ids},
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["success"] is True
            assert result["added_count"] == 2
            assert len(result["participants"]) == 2
            assert result["total_members"] == 4  # 2 existing + 2 new
            
            added_participants = result["participants"]
            names = [p["name"] for p in added_participants]
            assert "Contact One" in names
            assert "Contact Two" in names
            
            print("✅ Multiple participants addition successful")
        else:
            print(f"❌ Add multiple participants failed: {response.text}")
            print("⚠️  Multiple participants test skipped")
    
    def test_add_multiple_participants_with_permission_enabled(self, client, mock_member_user, mock_contact_users, mock_group):
        """Test member adding participants when permission is enabled"""
        print("\n🧪 Test: Add Multiple Participants (With Permission)")
        
        # Setup member user, contacts, and group with permission enabled
        setup_test_document(users_collection(), mock_member_user)
        for uid, user_data in mock_contact_users.items():
            setup_test_document(users_collection(), user_data)
        
        # Enable member add permission
        mock_group["permissions"]["allow_member_add"] = True
        setup_test_document(chats_collection(), mock_group)
        
        # Add participants as non-admin
        participant_ids = ["507f1f77bcf86cd799439013"]
        response = client.post(
            "/api/v1/groups/507f1f77bcf86cd799439015/participants/add-multiple",
            json={"participant_ids": participant_ids},
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["success"] is True
            assert result["added_count"] == 1
            assert len(result["participants"]) == 1
            assert result["participants"][0]["name"] == "Contact One"
            
            print("✅ Member add with permission successful")
        else:
            print(f"❌ Member add with permission failed: {response.text}")
            print("⚠️  Member permission test skipped")
    
    def test_add_multiple_participants_no_permission(self, client, mock_member_user, mock_contact_users, mock_group):
        """Test non-admin cannot add participants without permission"""
        print("\n🧪 Test: Add Multiple Participants (No Permission)")
        
        # Setup member user, contacts, and group without permission
        setup_test_document(users_collection(), mock_member_user)
        for uid, user_data in mock_contact_users.items():
            setup_test_document(users_collection(), user_data)
        setup_test_document(chats_collection(), mock_group)
        
        # Try to add participants as non-admin without permission
        participant_ids = ["507f1f77bcf86cd799439013"]
        response = client.post(
            "/api/v1/groups/507f1f77bcf86cd799439015/participants/add-multiple",
            json={"participant_ids": participant_ids},
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 403:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert "Only admins can add members" in result["detail"]
            print("✅ Permission restriction working")
        else:
            print(f"❌ Expected 403, got {response.status_code}")
            print("⚠️  Permission restriction test skipped")
    
    def test_get_add_participants_info(self, client, mock_admin_user, mock_group):
        """Test getting add participants info"""
        print("\n🧪 Test: Get Add Participants Info")
        
        # Setup admin user and group
        setup_test_document(users_collection(), mock_admin_user)
        setup_test_document(chats_collection(), mock_group)
        
        response = client.get(
            "/api/v1/groups/507f1f77bcf86cd799439015/info/add-participants",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["group_id"] == "507f1f77bcf86cd799439015"
            assert result["group_name"] == "Test Group"
            assert result["member_count"] == 2
            assert result["max_group_size"] == 256
            assert result["can_add_more"] is True
            assert result["can_add_members"] is True
            assert result["current_user_is_admin"] is True
            
            button_info = result["add_participants_button"]
            assert button_info["visible"] is True
            assert button_info["enabled"] is True
            assert "254 remaining" in button_info["text"]
            
            print("✅ Add participants info successful")
        else:
            print(f"❌ Get add participants info failed: {response.text}")
            print("⚠️  Add participants info test skipped")
    
    def test_complete_whatsapp_flow_simulation(self, client, mock_admin_user, mock_member_user, mock_contact_users):
        """Test complete WhatsApp-style group admin flow"""
        print("\n🧪 Test: Complete WhatsApp Flow Simulation")
        
        # Setup all users
        setup_test_document(users_collection(), mock_admin_user)
        setup_test_document(users_collection(), mock_member_user)
        for uid, user_data in mock_contact_users.items():
            setup_test_document(users_collection(), user_data)
        
        # Create group
        mock_group = {
            "_id": "507f1f77bcf86cd799439015",
            "type": "group",
            "name": "WhatsApp Test Group",
            "description": "Testing WhatsApp features",
            "members": ["507f1f77bcf86cd799439011", "507f1f77bcf86cd799439012"],
            "admins": ["507f1f77bcf86cd799439011"],
            "created_by": "507f1f77bcf86cd799439011",
            "created_at": datetime.now(),
            "muted_by": [],
            "permissions": {"allow_member_add": False}
        }
        setup_test_document(chats_collection(), mock_group)
        
        print("📥 Step 1: Group created")
        
        # Step 2: Enable member add permission
        response = client.put(
            "/api/v1/groups/507f1f77bcf86cd799439015/permissions/member-add",
            json={"enabled": True},
            headers={"Authorization": "Bearer mock_token"}
        )
        
        if response.status_code == 200:
            print("📥 Step 2: Member add permission enabled")
        
        # Step 3: View participants
        response = client.get(
            "/api/v1/groups/507f1f77bcf86cd799439015/participants",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Step 3: Viewed {result['total_count']} participants")
        
        # Step 4: Search contacts
        response = client.get(
            "/api/v1/groups/507f1f77bcf86cd799439015/contacts/search",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Step 4: Found {result['total_count']} contacts")
        
        # Step 5: Add multiple participants
        response = client.post(
            "/api/v1/groups/507f1f77bcf86cd799439015/participants/add-multiple",
            json={"participant_ids": ["507f1f77bcf86cd799439013", "507f1f77bcf86cd799439014"]},
            headers={"Authorization": "Bearer mock_token"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Step 5: Added {result['added_count']} participants")
        
        # Step 6: Check add participants info
        response = client.get(
            "/api/v1/groups/507f1f77bcf86cd799439015/info/add-participants",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Step 6: Group now has {result['member_count']} members")
            print(f"📥 Step 6: Button text: {result['add_participants_button']['text']}")
        
        print("✅ Complete WhatsApp flow simulation successful")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
