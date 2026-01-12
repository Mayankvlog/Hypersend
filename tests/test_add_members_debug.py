#!/usr/bin/env python3
"""
Real-time Add Members Debug Script
This script will help identify exactly why add members is not working
"""

import sys
import os
import asyncio
import json
from fastapi.testclient import TestClient

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import required modules
try:
    from main import app
except ImportError:
    print("❌ Could not import main.py. Trying alternative...")
    sys.path.insert(0, os.path.dirname(__file__))
    from backend.main import app

try:
    from auth.utils import get_current_user
except ImportError:
    print("❌ Could not import auth.utils. Trying alternative...")
    from backend.auth.utils import get_current_user

try:
    from routes.groups import GroupMembersUpdate
except ImportError:
    print("❌ Could not import routes.groups. Trying alternative...")
    from backend.routes.groups import GroupMembersUpdate

try:
    from mock_database import chats_collection, users_collection
except ImportError:
    print("❌ Could not import mock_database. Trying alternative...")
    from backend.mock_database import chats_collection, users_collection
from unittest.mock import patch, AsyncMock

class AddMembersDebugger:
    def __init__(self):
        self.client = TestClient(app)
        # Override dependency for testing
        app.dependency_overrides[get_current_user] = lambda: "test_admin_user"
        
    async def setup_test_data(self):
        """Setup test group and users"""
        print("🔧 Setting up test data...")
        
        # Clear existing data
        chats_collection().data.clear()
        users_collection().data.clear()
        
        # Create test group with admin user
        test_group = {
            "_id": "debug_test_group",
            "type": "group",
            "name": "Debug Test Group",
            "members": ["test_admin_user"],
            "admins": ["test_admin_user"],  # Make current user admin
            "created_by": "test_admin_user",
            "created_at": "2026-01-12T00:00:00Z",
            "updated_at": "2026-01-12T00:00:00Z"
        }
        
        # Create test users
        test_users = [
            {
                "_id": "user_to_add_1",
                "name": "User One",
                "email": "user1@test.com",
                "username": "user1",
                "avatar_url": None,
                "is_online": True,
                "status": "active"
            },
            {
                "_id": "user_to_add_2", 
                "name": "User Two",
                "email": "user2@test.com",
                "username": "user2",
                "avatar_url": None,
                "is_online": False,
                "status": "active"
            }
        ]
        
        # Insert test data
        await chats_collection().insert_one(test_group)
        for user in test_users:
            await users_collection().insert_one(user)
            
        print(f"✅ Created test group: {test_group['_id']}")
        print(f"✅ Created {len(test_users)} test users")
        print(f"✅ Admin user: test_admin_user")
        
        return test_group, test_users
    
    def test_add_members_real_time(self):
        """Test add members with real-time debugging"""
        print("\n🚀 Starting Real-Time Add Members Test")
        print("=" * 60)
        
        # Test Case 1: Valid member addition
        print("\n📝 Test Case 1: Valid Member Addition")
        print("-" * 40)
        
        payload = {
            "user_ids": ["user_to_add_1", "user_to_add_2"]
        }
        
        print(f"📤 Request Payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = self.client.post(
                "/api/v1/groups/debug_test_group/members",
                json=payload,
                headers={"Authorization": "Bearer test_token"}
            )
            
            print(f"📥 Response Status: {response.status_code}")
            print(f"📥 Response Body: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ SUCCESS: Added {result.get('added', 0)} members")
            else:
                print(f"❌ FAILED: Status {response.status_code}")
                print(f"❌ Error: {response.text}")
                
        except Exception as e:
            print(f"💥 EXCEPTION: {str(e)}")
        
        # Test Case 2: Empty user list
        print("\n📝 Test Case 2: Empty User List")
        print("-" * 40)
        
        payload = {"user_ids": []}
        
        try:
            response = self.client.post(
                "/api/v1/groups/debug_test_group/members",
                json=payload
            )
            
            print(f"📥 Response Status: {response.status_code}")
            print(f"📥 Response Body: {response.text}")
            
        except Exception as e:
            print(f"💥 EXCEPTION: {str(e)}")
        
        # Test Case 3: Invalid payload
        print("\n📝 Test Case 3: Invalid Payload (None)")
        print("-" * 40)
        
        payload = {"user_ids": None}
        
        try:
            response = self.client.post(
                "/api/v1/groups/debug_test_group/members",
                json=payload
            )
            
            print(f"📥 Response Status: {response.status_code}")
            print(f"📥 Response Body: {response.text}")
            
        except Exception as e:
            print(f"💥 EXCEPTION: {str(e)}")
        
        # Test Case 4: Non-admin user (should fail)
        print("\n📝 Test Case 4: Non-Admin User Test")
        print("-" * 40)
        
        # Override dependency with non-admin user
        app.dependency_overrides[get_current_user] = lambda: "non_admin_user"
        
        payload = {"user_ids": ["user_to_add_1"]}
        
        try:
            response = self.client.post(
                "/api/v1/groups/debug_test_group/members",
                json=payload
            )
            
            print(f"📥 Response Status: {response.status_code}")
            print(f"📥 Response Body: {response.text}")
            
            if response.status_code == 403:
                print("✅ EXPECTED: Non-admin user correctly rejected")
            else:
                print("❌ UNEXPECTED: Non-admin user should be rejected")
                
        except Exception as e:
            print(f"💥 EXCEPTION: {str(e)}")
        
        # Restore admin user
        app.dependency_overrides[get_current_user] = lambda: "test_admin_user"
        
        print("\n" + "=" * 60)
        print("🏁 Real-Time Test Complete")
    
    async def check_group_state(self):
        """Check current group state"""
        print("\n🔍 Checking Current Group State")
        print("-" * 40)
        
        group = await chats_collection().find_one({"_id": "debug_test_group"})
        if group:
            print(f"📋 Group ID: {group.get('_id')}")
            print(f"👥 Group Members: {group.get('members', [])}")
            print(f"👑 Group Admins: {group.get('admins', [])}")
            print(f"📊 Member Count: {len(group.get('members', []))}")
        else:
            print("❌ Group not found!")
    
    async def run_debug_session(self):
        """Run complete debug session"""
        print("🐛 ADD MEMBERS DEBUG SESSION")
        print("=" * 60)
        
        try:
            # Setup test data
            await self.setup_test_data()
            
            # Check initial state
            await self.check_group_state()
            
            # Run real-time tests
            self.test_add_members_real_time()
            
            # Check final state
            await self.check_group_state()
            
        except Exception as e:
            print(f"💥 DEBUG SESSION ERROR: {str(e)}")
            import traceback
            traceback.print_exc()

def main():
    """Main debug function"""
    debugger = AddMembersDebugger()
    
    # Run async debug session
    asyncio.run(debugger.run_debug_session())
    
    print("\n🎯 Debug session completed!")
    print("📝 Check the logs above to identify the issue")

if __name__ == "__main__":
    main()
