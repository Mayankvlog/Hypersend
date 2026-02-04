#!/usr/bin/env python3
"""Simple test for group member addition"""

import os
import sys
import requests

# Test the group member addition endpoint directly
API_BASE_URL = "https://zaply.in.net/api/v1"

def test_add_member():
    """Test adding member to group"""
    print("Testing group member addition...")
    
    # First create a group
    group_data = {
        "name": "Test Group",
        "member_ids": ["admin@test.com"]
    }
    
    try:
        # Create group
        response = requests.post(f"{API_BASE_URL}/groups", json=group_data)
        print(f"Group creation: {response.status_code}")
        
        if response.status_code not in [200, 201]:
            print(f"❌ Group creation failed: {response.text}")
            return False
        
        group_info = response.json()
        group_id = group_info.get("group_id")
        
        if not group_id:
            print("❌ No group_id in response")
            return False
        
        print(f"✅ Group created with ID: {group_id}")
        
        # Now try to add a member
        member_payload = {
            "user_ids": ["member@test.com"]
        }
        
        response = requests.post(f"{API_BASE_URL}/groups/{group_id}/members", json=member_payload)
        print(f"Member addition: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            added = result.get("added", 0)
            print(f"✅ Members added: {added}")
            return added > 0
        else:
            print(f"❌ Member addition failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

if __name__ == "__main__":
    success = test_add_member()
    if success:
        print("🎉 Group member addition working!")
    else:
        print("❌ Group member addition failed!")
