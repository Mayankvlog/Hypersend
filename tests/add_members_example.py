#!/usr/bin/env python3
"""
Simple Add Members Working Example
This shows exactly how to add members step by step
"""

import requests
import json

def add_members_example():
    """Complete working example of adding members"""
    
    print("🚀 ADD MEMBERS - COMPLETE WORKING EXAMPLE")
    print("=" * 50)
    
    # Step 1: Get authentication token (you need to login first)
    print("\n📝 Step 1: Login to get token")
    print("-" * 30)
    
    login_data = {
        "email": "your_email@example.com",  # Replace with your email
        "password": "your_password"         # Replace with your password
    }
    
    try:
        # Login request
        login_response = requests.post(
            "https://zaply.in.net/api/v1/auth/login",
            json=login_data
        )
        
        if login_response.status_code == 200:
            login_result = login_response.json()
            token = login_result.get("access_token")
            print(f"✅ Login successful! Token: {token[:20]}...")
        else:
            print(f"❌ Login failed: {login_response.text}")
            return
            
    except Exception as e:
        print(f"❌ Login error: {e}")
        return
    
    # Step 2: Get member suggestions (optional but recommended)
    print("\n📝 Step 2: Get available users to add")
    print("-" * 30)
    
    group_id = "your_group_id"  # Replace with actual group ID
    
    try:
        suggestions_response = requests.get(
            f"https://zaply.in.net/api/v1/groups/{group_id}/member-suggestions",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if suggestions_response.status_code == 200:
            suggestions = suggestions_response.json()
            print(f"✅ Found {len(suggestions)} available users:")
            for user in suggestions[:3]:  # Show first 3
                print(f"   - {user['name']} ({user['email']})")
        else:
            print(f"❌ Failed to get suggestions: {suggestions_response.text}")
            
    except Exception as e:
        print(f"❌ Suggestions error: {e}")
    
    # Step 3: Add members (THE MAIN STEP)
    print("\n📝 Step 3: Add Members to Group")
    print("-" * 30)
    
    # These are the users you want to add
    users_to_add = [
        "user_id_1",  # Replace with actual user IDs
        "user_id_2",  # Replace with actual user IDs
        "user_id_3"   # Replace with actual user IDs
    ]
    
    add_members_payload = {
        "user_ids": users_to_add
    }
    
    print(f"📤 Adding users: {users_to_add}")
    
    try:
        add_response = requests.post(
            f"https://zaply.in.net/api/v1/groups/{group_id}/members",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            json=add_members_payload
        )
        
        print(f"📥 Response Status: {add_response.status_code}")
        print(f"📥 Response Body: {add_response.text}")
        
        if add_response.status_code == 200:
            result = add_response.json()
            added_count = result.get("added", 0)
            print(f"✅ SUCCESS! Added {added_count} members to the group")
            
            if added_count > 0:
                print("🎉 Members added successfully!")
            else:
                print("ℹ️  No new members were added (they might already be in the group)")
                
        elif add_response.status_code == 403:
            print("❌ PERMISSION DENIED: You must be an admin to add members")
            print("💡 Solution: Ask the group admin to add you as an admin first")
            
        elif add_response.status_code == 404:
            print("❌ GROUP NOT FOUND: Check if the group ID is correct")
            print("💡 Solution: Verify the group exists and you're a member")
            
        elif add_response.status_code == 400:
            print("❌ BAD REQUEST: Invalid user IDs or format")
            print("💡 Solution: Check that user_ids is a valid list of strings")
            
        else:
            print(f"❌ ERROR: {add_response.text}")
            
    except Exception as e:
        print(f"❌ Add members error: {e}")
    
    # Step 4: Verify members were added
    print("\n📝 Step 4: Verify Members Added")
    print("-" * 30)
    
    try:
        # Get group info to check members
        group_response = requests.get(
            f"https://zaply.in.net/api/v1/groups/{group_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if group_response.status_code == 200:
            group_info = group_response.json()
            members = group_info.get("group", {}).get("members", [])
            print(f"✅ Group now has {len(members)} members:")
            for member in members[-5:]:  # Show last 5 members
                print(f"   - {member}")
        else:
            print(f"❌ Failed to get group info: {group_response.text}")
            
    except Exception as e:
        print(f"❌ Verification error: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 Add Members Process Complete!")

def troubleshooting_guide():
    """Common issues and solutions"""
    
    print("\n🔧 TROUBLESHOOTING GUIDE")
    print("=" * 50)
    
    issues = [
        {
            "problem": "Getting 403 Forbidden",
            "solution": "You must be an admin of the group. Contact the group owner to make you an admin."
        },
        {
            "problem": "Getting 404 Not Found", 
            "solution": "Group doesn't exist or you're not a member. Check the group ID and ensure you're in the group."
        },
        {
            "problem": "Getting 400 Bad Request",
            "solution": "Invalid user_ids format. Ensure it's a list of valid user ID strings."
        },
        {
            "problem": "Added 0 members",
            "solution": "Users might already be in the group, or user IDs are invalid. Check member suggestions first."
        },
        {
            "problem": "Server error (500)",
            "solution": "Backend issue. Check server logs and try again."
        }
    ]
    
    for i, issue in enumerate(issues, 1):
        print(f"\n{i}. ❌ {issue['problem']}")
        print(f"   💡 {issue['solution']}")

def quick_test():
    """Quick test to check if add members is working"""
    
    print("\n⚡ QUICK TEST")
    print("-" * 30)
    
    # Test with minimal data
    test_payload = {
        "user_ids": ["test_user_123"]
    }
    
    print("🧪 Testing add members endpoint...")
    print(f"📤 Test payload: {test_payload}")
    
    try:
        response = requests.post(
            "http://localhost:8000/api/v1/groups/test_group/members",
            json=test_payload,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"📥 Status: {response.status_code}")
        print(f"📥 Body: {response.text}")
        
        if response.status_code in [200, 403, 404, 400]:
            print("✅ Endpoint is working (response is expected)")
        else:
            print("❌ Endpoint might have issues")
            
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("💡 Make sure the backend server is running on localhost:8000")

if __name__ == "__main__":
    print("🎯 ADD MEMBERS - COMPLETE GUIDE")
    print("Choose an option:")
    print("1. Full working example")
    print("2. Troubleshooting guide") 
    print("3. Quick test")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == "1":
        add_members_example()
    elif choice == "2":
        troubleshooting_guide()
    elif choice == "3":
        quick_test()
    else:
        print("Running quick test by default...")
        quick_test()
