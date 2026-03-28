#!/usr/bin/env python3
"""
Test database connection directly via API endpoint
"""

import asyncio
import aiohttp
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

async def test_direct_database():
    """Test database connection via API"""
    print("🔍 Testing Database Connection via API")
    print("=" * 50)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register and login
        print("📝 Registering user...")
        register_data = {
            "email": f"dbtest_{datetime.now().timestamp()}@example.com",
            "password": "TestPassword123",
            "full_name": "Database Test User"
        }
        
        async with session.post(f"{BASE_URL}/api/v1/auth/register", json=register_data) as resp:
            if resp.status not in [201, 409]:
                print(f"❌ Registration failed: {resp.status}")
                return
            print("✅ User registered")
        
        login_data = {
            "email": register_data["email"],
            "password": register_data["password"]
        }
        
        async with session.post(f"{BASE_URL}/api/v1/auth/login", json=login_data) as resp:
            if resp.status != 200:
                print(f"❌ Login failed: {resp.status}")
                return
            login_result = await resp.json()
            token = login_result.get("access_token")
            headers = {"Authorization": f"Bearer {token}"}
            print("✅ Login successful")
        
        # Step 2: Create chat (this should access database)
        print("💬 Creating chat...")
        chat_data = {
            "name": "Database Test Chat",
            "type": "group",
            "member_ids": []
        }
        
        async with session.post(f"{BASE_URL}/api/v1/chats", json=chat_data, headers=headers) as resp:
            if resp.status not in [201, 200]:
                print(f"❌ Chat creation failed: {resp.status}")
                return
            chat_result = await resp.json()
            chat_id = chat_result.get("id") or chat_result.get("_id")
            print(f"✅ Chat created: {chat_id}")
        
        # Step 3: Initiate upload (this should access database)
        print("📤 Initiating upload...")
        upload_data = {
            "filename": "database_test_file.txt",
            "file_size": 12,
            "mime_type": "text/plain",
            "chat_id": chat_id
        }
        
        async with session.post(f"{BASE_URL}/api/v1/files/init", json=upload_data, headers=headers) as resp:
            if resp.status not in [200, 201]:
                print(f"❌ Upload initiation failed: {resp.status}")
                return
            upload_result = await resp.json()
            upload_id = upload_result.get("media_id") or upload_result.get("upload_id")
            print(f"✅ Upload initiated: {upload_id}")
        
        # Step 4: Check if upload record is in database
        print("🔍 Checking database connection...")
        
        # Try to access the upload record (this should trigger database access)
        async with session.get(f"{BASE_URL}/api/v1/files/{upload_id}/status", headers=headers) as resp:
            print(f"🔍 Upload status response: {resp.status}")
            if resp.status == 200:
                status_result = await resp.json()
                print(f"✅ Upload record found in database")
                print(f"🔍 Upload status: {status_result.get('status', 'unknown')}")
            else:
                print(f"❌ Upload record not found: {resp.status}")
        
        print("\n🎯 CONCLUSION:")
        print("📌 If upload record is found, database connection works")
        print("📌 If download still fails, the issue is in download endpoint logic")
        print("📌 If upload record is not found, database connection is broken")

if __name__ == "__main__":
    asyncio.run(test_direct_database())
