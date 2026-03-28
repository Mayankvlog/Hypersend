#!/usr/bin/env python3
"""
Test to trigger upload completion and see database debug info
"""

import asyncio
import aiohttp
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

async def test_upload_db_debug():
    """Test upload completion to see database debug info"""
    print("🔍 Testing Upload Database Connection")
    print("=" * 50)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register and login
        print("📝 Registering user...")
        register_data = {
            "email": f"dbdebug_{datetime.now().timestamp()}@example.com",
            "password": "TestPassword123",
            "full_name": "Debug User"
        }
        
        async with session.post(f"{BASE_URL}/api/v1/auth/register", json=register_data) as resp:
            if resp.status not in [201, 409]:
                print(f"❌ Registration failed: {resp.status}")
                return
            print("✅ User registered")
        
        # Step 2: Login
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
        
        # Step 3: Create chat
        chat_data = {
            "name": "Debug Chat",
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
        
        # Step 4: Initiate upload
        upload_data = {
            "filename": "debug_file.txt",
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
        
        # Step 5: Try to complete upload (this should trigger database debug logging)
        print("🔧 Attempting upload completion...")
        
        async with session.post(f"{BASE_URL}/api/v1/files/{upload_id}/complete", headers=headers) as resp:
            print(f"🔍 Completion response: {resp.status}")
            if resp.status == 403:
                print("⚠️ 403 Forbidden - expected for this test")
                print("🔍 Check backend logs for database connection debug info")
            elif resp.status in [200, 201]:
                complete_result = await resp.json()
                file_id = complete_result.get("file_id")
                print(f"✅ Upload completed! File ID: {file_id}")
            else:
                error_text = await resp.text()
                print(f"❌ Upload completion failed: {resp.status}")
                print(f"❌ Error: {error_text}")

if __name__ == "__main__":
    asyncio.run(test_upload_db_debug())
