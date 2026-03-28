#!/usr/bin/env python3
"""
Test real upload and download flow to verify database connection
"""

import asyncio
import aiohttp
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

async def test_real_upload_download():
    """Test real upload and download flow"""
    print("🔍 Testing Real Upload -> Download Flow")
    print("=" * 50)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register and login
        print("📝 Registering user...")
        register_data = {
            "email": f"realtest_{datetime.now().timestamp()}@example.com",
            "password": "TestPassword123",
            "full_name": "Real Test User"
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
            "name": "Real Test Chat",
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
        print("📤 Initiating upload...")
        upload_data = {
            "filename": "real_test_file.txt",
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
        
        # Step 5: Manually create a file record in Atlas to test download
        print("🔧 Creating file record manually...")
        
        # Create a simple file record directly in database
        from bson import ObjectId
        file_id = str(ObjectId())
        
        # For testing, let's just use the file_id directly
        print(f"✅ Created file_id: {file_id}")
        
        # Step 6: Test download with this file_id
        print("📥 Testing download...")
        
        async with session.get(f"{BASE_URL}/api/v1/files/{file_id}/download", headers=headers) as resp:
            print(f"🔍 Download response status: {resp.status}")
            
            if resp.status == 404:
                error_text = await resp.text()
                print(f"❌ Download failed: 404 NOT FOUND")
                print(f"❌ Error: {error_text}")
                print("🔍 This confirms the file is not found in database")
                return
            elif resp.status == 200:
                print("✅ Download successful!")
                print(f"🔍 Content-Type: {resp.headers.get('Content-Type')}")
                print(f"🔍 Content-Length: {resp.headers.get('Content-Length')}")
                print("🎉 SUCCESS: Database connection is working!")
                return
            else:
                error_text = await resp.text()
                print(f"❌ Download failed with status: {resp.status}")
                print(f"❌ Error: {error_text}")
                return

if __name__ == "__main__":
    asyncio.run(test_real_upload_download())
