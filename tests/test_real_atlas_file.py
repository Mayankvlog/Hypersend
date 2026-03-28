#!/usr/bin/env python3
"""
Test with real Atlas file to verify 404 fix
"""

import asyncio
import aiohttp
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

async def test_real_atlas_file():
    """Test with real Atlas file to verify 404 fix"""
    print("🎯 TESTING WITH REAL ATLAS FILE")
    print("=" * 50)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register and login
        print("📝 Registering user...")
        register_data = {
            "email": f"atlastest_{datetime.now().timestamp()}@example.com",
            "password": "TestPassword123",
            "full_name": "Atlas Test User"
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
        
        # Step 2: Try to create a real file and then download it
        print("🔧 Creating real file...")
        
        # Create chat
        chat_data = {
            "name": "Atlas Test Chat",
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
        
        # Initiate upload
        upload_data = {
            "filename": "atlas_test_file.txt",
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
        
        # Try to complete upload (this should create file record in Atlas)
        print("🔧 Completing upload...")
        
        async with session.post(f"{BASE_URL}/api/v1/files/{upload_id}/complete", headers=headers) as resp:
            print(f"🔍 Upload completion response: {resp.status}")
            
            if resp.status in [200, 201]:
                complete_result = await resp.json()
                file_id = complete_result.get("file_id")
                if file_id:
                    print(f"✅ Upload completed! File ID: {file_id}")
                    
                    # Now test download with the real file_id
                    print("📥 Testing download with real Atlas file...")
                    
                    async with session.get(f"{BASE_URL}/api/v1/files/{file_id}/download", headers=headers) as download_resp:
                        print(f"🔍 Download response status: {download_resp.status}")
                        
                        if download_resp.status == 200:
                            print("✅ SUCCESS! 404 ERROR FIXED!")
                            print("🎉 Real Atlas file download works!")
                            return True
                        elif download_resp.status == 404:
                            print("❌ Still getting 404 even with real Atlas file")
                            print("🔍 This confirms database connection issue")
                            return False
                        else:
                            print(f"❌ Unexpected status: {download_resp.status}")
                            return False
                else:
                    print("❌ No file_id in complete response")
                    return False
            else:
                error_text = await resp.text()
                print(f"❌ Upload completion failed: {resp.status}")
                print(f"❌ Error: {error_text}")
                return False

if __name__ == "__main__":
    result = asyncio.run(test_real_atlas_file())
    
    if result:
        print("\n🎉 404 ERROR FIX SUCCESSFUL!")
        print("📌 Real Atlas file download works")
        print("📌 Database connection issue resolved")
    else:
        print("\n❌ 404 ERROR FIX FAILED")
        print("📌 Database connection issue persists")
