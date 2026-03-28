#!/usr/bin/env python3
"""
Final 404 Error Test - Complete Upload -> Download Flow
"""

import asyncio
import aiohttp
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

async def final_404_test():
    """Final test for 404 error fix"""
    print("🎯 FINAL 404 ERROR TEST")
    print("=" * 50)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register and login
        print("📝 Registering user...")
        register_data = {
            "email": f"finaltest_{datetime.now().timestamp()}@example.com",
            "password": "TestPassword123",
            "full_name": "Final Test User"
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
        
        # Step 2: Create chat
        print("💬 Creating chat...")
        chat_data = {
            "name": "Final Test Chat",
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
        
        # Step 3: Initiate upload
        print("📤 Initiating upload...")
        upload_data = {
            "filename": "final_test_file.txt",
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
        
        # Step 4: Test upload completion
        print("🔧 Testing upload completion...")
        
        async with session.post(f"{BASE_URL}/api/v1/files/{upload_id}/complete", headers=headers) as resp:
            print(f"🔍 Upload completion response: {resp.status}")
            
            if resp.status in [200, 201]:
                complete_result = await resp.json()
                file_id = complete_result.get("file_id")
                if file_id:
                    print(f"✅ Upload completed! File ID: {file_id}")
                    
                    # Step 5: Test download
                    print("📥 Testing download...")
                    
                    async with session.get(f"{BASE_URL}/api/v1/files/{file_id}/download", headers=headers) as download_resp:
                        print(f"🔍 Download response: {download_resp.status}")
                        
                        if download_resp.status == 200:
                            print("✅ SUCCESS! 404 ERROR FIXED!")
                            print("🎉 Upload completion and download both work!")
                            return True
                        elif download_resp.status == 404:
                            print("❌ Still getting 404 even after upload completion")
                            return False
                        else:
                            print(f"❌ Download failed with status: {download_resp.status}")
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
    result = asyncio.run(final_404_test())
    
    if result:
        print("\n🎉 404 ERROR FIX SUCCESSFUL!")
        print("📌 Upload completion works")
        print("📌 File records are created in database")
        print("📌 File download works")
        print("📌 404 ERROR PERMANENTLY FIXED!")
    else:
        print("\n❌ 404 ERROR FIX FAILED")
        print("📌 Need further investigation")
