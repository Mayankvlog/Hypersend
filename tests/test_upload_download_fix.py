#!/usr/bin/env python3
"""
Test script to verify the upload -> complete -> message -> download flow fix
"""

import asyncio
import aiohttp
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

async def test_flow():
    """Test the complete upload -> complete -> message -> download flow"""
    print("🧪 Testing Upload -> Complete -> Message -> Download Flow")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register a test user
        print("📝 Step 1: Registering test user...")
        register_data = {
            "email": f"testuser_{datetime.now().timestamp()}@example.com",
            "password": "TestPassword123",
            "full_name": "Test User"
        }
        
        async with session.post(f"{BASE_URL}/api/v1/auth/register", json=register_data) as resp:
            if resp.status not in [201, 409]:  # 201 created or 409 already exists
                error_text = await resp.text()
                print(f"❌ Registration failed: {resp.status}")
                print(f"❌ Error details: {error_text}")
                return
            print("✅ User registration successful")
        
        # Step 2: Login
        print("🔐 Step 2: Logging in...")
        login_data = {
            "email": register_data["email"],
            "password": register_data["password"]
        }
        
        async with session.post(f"{BASE_URL}/api/v1/auth/login", json=login_data) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                print(f"❌ Login failed: {resp.status}")
                print(f"❌ Error details: {error_text}")
                return
            login_result = await resp.json()
            token = login_result.get("access_token")
            if not token:
                print("❌ No token received")
                return
            
            headers = {"Authorization": f"Bearer {token}"}
            print("✅ Login successful")
        
        # Step 3: Create a chat
        print("💬 Step 3: Creating chat...")
        chat_data = {
            "name": "Test Chat for File Upload",
            "type": "group",
            "member_ids": []  # Empty for now, will add current user automatically
        }
        
        async with session.post(f"{BASE_URL}/api/v1/chats", json=chat_data, headers=headers) as resp:
            if resp.status not in [201, 200]:
                error_text = await resp.text()
                print(f"❌ Chat creation failed: {resp.status}")
                print(f"❌ Error details: {error_text}")
                return
            chat_result = await resp.json()
            chat_id = chat_result.get("id") or chat_result.get("_id")
            if not chat_id:
                print("❌ No chat ID received")
                return
            print(f"✅ Chat created: {chat_id}")
        
        # Step 4: Initiate upload
        print("📤 Step 4: Initiating upload...")
        upload_data = {
            "filename": "test_file.txt",
            "file_size": 12,
            "mime_type": "text/plain",
            "chat_id": chat_id
        }
        
        async with session.post(f"{BASE_URL}/api/v1/files/init", json=upload_data, headers=headers) as resp:
            if resp.status not in [200, 201]:
                print(f"❌ Upload initiation failed: {resp.status}")
                print(await resp.text())
                return
            upload_result = await resp.json()
            upload_id = upload_result.get("media_id") or upload_result.get("upload_id")
            if not upload_id:
                print("❌ No upload ID received")
                return
            print(f"✅ Upload initiated: {upload_id}")
            print(f"🔍 Upload ID type: {type(upload_id)}")
            print(f"🔍 Upload ID format: {upload_id[:8]}...")
        
        # Step 5: Simulate S3 upload (mark as uploaded)
        print("📦 Step 5: Simulating S3 upload...")
        file_id = None
        
        # For testing, we'll just mark the upload as completed in S3
        # In real scenario, frontend would upload file to S3 using presigned URL
        async with session.post(f"{BASE_URL}/api/v1/files/{upload_id}/complete", headers=headers) as resp:
            if resp.status == 403:
                # Try to manually update the upload record to simulate S3 completion
                print("⚠️ 403 Forbidden - trying manual completion...")
                # For now, let's just try to continue with the test
                pass
            elif resp.status not in [200, 201]:
                error_text = await resp.text()
                print(f"❌ Upload completion failed: {resp.status}")
                print(f"❌ Error details: {error_text}")
                return
            else:
                complete_result = await resp.json()
                file_id = complete_result.get("file_id")
                if not file_id:
                    print("❌ No file ID received from complete")
                    return
                print(f"✅ Upload completed")
                print(f"🔍 File ID type: {type(file_id)}")
                print(f"🔍 File ID format: {file_id[:8]}...")
                print(f"🔍 IDs different: {upload_id != file_id}")
        
        # If completion failed, let's try to create the file record directly for testing
        if not file_id:
            print("🔧 Step 5b: Creating file record manually for testing...")
            # Create a proper MongoDB ObjectId for testing
            from bson import ObjectId
            file_id = str(ObjectId())
            print(f"✅ Created MongoDB ObjectId: {file_id}")
        
        # Step 6: Send message with file
        print("📨 Step 6: Sending message with file...")
        message_data = {
            "text": "Test file upload",
            "file_id": file_id
        }
        
        async with session.post(f"{BASE_URL}/api/v1/chats/{chat_id}/messages", json=message_data, headers=headers) as resp:
            if resp.status not in [201, 200]:
                error_text = await resp.text()
                print(f"❌ Message sending failed: {resp.status}")
                print(f"❌ Error details: {error_text}")
                return
            message_result = await resp.json()
            print("✅ Message sent with file")
        
        # Step 7: Try to download file
        print("📥 Step 7: Downloading file...")
        
        async with session.get(f"{BASE_URL}/api/v1/files/{file_id}/download", headers=headers) as resp:
            if resp.status == 404:
                print(f"❌ File download failed: 404 NOT FOUND")
                print("🔍 This indicates the file_id lookup issue is NOT fixed")
                return
            elif resp.status == 200:
                print("✅ File download successful!")
                print(f"🔍 Content-Type: {resp.headers.get('Content-Type')}")
                print(f"🔍 Content-Length: {resp.headers.get('Content-Length')}")
                return
            else:
                error_text = await resp.text()
                print(f"❌ Download failed with status: {resp.status}")
                print(f"❌ Error details: {error_text}")
                return

if __name__ == "__main__":
    asyncio.run(test_flow())
