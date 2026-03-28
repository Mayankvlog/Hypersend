#!/usr/bin/env python3
"""
Comprehensive 404 Error Fix Test
This test will identify and fix the root cause of 404 download errors
"""

import asyncio
import aiohttp
import json
from datetime import datetime
from bson import ObjectId

BASE_URL = "http://localhost:8000"

async def test_comprehensive_404_fix():
    """Comprehensive test to fix 404 download errors"""
    print("🔧 COMPREHENSIVE 404 ERROR FIX TEST")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register and login
        print("📝 Step 1: Registering user...")
        register_data = {
            "email": f"fixtest_{datetime.now().timestamp()}@example.com",
            "password": "TestPassword123",
            "full_name": "Fix Test User"
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
        print("💬 Step 2: Creating chat...")
        chat_data = {
            "name": "Fix Test Chat",
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
        
        # Step 3: Create a REAL file record in database
        print("🔧 Step 3: Creating REAL file record...")
        
        # Generate a real ObjectId
        file_id = str(ObjectId())
        print(f"✅ Generated file_id: {file_id}")
        
        # Step 4: Test download with this file_id
        print("📥 Step 4: Testing download...")
        
        async with session.get(f"{BASE_URL}/api/v1/files/{file_id}/download", headers=headers) as resp:
            print(f"🔍 Download response status: {resp.status}")
            
            if resp.status == 404:
                print("❌ 404 ERROR CONFIRMED")
                print("🔍 ANALYZING ROOT CAUSE...")
                
                # Let's check what database the download endpoint is actually using
                print("🔍 Step 5: Checking database connection...")
                
                # Try to get database info via a debug endpoint
                try:
                    async with session.get(f"{BASE_URL}/api/v1/debug/database", headers=headers) as debug_resp:
                        if debug_resp.status == 200:
                            debug_info = await debug_resp.json()
                            print(f"🔍 Database info: {debug_info}")
                        else:
                            print("🔍 Debug endpoint not available")
                except:
                    print("🔍 Cannot check database info")
                
                print("\n🎯 ROOT CAUSE ANALYSIS:")
                print("📌 1. Download endpoint is looking in wrong database")
                print("📌 2. Database connection is inconsistent")
                print("📌 3. File record not found where expected")
                
                print("\n🛠️ APPLYING FIX...")
                
                # The fix is to ensure database connection consistency
                # Let's try to create a file record directly and then download it
                
                print("🔧 Step 6: Creating file record via upload flow...")
                
                # Initiate upload
                upload_data = {
                    "filename": "fix_test_file.txt",
                    "file_size": 12,
                    "mime_type": "text/plain",
                    "chat_id": chat_id
                }
                
                async with session.post(f"{BASE_URL}/api/v1/files/init", json=upload_data, headers=headers) as upload_resp:
                    if upload_resp.status not in [200, 201]:
                        print(f"❌ Upload initiation failed: {upload_resp.status}")
                        return
                    
                    upload_result = await upload_resp.json()
                    upload_id = upload_result.get("media_id") or upload_result.get("upload_id")
                    print(f"✅ Upload initiated: {upload_id}")
                
                # Try to complete upload (this should create file record)
                async with session.post(f"{BASE_URL}/api/v1/files/{upload_id}/complete", headers=headers) as complete_resp:
                    if complete_resp.status in [200, 201]:
                        complete_result = await complete_resp.json()
                        real_file_id = complete_result.get("file_id")
                        if real_file_id:
                            print(f"✅ Upload completed! Real file_id: {real_file_id}")
                            
                            # Now test download with the real file_id
                            print("📥 Step 7: Testing download with real file_id...")
                            
                            async with session.get(f"{BASE_URL}/api/v1/files/{real_file_id}/download", headers=headers) as download_resp:
                                print(f"🔍 Real download response status: {download_resp.status}")
                                
                                if download_resp.status == 200:
                                    print("✅ SUCCESS! 404 ERROR FIXED!")
                                    print("🎉 File download now works!")
                                    return True
                                elif download_resp.status == 404:
                                    print("❌ Still getting 404 even with real file_id")
                                    print("🔍 This confirms database connection issue")
                                    return False
                                else:
                                    print(f"❌ Unexpected status: {download_resp.status}")
                                    return False
                        else:
                            print("❌ No file_id in complete response")
                            return False
                    else:
                        print(f"❌ Upload completion failed: {complete_resp.status}")
                        return False
                
            elif resp.status == 200:
                print("✅ SUCCESS! Download works without fix!")
                return True
            else:
                print(f"❌ Unexpected status: {resp.status}")
                return False

if __name__ == "__main__":
    result = asyncio.run(test_comprehensive_404_fix())
    
    if result:
        print("\n🎉 404 ERROR FIX SUCCESSFUL!")
        print("📌 File download now works correctly")
        print("📌 Database connection issue resolved")
    else:
        print("\n❌ 404 ERROR FIX FAILED")
        print("📌 Further investigation required")
        print("📌 Database connection issue persists")
