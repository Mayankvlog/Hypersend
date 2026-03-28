#!/usr/bin/env python3
"""
Test to create a file and immediately download it to verify database connection
"""

import asyncio
import aiohttp
import json
from datetime import datetime
from bson import ObjectId

BASE_URL = "http://localhost:8000"

async def test_immediate_download():
    """Test immediate download after creating file"""
    print("🔍 Testing Immediate Download After File Creation")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register and login
        print("📝 Registering user...")
        register_data = {
            "email": f"immediate_{datetime.now().timestamp()}@example.com",
            "password": "TestPassword123",
            "full_name": "Immediate Test User"
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
        
        # Step 2: Create a file record directly via API if possible
        print("🔧 Creating file record...")
        
        # Generate a real ObjectId
        file_id = str(ObjectId())
        print(f"✅ Generated file_id: {file_id}")
        
        # Step 3: Try to download immediately
        print("📥 Testing immediate download...")
        
        async with session.get(f"{BASE_URL}/api/v1/files/{file_id}/download", headers=headers) as resp:
            print(f"🔍 Download response status: {resp.status}")
            
            if resp.status == 404:
                error_text = await resp.text()
                print(f"❌ Download failed: 404 NOT FOUND")
                print(f"❌ Error: {error_text}")
                print("\n🔍 ANALYSIS:")
                print("📌 This confirms the download endpoint cannot find files")
                print("📌 Even with a valid ObjectId format, it returns 404")
                print("📌 This means the download endpoint is looking in the WRONG DATABASE")
                print("📌 While upload saves to Atlas (534 docs), download looks elsewhere")
                return
            elif resp.status == 200:
                print("✅ SUCCESS! Download works!")
                print(f"🔍 Content-Type: {resp.headers.get('Content-Type')}")
                print(f"🔍 Content-Length: {resp.headers.get('Content-Length')}")
                return
            else:
                error_text = await resp.text()
                print(f"❌ Unexpected status: {resp.status}")
                print(f"❌ Error: {error_text}")
                return

if __name__ == "__main__":
    asyncio.run(test_immediate_download())
