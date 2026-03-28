#!/usr/bin/env python3
"""
Simple test to check download endpoint database connection
"""

import asyncio
import aiohttp
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

async def test_download_only():
    """Test download endpoint with direct database connection check"""
    print("🔍 Testing Download Endpoint Database Connection")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register and login
        print("📝 Step 1: Registering test user...")
        register_data = {
            "email": f"testdownload_{datetime.now().timestamp()}@example.com",
            "password": "TestPassword123",
            "full_name": "Test Download User"
        }
        
        async with session.post(f"{BASE_URL}/api/v1/auth/register", json=register_data) as resp:
            if resp.status not in [201, 409]:
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
        
        # Step 3: Try download with a sample ObjectId (this will trigger the database debug logging)
        print("📥 Step 3: Testing download endpoint with sample ObjectId...")
        
        # Use a sample ObjectId that looks real
        sample_file_id = "69c7a0810ad4f5d481e396fa"  # From our previous test
        
        async with session.get(f"{BASE_URL}/api/v1/files/{sample_file_id}/download", headers=headers) as resp:
            print(f"🔍 Download response status: {resp.status}")
            
            if resp.status == 404:
                error_text = await resp.text()
                print(f"❌ Download failed: 404 NOT FOUND")
                print(f"❌ Error details: {error_text}")
                print("🔍 Check backend logs for database connection debug info")
                return
            elif resp.status == 200:
                print("✅ Download successful!")
                print(f"🔍 Content-Type: {resp.headers.get('Content-Type')}")
                print(f"🔍 Content-Length: {resp.headers.get('Content-Length')}")
                return
            else:
                error_text = await resp.text()
                print(f"❌ Download failed with status: {resp.status}")
                print(f"❌ Error details: {error_text}")
                return

if __name__ == "__main__":
    asyncio.run(test_download_only())
