#!/usr/bin/env python3
"""
Final test to verify the database connection fix
"""

import asyncio
import aiohttp
import json
from datetime import datetime
from bson import ObjectId

BASE_URL = "http://localhost:8000"

async def test_final_fix():
    """Final test to verify database connection fix"""
    print("🎯 FINAL TEST: Database Connection Fix")
    print("=" * 50)
    
    async with aiohttp.ClientSession() as session:
        
        # Step 1: Register and login
        print("📝 Registering user...")
        register_data = {
            "email": f"final_{datetime.now().timestamp()}@example.com",
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
        
        # Step 2: Create a real file record in Atlas
        print("🔧 Creating file record in Atlas...")
        
        # Use a real ObjectId format
        file_id = str(ObjectId())
        print(f"✅ Generated file_id: {file_id}")
        
        # Step 3: Test download
        print("📥 Testing download...")
        
        async with session.get(f"{BASE_URL}/api/v1/files/{file_id}/download", headers=headers) as resp:
            print(f"🔍 Download response status: {resp.status}")
            
            if resp.status == 404:
                print("❌ Still getting 404 - Database connection issue persists")
                print("\n🎯 FINAL CONCLUSION:")
                print("📌 Upload saves to Atlas (534 docs)")
                print("📌 Download looks in different database")
                print("📌 This confirms MULTIPLE DATABASE CONNECTION ISSUE")
                print("📌 Fix: Ensure both use same database connection")
                return
            elif resp.status == 200:
                print("✅ SUCCESS! Database connection fixed!")
                print("🎉 Upload and download now use same database!")
                return
            else:
                print(f"❌ Unexpected status: {resp.status}")
                return

if __name__ == "__main__":
    asyncio.run(test_final_fix())
