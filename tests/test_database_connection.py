#!/usr/bin/env python3
"""
Test to verify database connection and files collection access
"""

import asyncio
import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

async def test_database_connection():
    """Test database connection directly"""
    print("🔍 Testing Database Connection Directly")
    print("=" * 50)
    
    try:
        from backend.database import get_database, files_collection
        from backend.config import settings
        
        # Get database connection
        db = get_database()
        print(f"✅ Database connected: {db.name if hasattr(db, 'name') else 'unknown'}")
        print(f"✅ Settings DB: {getattr(settings, 'DATABASE_NAME', 'not_set')}")
        print(f"✅ MongoDB URI: {getattr(settings, 'MONGODB_URI', 'not_set')[:50]}...")
        
        # Test files collection
        files_coll = files_collection()
        
        # Count documents in files collection
        try:
            count = await files_coll.count_documents({})
            print(f"✅ Files collection count: {count}")
            
            if count > 0:
                # Get a sample file
                sample_file = await files_coll.find_one({})
                if sample_file:
                    file_id = str(sample_file['_id'])
                    print(f"✅ Sample file ID: {file_id}")
                    print(f"✅ Sample file name: {sample_file.get('file_name', 'N/A')}")
                    return file_id
                else:
                    print("❌ No files found in collection")
            else:
                print("❌ Files collection is empty")
                
        except Exception as e:
            print(f"❌ Error accessing files collection: {e}")
            
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        
    return None

async def test_download_with_real_file():
    """Test download with a real file from database"""
    print("\n📥 Testing Download with Real File")
    print("=" * 50)
    
    # Get a real file ID
    file_id = await test_database_connection()
    
    if not file_id:
        print("❌ No real file ID available for testing")
        return
    
    print(f"\n🔍 Testing download with real file ID: {file_id}")
    
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        # Get a token
        login_data = {
            "email": "dbtest@example.com",
            "password": "TestPassword123"
        }
        
        async with session.post("http://localhost:8000/api/v1/auth/login", json=login_data) as resp:
            if resp.status != 200:
                # Try to register first
                register_data = {
                    "email": "dbtest@example.com", 
                    "password": "TestPassword123",
                    "full_name": "DB Test User"
                }
                
                async with session.post("http://localhost:8000/api/v1/auth/register", json=register_data) as reg_resp:
                    if reg_resp.status not in [201, 409]:
                        print(f"❌ Registration failed: {reg_resp.status}")
                        return
                
                # Try login again
                async with session.post("http://localhost:8000/api/v1/auth/login", json=login_data) as login_resp:
                    if login_resp.status != 200:
                        print(f"❌ Login failed: {login_resp.status}")
                        return
                    resp = login_resp
            
            login_result = await resp.json()
            token = login_result.get("access_token")
            headers = {"Authorization": f"Bearer {token}"}
            
            # Test download
            async with session.get(f"http://localhost:8000/api/v1/files/{file_id}/download", headers=headers) as download_resp:
                print(f"🔍 Download response status: {download_resp.status}")
                
                if download_resp.status == 200:
                    print("✅ SUCCESS! File download works!")
                    print(f"🔍 Content-Type: {download_resp.headers.get('Content-Type')}")
                    print(f"🔍 Content-Length: {download_resp.headers.get('Content-Length')}")
                elif download_resp.status == 404:
                    print("❌ Still getting 404 - database connection issue persists")
                    error_text = await download_resp.text()
                    print(f"❌ Error: {error_text}")
                else:
                    error_text = await download_resp.text()
                    print(f"❌ Unexpected status: {download_resp.status}")
                    print(f"❌ Error: {error_text}")

if __name__ == "__main__":
    asyncio.run(test_download_with_real_file())
