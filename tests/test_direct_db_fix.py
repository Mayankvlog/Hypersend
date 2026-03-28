#!/usr/bin/env python3
"""
Direct database connection test and fix
"""

import asyncio
import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

async def test_direct_db_fix():
    """Test direct database connection"""
    print("🔧 DIRECT DATABASE CONNECTION TEST")
    print("=" * 50)
    
    try:
        # Load environment variables
        from dotenv import load_dotenv
        env_path = os.path.join(os.path.dirname(__file__), 'backend', '.env')
        load_dotenv(env_path)
        
        # Test database connection
        from backend.database import get_database
        
        print("🔍 Testing database connection...")
        db = get_database()
        
        # Test database ping
        try:
            await db.command('ping')
            print("✅ Database ping successful")
        except Exception as e:
            print(f"❌ Database ping failed: {e}")
            return False
        
        # Test files collection
        try:
            files_count = await db.files.count_documents({})
            print(f"✅ Files collection count: {files_count}")
            
            if files_count > 0:
                # Get a real file
                sample_file = await db.files.find_one({})
                if sample_file:
                    file_id = str(sample_file['_id'])
                    print(f"✅ Found sample file: {file_id}")
                    
                    # Test direct download query
                    from bson import ObjectId
                    file_oid = ObjectId(file_id)
                    
                    # Test the exact same query as download endpoint
                    test_file = await db.files.find_one({"_id": file_oid})
                    
                    if test_file:
                        print("✅ Direct database query successful!")
                        print("🎉 Database connection is working correctly")
                        
                        # Now test via API
                        print("📥 Testing via API...")
                        
                        import aiohttp
                        from datetime import datetime
                        
                        async with aiohttp.ClientSession() as session:
                            # Register and login
                            register_data = {
                                "email": f"dbtest_{datetime.now().timestamp()}@example.com",
                                "password": "TestPassword123",
                                "full_name": "DB Test User"
                            }
                            
                            async with session.post("http://localhost:8000/api/v1/auth/register", json=register_data) as resp:
                                if resp.status not in [201, 409]:
                                    print(f"❌ Registration failed: {resp.status}")
                                    return False
                            
                            login_data = {
                                "email": register_data["email"],
                                "password": register_data["password"]
                            }
                            
                            async with session.post("http://localhost:8000/api/v1/auth/login", json=login_data) as resp:
                                if resp.status != 200:
                                    print(f"❌ Login failed: {resp.status}")
                                    return False
                                
                                login_result = await resp.json()
                                token = login_result.get("access_token")
                                headers = {"Authorization": f"Bearer {token}"}
                                
                                # Test download with real file_id
                                async with session.get(f"http://localhost:8000/api/v1/files/{file_id}/download", headers=headers) as download_resp:
                                    print(f"🔍 API download response: {download_resp.status}")
                                    
                                    if download_resp.status == 200:
                                        print("✅ SUCCESS! 404 ERROR FIXED!")
                                        print("🎉 API download works with real Atlas file!")
                                        return True
                                    elif download_resp.status == 404:
                                        print("❌ API download returns 404 even though DB query works")
                                        print("🔍 This confirms API endpoint issue")
                                        return False
                                    else:
                                        print(f"❌ Unexpected API status: {download_resp.status}")
                                        return False
                    else:
                        print("❌ Direct database query failed")
                        return False
                else:
                    print("❌ No files found in database")
                    return False
            else:
                print("❌ Files collection is empty")
                return False
                
        except Exception as e:
            print(f"❌ Files collection error: {e}")
            return False
            
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_direct_db_fix())
    
    if result:
        print("\n🎉 404 ERROR FIX SUCCESSFUL!")
        print("📌 Database connection is working")
        print("📌 API download works with real files")
    else:
        print("\n❌ 404 ERROR FIX FAILED")
        print("📌 Database connection or API issue persists")
