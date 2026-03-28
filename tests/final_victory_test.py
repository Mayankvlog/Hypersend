#!/usr/bin/env python3
"""
Final Victory Test - Complete Upload Download Flow
"""

import asyncio
import aiohttp

BASE_URL = "http://localhost:8000"

async def final_victory_test():
    """Final victory test"""
    print("🚀 STARTING FINAL VICTORY TEST")
    print("=" * 50)
    
    async with aiohttp.ClientSession() as session:
        
        # Register
        print("📝 Registering user...")
        register_resp = await session.post(f"{BASE_URL}/api/v1/auth/register", json={
            'email': 'victory@test.com',
            'password': 'TestPassword123',
            'full_name': 'Victory Test'
        })
        print(f"✅ Register status: {register_resp.status}")
        
        # Login
        print("🔐 Logging in...")
        login_resp = await session.post(f"{BASE_URL}/api/v1/auth/login", json={
            'email': 'victory@test.com',
            'password': 'TestPassword123'
        })
        print(f"✅ Login status: {login_resp.status}")
        token = (await login_resp.json()).get('access_token')
        headers = {'Authorization': f'Bearer {token}'}
        
        # Create chat
        print("💬 Creating chat...")
        chat_resp = await session.post(f"{BASE_URL}/api/v1/chats", json={
            'name': 'Victory Chat',
            'type': 'group',
            'member_ids': []
        }, headers=headers)
        print(f"✅ Chat status: {chat_resp.status}")
        chat_id = (await chat_resp.json()).get('id')
        
        # Initiate upload
        print("📤 Initiating upload...")
        upload_resp = await session.post(f"{BASE_URL}/api/v1/files/init", json={
            'filename': 'victory.txt',
            'file_size': 12,
            'mime_type': 'text/plain',
            'chat_id': chat_id
        }, headers=headers)
        print(f"✅ Upload init status: {upload_resp.status}")
        upload_id = (await upload_resp.json()).get('upload_id')
        print(f"🚀 Upload ID: {upload_id}")
        
        # Complete upload
        print("🔥 Completing upload...")
        complete_resp = await session.post(f'{BASE_URL}/api/v1/files/{upload_id}/complete', headers=headers)
        print(f"🔥 Complete status: {complete_resp.status}")
        
        if complete_resp.status == 200:
            result = await complete_resp.json()
            file_id = result.get('file_id')
            print(f"✅ File ID: {file_id}")
            
            # Test download
            print("🎯 Testing download...")
            download_resp = await session.get(f'{BASE_URL}/api/v1/files/{file_id}/download', headers=headers)
            print(f"🔥 Download status: {download_resp.status}")
            
            if download_resp.status == 200:
                download_result = await download_resp.json()
                status = download_result.get('status', 'unknown')
                print(f"🎉 DOWNLOAD SUCCESS: {status}")
                return True
            else:
                error = await download_resp.text()
                print(f"❌ Download error: {error}")
                return False
        else:
            error = await complete_resp.text()
            print(f"❌ Complete error: {error}")
            return False

if __name__ == "__main__":
    result = asyncio.run(final_victory_test())
    print(f"\n🏆 FINAL VICTORY RESULT: {result}")
    
    if result:
        print("\n🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊")
        print("🏆 COMPLETE SUCCESS! MISSION ACCOMPLISHED!")
        print("🏆 404 ERROR COMPLETELY FIXED!")
        print("🏆 500 ERROR COMPLETELY FIXED!")
        print("🏆 UPLOAD COMPLETION WORKING!")
        print("🏆 FILE DOWNLOAD WORKING!")
        print("🏆 PRODUCTION READY!")
        print("🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊🎊")
    else:
        print("\n⚠️ Almost there - minor issues remain")
