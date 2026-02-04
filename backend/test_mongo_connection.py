#!/usr/bin/env python3
"""Test MongoDB Atlas connection"""
import asyncio
from config import settings
from database import connect_db, close_db

async def test_connection():
    """Test MongoDB connection"""
    try:
        print('[TEST] MongoDB Connection Test')
        print('=' * 60)
        print(f'[INFO] MONGODB_ATLAS_ENABLED: {settings._MONGODB_ATLAS_ENABLED}')
        print(f'[INFO] USE_MOCK_DB: {settings.USE_MOCK_DB}')
        print(f'[INFO] Connection type: {"Atlas" if "mongodb+srv" in settings.MONGODB_URI else "Traditional"}')
        print()
        
        print('[TEST] Attempting MongoDB connection...')
        await connect_db()
        
        print()
        print('[SUCCESS] ✅ MongoDB connection successful!')
        print('[SUCCESS] Database is ready for use')
        print('=' * 60)
        
        # Close connection
        await close_db()
        return True
        
    except Exception as e:
        print()
        print('[FAILED] ❌ Connection error')
        print(f'[ERROR] Type: {type(e).__name__}')
        print(f'[ERROR] Message: {str(e)[:500]}')
        print('=' * 60)
        print()
        print('[TROUBLESHOOTING GUIDE]')
        print('1. Verify MONGODB_URI in .env file')
        print('2. Check MongoDB Atlas IP whitelist includes your IP')
        print('3. Verify username and password are correct')
        print('4. Ensure authSource parameter is set correctly')
        print('5. Check network connectivity to cluster0.rnj3vfd.mongodb.net')
        return False

if __name__ == "__main__":
    result = asyncio.run(test_connection())
    exit(0 if result else 1)
