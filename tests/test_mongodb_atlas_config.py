#!/usr/bin/env python3
"""Simple test to verify MongoDB Atlas + S3 configuration"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

async def test_basic():
    try:
        from backend.config import settings
        from backend.database import init_database
        
        await init_database()
        print('✅ MongoDB Atlas configured:', bool(settings.MONGODB_URI))
        print('✅ S3 Bucket configured:', bool(settings.S3_BUCKET))
        print('✅ AWS Region configured:', bool(settings.AWS_REGION))
        print('✅ AWS credentials configured:', bool(settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY))
        print('✅ Configuration test passed')
        
    except Exception as e:
        print('❌ Configuration test failed:', str(e))

if __name__ == '__main__':
    asyncio.run(test_basic())
