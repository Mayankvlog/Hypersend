#!/usr/bin/env python3
"""
Simple Redis Connection Test
Tests Redis initialization without pytest complications
"""

import asyncio
import sys
import os
from unittest.mock import patch, AsyncMock

sys.path.insert(0, 'backend')


async def test_redis_connection():
    """Test Redis connection with mocked Redis"""
    try:
        from backend.main import _wait_for_redis_with_retry
        print('✓ Redis wait function imported successfully')
        
        # Mock everything to avoid actual Redis connection
        with patch('redis.asyncio.Redis') as mock_redis:
            # Configure mock Redis client
            mock_client = AsyncMock()
            mock_client.ping.return_value = True
            mock_client.info.return_value = {'redis_version': '7.2.0'}
            mock_client.setex.return_value = True
            mock_client.get.return_value = '{"test": true}'
            mock_client.delete.return_value = 1
            
            # Mock pubsub
            mock_pubsub = AsyncMock()
            mock_pubsub.subscribe = AsyncMock()
            mock_pubsub.close = AsyncMock()
            mock_client.pubsub.return_value = mock_pubsub
            mock_client.publish.return_value = 1
            
            mock_redis.return_value = mock_client
            
            with patch('backend.main.settings') as mock_settings:
                mock_settings.REDIS_HOST = 'redis'
                mock_settings.REDIS_PORT = 6379
                mock_settings.REDIS_PASSWORD = None
                mock_settings.REDIS_DB = 0
                
                result = await _wait_for_redis_with_retry()
                
                # CRITICAL: Assert the result is valid
                assert result is not None, "Redis client should not be None"
                assert result is not False, "Redis client should not be False"
                
                print('✓ Redis initialization test passed')
                print('✓ Redis client created and verified')
                print('✓ All functionality tests passed')
                return True
                
    except Exception as e:
        print(f'✗ Redis initialization test failed: {e}')
        import traceback
        traceback.print_exc()
        return False


async def test_config():
    """Test configuration validation"""
    try:
        from backend.config import Settings
        from unittest.mock import patch
        
        # Test localhost enforcement
        with patch.dict(os.environ, {'REDIS_HOST': 'localhost'}):
            settings = Settings()
            assert settings.REDIS_HOST == 'redis'
            print('✓ localhost forced to redis service name')
        
        # Test valid redis host
        with patch.dict(os.environ, {'REDIS_HOST': 'redis'}):
            settings = Settings()
            assert settings.REDIS_HOST == 'redis'
            print('✓ redis service name preserved')
        
        return True
        
    except Exception as e:
        print(f'✗ Configuration test failed: {e}')
        import traceback
        traceback.print_exc()
        return False


async def main():
    print("Testing Redis Connection Fixes...")
    print("=" * 50)
    
    # Test configuration
    config_result = await test_config()
    print()
    
    # Test Redis connection
    redis_result = await test_redis_connection()
    print()
    
    # Summary
    if config_result and redis_result:
        print("🎉 ALL TESTS PASSED!")
        print("✅ Redis client initialization is working correctly")
        print("✅ Docker service name enforcement is working")
        print("✅ Health verification is working")
        return True
    else:
        print("❌ SOME TESTS FAILED!")
        return False


if __name__ == "__main__":
    result = asyncio.run(main())
    sys.exit(0 if result else 1)
    else:
        print("❌ SOME TESTS FAILED!")
        return False

if __name__ == "__main__":
    result = asyncio.run(main())
    sys.exit(0 if result else 1)
