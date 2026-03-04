"""
Comprehensive Redis Connection Tests for Hypersend Backend
Tests Redis initialization, retry mechanism, health verification, and WebSocket manager integration.
Uses pytest-asyncio for proper async testing.
"""

import pytest
import asyncio
import json
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Optional

# Test configuration
pytest_plugins = ('pytest_asyncio',)

class TestRedisConnection:
    """Test Redis connection initialization and retry mechanism"""
    
    @pytest.mark.asyncio
    async def test_redis_connection_success(self):
        """Test successful Redis connection with health verification"""
        # Mock Redis client and dependencies
        mock_redis_client = AsyncMock()
        mock_redis_client.ping.return_value = True
        mock_redis_client.info.return_value = {"redis_version": "7.2.0"}
        mock_redis_client.setex.return_value = True
        mock_redis_client.get.return_value = json.dumps({"test": True})
        mock_redis_client.delete.return_value = 1
        
        # Mock pubsub for functionality test
        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.close = AsyncMock()
        mock_redis_client.pubsub.return_value = mock_pubsub
        mock_redis_client.publish.return_value = 1
        
        # Mock redis.asyncio module
        with patch('redis.asyncio.Redis', return_value=mock_redis_client) as mock_redis:
            with patch('backend.main.settings') as mock_settings:
                # Configure settings for docker service name
                mock_settings.REDIS_HOST = 'redis'
                mock_settings.REDIS_PORT = 6379
                mock_settings.REDIS_PASSWORD = None
                mock_settings.REDIS_DB = 0
                
                # Import and test the function
                from backend.main import _wait_for_redis_with_retry
                
                # Should succeed on first attempt
                result = await _wait_for_redis_with_retry()
                
                # Verify Redis client was created with correct parameters
                mock_redis.assert_called_once_with(
                    host='redis',
                    port=6379,
                    password=None,
                    db=0,
                    decode_responses=True,
                    socket_connect_timeout=10,
                    socket_timeout=30,
                    health_check_interval=30,
                    socket_keepalive=True,
                    retry_on_timeout=True,
                )
                
                # Verify connection tests were performed
                mock_redis_client.ping.assert_called_once()
                mock_redis_client.info.assert_called_once_with('server')
                
                # Should return the Redis client
                assert result is mock_redis_client
    
    @pytest.mark.asyncio
    async def test_redis_connection_retry_mechanism(self):
        """Test Redis connection retry mechanism with exponential backoff"""
        # Mock Redis client that fails first 3 attempts, then succeeds
        mock_redis_client = AsyncMock()
        mock_redis_client.ping.return_value = True
        mock_redis_client.info.return_value = {"redis_version": "7.2.0"}
        mock_redis_client.setex.return_value = True
        mock_redis_client.get.return_value = json.dumps({"test": True})
        mock_redis_client.delete.return_value = 1
        
        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe.return_value = None
        mock_pubsub.close.return_value = None
        mock_redis_client.pubsub.return_value = mock_pubsub
        mock_redis_client.publish.return_value = 1
        
        call_count = 0
        
        def create_redis_client(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                # First 3 attempts fail
                raise ConnectionError("Connection refused")
            # 4th attempt succeeds
            return mock_redis_client
        
        # Mock redis.asyncio module
        with patch('redis.asyncio.Redis', side_effect=create_redis_client) as mock_redis:
            with patch('backend.main.settings') as mock_settings:
                mock_settings.REDIS_HOST = 'redis'
                mock_settings.REDIS_PORT = 6379
                mock_settings.REDIS_PASSWORD = None
                mock_settings.REDIS_DB = 0
                
                # Mock asyncio.sleep to track delays
                with patch('asyncio.sleep') as mock_sleep:
                    from backend.main import _wait_for_redis_with_retry
                    
                    # Should succeed after retries
                    result = await _wait_for_redis_with_retry()
                    
                    # Verify 4 attempts (3 failures + 1 success)
                    assert mock_redis.call_count == 4
                    
                    # Verify exponential backoff delays
                    expected_delays = [2, 4, 8]  # 2^1, 2^2, 2^3
                    # asyncio.sleep should have been called with the delay as first arg
                    actual_delays = [call.args[0] for call in mock_sleep.call_args_list]
                    assert actual_delays == expected_delays
                    
                    # Should return the Redis client
                    assert result is mock_redis_client
    
    @pytest.mark.asyncio
    async def test_redis_connection_all_retries_fail(self):
        """Test Redis connection failure after all retries"""
        # Mock Redis client that always fails
        def create_redis_client(*args, **kwargs):
            raise ConnectionError("Connection refused")
        
        # Mock redis.asyncio module
        with patch('redis.asyncio.Redis', side_effect=create_redis_client):
            with patch('backend.main.settings') as mock_settings:
                mock_settings.REDIS_HOST = 'redis'
                mock_settings.REDIS_PORT = 6379
                mock_settings.REDIS_PASSWORD = None
                mock_settings.REDIS_DB = 0
                
                from backend.main import _wait_for_redis_with_retry
                
                # Should raise RuntimeError after all retries
                with pytest.raises(RuntimeError, match="Redis connection failed after 5 attempts"):
                    await _wait_for_redis_with_retry()
    
    @pytest.mark.asyncio
    async def test_redis_connection_localhost_forced_to_redis(self):
        """Test that localhost is forced to redis service name"""
        mock_redis_client = AsyncMock()
        mock_redis_client.ping.return_value = True
        mock_redis_client.info.return_value = {"redis_version": "7.2.0"}
        mock_redis_client.setex.return_value = True
        mock_redis_client.get.return_value = json.dumps({"test": True})
        mock_redis_client.delete.return_value = 1
        
        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe.return_value = None
        mock_pubsub.close.return_value = None
        mock_redis_client.pubsub.return_value = mock_pubsub
        mock_redis_client.publish.return_value = 1
        
        # Mock redis.asyncio module
        with patch('redis.asyncio.Redis', return_value=mock_redis_client) as mock_redis:
            with patch('backend.main.settings') as mock_settings:
                # Configure with localhost (should be forced to redis)
                mock_settings.REDIS_HOST = 'localhost'
                mock_settings.REDIS_PORT = 6379
                mock_settings.REDIS_PASSWORD = None
                mock_settings.REDIS_DB = 0
                
                from backend.main import _wait_for_redis_with_retry
                
                # Should succeed but force host to redis
                result = await _wait_for_redis_with_retry()
                
                # Verify Redis client was created with 'redis' host, not 'localhost'
                mock_redis.assert_called_once()
                call_kwargs = mock_redis.call_args[1]
                assert call_kwargs['host'] == 'redis'
                
                assert result is mock_redis_client
    
    @pytest.mark.asyncio
    async def test_redis_functionality_verification(self):
        """Test Redis functionality verification with all operations"""
        mock_redis_client = AsyncMock()
        
        # Mock pubsub for functionality test
        mock_pubsub = AsyncMock()
        
        # Mock message for pubsub test
        test_message = {
            'type': 'message',
            'channel': b'__test_channel__12345678',
            'data': json.dumps({"type": "test", "data": "pubsub_verification"})
        }
        
        # Create an async iterator for the pubsub listen() call
        async def mock_listen():
            yield test_message
        
        mock_pubsub.listen = mock_listen
        mock_pubsub.subscribe.return_value = None
        mock_pubsub.close.return_value = None
        
        # Configure Redis client mocks
        mock_redis_client.ping.return_value = True
        mock_redis_client.info.return_value = {"redis_version": "7.2.0", "used_memory": 1048576}
        mock_redis_client.setex.return_value = True
        mock_redis_client.get.return_value = json.dumps({"test": True, "timestamp": time.time()})
        mock_redis_client.delete.return_value = 1
        mock_redis_client.pubsub.return_value = mock_pubsub
        mock_redis_client.publish.return_value = 1
        
        from backend.main import _verify_redis_functionality
        
        # Should pass all functionality tests
        await _verify_redis_functionality(mock_redis_client)
        
        # Verify all operations were called
        mock_redis_client.setex.assert_called_once()
        mock_redis_client.get.assert_called_once()
        mock_redis_client.delete.assert_called_once()
        mock_redis_client.info.assert_called_with('memory')
        mock_pubsub.subscribe.assert_called_once()
        mock_redis_client.publish.assert_called_once()
        mock_pubsub.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_redis_functionality_verification_timeout(self):
        """Test Redis functionality verification timeout"""
        mock_redis_client = AsyncMock()
        mock_redis_client.ping.return_value = True
        mock_redis_client.info.return_value = {"redis_version": "7.2.0"}
        
        # Make setex operation timeout
        mock_redis_client.setex.side_effect = asyncio.TimeoutError("Operation timeout")
        
        from backend.main import _verify_redis_functionality
        
        # Should raise RuntimeError on timeout
        with pytest.raises(RuntimeError, match="Redis functionality test timeout"):
            await _verify_redis_functionality(mock_redis_client)
    
    @pytest.mark.asyncio
    async def test_redis_functionality_verification_pubsub_failure(self):
        """Test Redis functionality verification pubsub failure"""
        mock_redis_client = AsyncMock()
        mock_redis_client.ping.return_value = True
        mock_redis_client.info.return_value = {"redis_version": "7.2.0"}
        mock_redis_client.setex.return_value = True
        mock_redis_client.get.return_value = json.dumps({"test": True})
        mock_redis_client.delete.return_value = 1
        
        # Mock pubsub that fails
        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe.side_effect = Exception("PubSub connection failed")
        mock_redis_client.pubsub.return_value = mock_pubsub
        
        from backend.main import _verify_redis_functionality
        
        # Should raise RuntimeError on pubsub failure
        with pytest.raises(RuntimeError, match="Redis functionality test failed"):
            await _verify_redis_functionality(mock_redis_client)


class TestWebSocketManagerRedisIntegration:
    """Test WebSocket manager integration with Redis"""
    
    @pytest.mark.asyncio
    async def test_websocket_manager_initialization_with_redis(self):
        """Test WebSocket manager initialization with Redis client"""
        # Mock Redis client
        mock_redis_client = AsyncMock()
        mock_redis_client.ping.return_value = True
        
        # Mock WebSocket manager
        with patch('backend.main.websocket_manager') as mock_ws_manager:
            mock_ws_manager.initialize = AsyncMock()
            mock_ws_manager.start_global_pubsub = AsyncMock()
            
            # Mock app state
            mock_app = MagicMock()
            mock_app.state.redis_client = mock_redis_client
            
            # Mock pytest detection to return False (production mode)
            with patch('backend.main._is_pytest_running', return_value=False):
                from backend.main import lifespan
                
                # Create a FastAPI app for testing
                from fastapi import FastAPI
                app = FastAPI(lifespan=lifespan)
                
                # Run the full lifespan to execute startup (and shutdown on exit)
                async with app.lifespan_context():
                    # entering this block triggers the startup code
                    pass
                
                # Verify WebSocket manager was initialized with Redis client
                mock_ws_manager.initialize.assert_called_once_with(mock_redis_client)
                mock_ws_manager.start_global_pubsub.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_websocket_manager_fails_without_redis(self):
        """Test WebSocket manager initialization fails without Redis client"""
        # Mock WebSocket manager
        with patch('backend.main.websocket_manager') as mock_ws_manager:
            # Ensure the FastAPI app has no redis client attached
            from backend.main import lifespan
            
            # Create a FastAPI app for testing and explicitly null out redis client
            from fastapi import FastAPI
            app = FastAPI(lifespan=lifespan)
            app.state.redis_client = None
            
            # Should raise RuntimeError when Redis client is None
            with pytest.raises(RuntimeError, match="Redis client not available in app.state"):
                async with app.lifespan_context():
                    pass


class TestRedisConfiguration:
    """Test Redis configuration validation"""
    
    def test_redis_host_enforcement(self):
        """Test that Redis host is enforced to docker service name"""
        # Test with localhost - should be forced to redis
        with patch.dict('os.environ', {'REDIS_HOST': 'localhost'}):
            import importlib
            from backend import config
            importlib.reload(config)
            settings = config.Settings()
            # The config forces localhost to redis, so check the final value
            assert settings.REDIS_HOST == 'redis'
        
        # Test with 127.0.0.1 - should be forced to redis
        with patch.dict('os.environ', {'REDIS_HOST': '127.0.0.1'}):
            import importlib
            from backend import config
            importlib.reload(config)
            settings = config.Settings()
            assert settings.REDIS_HOST == 'redis'
        
        # Test with valid docker service name - should remain unchanged
        with patch.dict('os.environ', {'REDIS_HOST': 'redis'}):
            import importlib
            from backend import config
            importlib.reload(config)
            settings = config.Settings()
            assert settings.REDIS_HOST == 'redis'
    
    def test_redis_url_construction(self):
        """Test Redis URL construction from components"""
        # Test with password
        with patch.dict('os.environ', {
            'REDIS_HOST': 'redis',
            'REDIS_PORT': '6379',
            'REDIS_PASSWORD': 'testpass',
            'REDIS_DB': '1'
        }):
            from backend.config import Settings
            settings = Settings()
            # URL should include password but not be encoded
            assert 'redis://redis:6379/1' in settings.REDIS_URL
        
        # Test without password
        with patch.dict('os.environ', {
            'REDIS_HOST': 'redis',
            'REDIS_PORT': '6379',
            'REDIS_PASSWORD': '',
            'REDIS_DB': '0'
        }):
            from backend.config import Settings
            settings = Settings()
            assert settings.REDIS_URL == "redis://redis:6379/0"


class TestRedisCleanup:
    """Test Redis cleanup on shutdown"""
    
    @pytest.mark.asyncio
    async def test_redis_cleanup_success(self):
        """Test successful Redis cleanup on shutdown"""
        # Mock Redis client
        mock_redis_client = AsyncMock()
        mock_redis_client.aclose = AsyncMock()
        
        # Mock app state
        mock_app = MagicMock()
        mock_app.state.redis_client = mock_redis_client
        
        # Mock cache module
        with patch('backend.main.cache') as mock_cache:
            mock_cache.disconnect = AsyncMock()
            
            from backend.main import lifespan
            
            # Create a FastAPI app for testing
            from fastapi import FastAPI
            app = FastAPI(lifespan=lifespan)
            
            # Run only the shutdown part by simulating cleanup
            # Import the shutdown code directly
            from backend.main import _cleanup_redis_cache
            await _cleanup_redis_cache(mock_app)
            
            # Verify cleanup was called
            mock_redis_client.aclose.assert_called_once()
            mock_cache.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_redis_cleanup_timeout(self):
        """Test Redis cleanup timeout handling"""
        # Mock Redis client that times out on close
        mock_redis_client = AsyncMock()
        mock_redis_client.aclose.side_effect = asyncio.TimeoutError("Close timeout")
        
        # Mock app state
        mock_app = MagicMock()
        mock_app.state.redis_client = mock_redis_client
        
        from backend.main import lifespan
        
        # Create a FastAPI app for testing
        from fastapi import FastAPI
        app = FastAPI(lifespan=lifespan)
        
# Should handle timeout gracefully by calling cleanup function directly
        from backend.main import _cleanup_redis_cache
        await _cleanup_redis_cache(mock_app)
        
        # Verify cleanup was attempted despite timeout
        mock_redis_client.aclose.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
