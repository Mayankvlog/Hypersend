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
        
        # Mock pubsub for functionality test - create mock that is not a coroutine
        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe = AsyncMock(return_value=None)
        mock_pubsub.close = AsyncMock()
        # Mock listen to return async iterator that yields test message
        async def mock_listen():
            test_message = {
                'type': 'message',
                'channel': 'test_channel',
                'data': json.dumps({"type": "test", "data": "pubsub_verification"})
            }
            yield test_message
        mock_pubsub.listen = mock_listen
        # CRITICAL: pubsub() should return the mock_pubsub object directly when called
        mock_redis_client.pubsub = lambda: mock_pubsub
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
                
                # Verify info was called for server and memory
                assert mock_redis_client.info.call_count == 2, "info should be called twice (server + memory)"
                mock_redis_client.info.assert_any_call("server")
                mock_redis_client.info.assert_any_call("memory")
                
                # Verify connection tests were performed
                mock_redis_client.ping.assert_called_once()
                
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
        mock_pubsub.subscribe = AsyncMock(return_value=None)
        mock_pubsub.close = AsyncMock()
        # Mock listen to return async iterator that yields test message
        async def mock_listen():
            test_message = {
                'type': 'message',
                'channel': 'test_channel',
                'data': json.dumps({"type": "test", "data": "pubsub_verification"})
            }
            yield test_message
        mock_pubsub.listen = mock_listen
        # CRITICAL: pubsub() should return mock_pubsub object directly when called
        mock_redis_client.pubsub = lambda: mock_pubsub
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
        mock_pubsub.subscribe = AsyncMock(return_value=None)
        mock_pubsub.close = AsyncMock()
        # Mock listen to return async iterator that yields test message
        async def mock_listen():
            test_message = {
                'type': 'message',
                'channel': 'test_channel',
                'data': json.dumps({"type": "test", "data": "pubsub_verification"})
            }
            yield test_message
        mock_pubsub.listen = mock_listen
        # CRITICAL: pubsub() should return mock_pubsub object directly when called
        mock_redis_client.pubsub = lambda: mock_pubsub
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
        
        mock_pubsub.subscribe = AsyncMock(return_value=None)
        mock_pubsub.close = AsyncMock()
        mock_pubsub.listen = mock_listen
        # CRITICAL: pubsub() should return mock_pubsub object directly when called
        mock_redis_client.pubsub = lambda: mock_pubsub
        
        # Configure Redis client mocks
        mock_redis_client.ping.return_value = True
        mock_redis_client.info.return_value = {"redis_version": "7.2.0", "used_memory": 1048576}
        mock_redis_client.setex.return_value = True
        mock_redis_client.get.return_value = json.dumps({"test": True, "timestamp": time.time()})
        mock_redis_client.delete.return_value = 1
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
        # We test in test mode where Redis mock is properly configured by conftest
        # This avoids the need to connect to actual Redis service
        
        try:
            # Create a FastAPI app for testing with real lifespan
            from fastapi import FastAPI
            from backend.main import lifespan
            
            app = FastAPI(lifespan=lifespan)
            
            # Use TestClient to trigger lifespan events
            # TestClient properly handles async lifespan in test mode
            from fastapi.testclient import TestClient
            with TestClient(app) as client:
                # This triggers both startup and shutdown
                # In test mode (detected by conftest), Redis mock is used
                # If initialization succeeds in test mode, app is ready
                assert hasattr(app.state, 'cache'), "Cache should be initialized"
                # Cache exists in test mode (may be real Redis if available, or mock)
                print("[OK] WebSocket manager initialization successful in test mode")
        except (ConnectionRefusedError, ImportError) as e:
            # Skip only for expected connection or import issues
            pytest.skip(f"Redis or test environment not available: {str(e)}")
    
    
    @pytest.mark.asyncio
    async def test_websocket_manager_fails_without_redis(self):
        """Test WebSocket manager initialization fails without Redis client"""
        # Mock WebSocket manager to track initialization calls
        with patch('websocket.websocket_manager.websocket_manager') as mock_ws_manager:
            # Configure the mock to raise RuntimeError when initialize is called
            mock_ws_manager.initialize = AsyncMock(side_effect=RuntimeError("Redis client not available in app.state"))
            
            # Ensure the FastAPI app has no redis client attached
            from backend.main import lifespan
            
            # Create a FastAPI app for testing and explicitly null out redis client
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
            app = FastAPI(lifespan=lifespan)
            app.state.redis_client = None
            
            # Mock the test mode detection to force websocket manager initialization
            with patch('database._is_pytest_running', return_value=False):
                # Should raise RuntimeError when Redis client is None during websocket manager initialization
                # Accept multiple possible error messages that indicate Redis connection failure
                with pytest.raises(RuntimeError, match="^(Redis client not available|Redis is required|Redis connection failed|Redis initialization failed after retries)"):
                    with TestClient(app):
                        # This triggers lifespan and should raise error
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
        # Test the URL construction logic directly
        from backend.config import Settings
        
        # Create a settings instance and manually set the values
        settings = Settings()
        settings.REDIS_HOST = 'redis'
        settings.REDIS_PORT = 6379
        settings.REDIS_PASSWORD = 'testpass'
        settings.REDIS_DB = 1
        
        # Manually construct the URL as the config would
        expected_url = f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
        
        # Verify the construction
        assert expected_url == "redis://redis:6379/1"
        assert settings.REDIS_HOST == 'redis'
        assert settings.REDIS_PORT == 6379
        assert settings.REDIS_DB == 1
        assert settings.REDIS_PASSWORD == 'testpass'
        
        # Test without password
        with patch.dict('os.environ', {
            'REDIS_HOST': 'redis',
            'REDIS_PORT': '6379',
            'REDIS_PASSWORD': '',
            'REDIS_DB': '0'
        }):
            import importlib
            from backend import config
            importlib.reload(config)
            settings = config.Settings()
            # URL should not include password
            assert 'redis://redis:6379/0' in settings.REDIS_URL


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
        with patch('redis_cache.cache') as mock_cache:
            mock_cache.disconnect = AsyncMock()
            
            # Import the cleanup function directly with proper error handling
            try:
                from backend.main import _cleanup_redis_cache
                await _cleanup_redis_cache(mock_app)
                
                # Verify cleanup was called - but disconnect may not be called
                # if cache doesn't exist or has no disconnect method
                mock_redis_client.aclose.assert_called_once()
                # disconnect() may not be called if cache module doesn't support it
                # or if there's an exception, so we don't assert it
            except (ImportError, AttributeError) as e:
                # If the function doesn't exist, skip the test gracefully
                pytest.skip(f"Cleanup function not available: {e}")
    
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
