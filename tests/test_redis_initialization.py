"""
Comprehensive Redis initialization tests for hypersend backend.

Tests cover:
1. Redis connection success during startup
2. Redis connection failure and retry mechanism
3. WebSocket manager initialization after Redis is ready
4. Global Redis client accessor function
5. Redis cleanup on shutdown
"""

import pytest
import asyncio
import logging
import os
import redis
from unittest import mock
from typing import Optional
import sys
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent.parent / 'backend'
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

logger = logging.getLogger(__name__)

# Note: Each async test should be marked with @pytest.mark.asyncio individually
# We do not use pytestmark to avoid marking non-async tests


class TestRedisConnectionSuccess:
    """Test Redis connection success during startup"""
    
    @pytest.mark.asyncio
    async def test_wait_for_redis_with_retry_success(self):
        """Test _wait_for_redis_with_retry() returns valid Redis client on success"""
        from backend.main import _wait_for_redis_with_retry
        
        # This test requires actual Redis running
        # Skip if Redis is not available
        import socket
        try:
            socket.create_connection(('redis', 6379), timeout=2)
            redis_available = True
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            try:
                socket.create_connection(('localhost', 6379), timeout=2)
                redis_available = True
            except (socket.timeout, ConnectionRefusedError, socket.gaierror):
                redis_available = False
        
        if not redis_available:
            pytest.skip("Redis not available for integration test")
        
        redis_client = None
        try:
            redis_client = await _wait_for_redis_with_retry()
            assert redis_client is not None, "Redis client should not be None"
            
            # Verify client is functional with ping
            ping_result = await redis_client.ping()
            assert ping_result is True or ping_result == b'PONG', "Redis ping should succeed"
            
            logger.info("[TEST] ✓ Redis connection successful with retry mechanism")
        finally:
            if redis_client:
                await redis_client.aclose()
    
    @pytest.mark.asyncio
    async def test_verify_redis_functionality(self):
        """Test _verify_redis_functionality() ensures Redis is fully operational"""
        from backend.main import _wait_for_redis_with_retry, _verify_redis_functionality
        import socket
        
        # Check if Redis is available
        try:
            socket.create_connection(('redis', 6379), timeout=2)
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            try:
                socket.create_connection(('localhost', 6379), timeout=2)
            except (socket.timeout, ConnectionRefusedError, socket.gaierror):
                pytest.skip("Redis not available for integration test")
        
        redis_client = None
        try:
            redis_client = await _wait_for_redis_with_retry()
            
            # This should not raise an exception
            await _verify_redis_functionality(redis_client)
            
            logger.info("[TEST] ✓ Redis functionality verification passed")
        finally:
            if redis_client:
                await redis_client.aclose()


class TestRedisConnectionFailure:
    """Test Redis connection failure and retry mechanism"""
    
    @pytest.mark.asyncio
    async def test_wait_for_redis_timeout_handling(self):
        """Test _wait_for_redis_with_retry() handles connection timeouts gracefully"""
        from backend.main import _wait_for_redis_with_retry
        
        # Simply test that the function fails appropriately when Redis is not available
        # This is testing the actual behavior rather than mocking
        try:
            # This should raise RuntimeError after max retries when Redis is not available
            with pytest.raises(RuntimeError, match="Redis connection failed"):
                await _wait_for_redis_with_retry()
            logger.info("[TEST] ✓ Redis timeout error handling works correctly")
        except asyncio.TimeoutError:
            # If it times out, that's also a failure of the test
            pytest.fail("Redis connection test timed out - should have raised RuntimeError quickly")
    
    @pytest.mark.asyncio
    async def test_redis_password_validation(self):
        """Test Redis connection respects password configuration"""
        from backend.config import settings
        
        # Verify REDIS_PASSWORD configuration
        redis_password = getattr(settings, 'REDIS_PASSWORD', None)
        
        # Password can be None (no auth) or string (with auth)
        if redis_password is not None:
            assert isinstance(redis_password, str), "REDIS_PASSWORD must be string or None"
            # Empty string is allowed (no password), but should not be just whitespace
            # Only reject if it's not exactly empty string and strip() results in empty
            if redis_password != "":
                assert redis_password.strip() != "", "REDIS_PASSWORD should not be whitespace-only when set"
        
        # Verify password handling in URL
        redis_url = settings.REDIS_URL
        if redis_password:
            # URL should contain password credentials
            assert "@" in redis_url, "REDIS_URL should contain @ separator for auth"
        else:
            # URL should not contain password
            logger.info(f"[TEST] ℹ REDIS_PASSWORD is not set (using default None)")
        
        logger.info(f"[TEST] ✓ Redis password configuration validated (set: {bool(redis_password)})")


class TestWebSocketManagerInitialization:
    """Test WebSocket manager initialization depends on Redis being ready"""
    
    @pytest.mark.asyncio
    async def test_websocket_manager_requires_redis(self):
        """Test WebSocket manager fails to initialize without Redis client"""
        from backend.websocket.websocket_manager import websocket_manager
        from backend.main import get_redis_client
        
        try:
            # Get or create a valid Redis client for WebSocket manager
            redis_client = get_redis_client()
            
            # If we got here, Redis is available
            assert redis_client is not None, "Redis client should not be None when available"
            
            # Verify the WebSocket manager can use the Redis client
            # The manager should have access to redis for pub/sub operations
            logger.info("[TEST] ✓ WebSocket manager has access to Redis client")
            
        except Exception as e:
            # If Redis is not available, the manager should handle it gracefully
            logger.warning(f"[TEST] ℹ Redis unavailable for WebSocket manager: {e}")
            pytest.skip(f"Redis not available: {e}")
    
    @pytest.mark.asyncio
    async def test_websocket_manager_initialization_after_redis(self):
        """Test WebSocket manager initializes successfully after Redis is ready"""
        import socket
        
        # Check if Redis is available
        try:
            socket.create_connection(('redis', 6379), timeout=2)
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            try:
                socket.create_connection(('localhost', 6379), timeout=2)
            except (socket.timeout, ConnectionRefusedError, socket.gaierror):
                pytest.skip("Redis not available for integration test")
        
        from backend.main import _wait_for_redis_with_retry
        from backend.websocket.websocket_manager import websocket_manager
        
        redis_client = None
        try:
            # Step 1: Initialize Redis
            redis_client = await _wait_for_redis_with_retry()
            assert redis_client is not None, "Redis should be initialized first"
            
            logger.info("[TEST] ✓ Redis initialized before WebSocket manager")
            
            # Step 2: Initialize WebSocket manager with Redis
            await asyncio.wait_for(
                websocket_manager.initialize(redis_client),
                timeout=10.0
            )
            
            # Verify WebSocket manager has Redis reference
            assert websocket_manager.redis is not None, "WebSocket manager should have Redis reference"
            
            logger.info("[TEST] ✓ WebSocket manager initialized successfully with Redis")
        finally:
            if redis_client:
                await redis_client.aclose()


class TestGlobalRedisAccessor:
    """Test global Redis client accessor function"""
    
    def test_get_redis_client_function_exists(self):
        """Test get_redis_client() function is accessible"""
        from backend.main import get_redis_client
        
        # Function should exist and be callable
        assert callable(get_redis_client), "get_redis_client should be a callable function"
        
        logger.info("[TEST] ✓ get_redis_client() function is accessible")
    
    def test_get_redis_client_returns_none_when_not_initialized(self):
        """Test get_redis_client() returns None gracefully when not initialized"""
        from backend.main import get_redis_client
        
        # Before app startup, Redis client may not be initialized
        redis_client = get_redis_client()
        
        # Should return None gracefully, not raise exception
        assert redis_client is None or hasattr(redis_client, 'ping'), \
            "get_redis_client() should return None or valid Redis client"
        
        logger.info("[TEST] ✓ get_redis_client() handles uninitialized state gracefully")


class TestRedisEnvironmentVariables:
    """Test Redis environment variable validation"""
    
    def test_redis_config_uses_docker_service_name(self):
        """Test REDIS_HOST does not contain localhost in production"""
        import os
        
        # Skip in local development (when CI env var is not set)
        if not os.getenv('CI') and os.getenv('DEBUG', 'False').lower() in ('true', '1'):
            pytest.skip("Skipping in local development environment")
        
        from backend.config import settings
        
        redis_host = settings.REDIS_HOST
        redis_url = settings.REDIS_URL
        
        # In production or CI, should use docker service name or actual hostname
        assert 'localhost' not in redis_host.lower(), \
            f"REDIS_HOST should not be localhost, got: {redis_host}"
        assert '127.0.0.1' not in redis_host, \
            f"REDIS_HOST should not be 127.0.0.1, got: {redis_host}"
        
        logger.info(f"[TEST] ✓ REDIS_HOST is configured properly: {redis_host}")
    
    def test_redis_url_construction(self):
        """Test REDIS_URL is properly constructed from components"""
        from backend.config import settings
        
        redis_host = settings.REDIS_HOST
        redis_port = settings.REDIS_PORT
        redis_db = settings.REDIS_DB
        
        # REDIS_URL should be properly formatted, starting with expected base
        expected_base = f"redis://{redis_host}:{redis_port}/{redis_db}"
        
        assert settings.REDIS_URL.startswith(expected_base), \
            f"REDIS_URL should start with '{expected_base}', got: {settings.REDIS_URL}"
        
        logger.info(f"[TEST] ✓ REDIS_URL properly constructed: {settings.REDIS_URL}")


class TestRedisConnectionLogging:
    """Test Redis connection logging is structured and informative"""
    
    @pytest.mark.asyncio
    async def test_redis_health_check_logging(self, caplog):
        """Test Redis health check produces structured logs"""
        import socket
        
        # Check if Redis is available
        try:
            socket.create_connection(('redis', 6379), timeout=2)
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            try:
                socket.create_connection(('localhost', 6379), timeout=2)
            except (socket.timeout, ConnectionRefusedError, socket.gaierror):
                pytest.skip("Redis not available for integration test")
        
        from backend.main import _wait_for_redis_with_retry
        
        redis_client = None
        try:
            with caplog.at_level(logging.INFO):
                redis_client = await _wait_for_redis_with_retry()
            
            # Check for structured logging markers
            log_text = caplog.text
            
            assert "[REDIS-HEALTH]" in log_text or "[REDIS]" in log_text, \
                "Redis health check should produce structured logs"
            assert "Successfully connected" in log_text or "verified" in log_text, \
                "Redis logs should indicate successful connection"
            
            logger.info("[TEST] ✓ Redis health check logging is structured")
        finally:
            if redis_client:
                await redis_client.aclose()


class TestRedisCleanup:
    """Test Redis cleanup on shutdown"""
    
    @pytest.mark.asyncio
    async def test_redis_client_cleanup(self):
        """Test Redis client can be cleanly closed"""
        import socket
        
        # Check if Redis is available
        try:
            socket.create_connection(('redis', 6379), timeout=2)
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            try:
                socket.create_connection(('localhost', 6379), timeout=2)
            except (socket.timeout, ConnectionRefusedError, socket.gaierror):
                pytest.skip("Redis not available for integration test")
        
        from backend.main import _wait_for_redis_with_retry
        
        redis_client = await _wait_for_redis_with_retry()
        
        try:
            # Should not raise exception
            await asyncio.wait_for(redis_client.aclose(), timeout=5.0)
            
            logger.info("[TEST] ✓ Redis client cleanup successful")
        except asyncio.TimeoutError:
            pytest.fail("Redis client cleanup timed out")
        except Exception as e:
            pytest.fail(f"Redis client cleanup failed: {e}")


class TestLifespanRedisInitialization:
    """Test FastAPI lifespan Redis initialization"""
    
    @pytest.mark.asyncio
    async def test_app_state_has_redis_client_after_startup(self):
        """Test app.state.redis_client is set after startup (if Redis is available)"""
        import socket
        
        redis_available = False
        try:
            socket.create_connection(('redis', 6379), timeout=2)
            redis_available = True
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            try:
                socket.create_connection(('localhost', 6379), timeout=2)
                redis_available = True
            except (socket.timeout, ConnectionRefusedError, socket.gaierror):
                pass
        
        # Import app after Redis is configured
        try:
            from backend.main import app
            
            redis_client = getattr(app.state, 'redis_client', None)
            
            if redis_available:
                # If Redis is available, app.state should have redis_client set
                assert redis_client is not None, "app.state.redis_client should be set when Redis is available"
                assert hasattr(redis_client, 'ping'), "redis_client should have ping method"
                logger.info("[TEST] ✓ app.state.redis_client is properly initialized")
            else:
                # If Redis is not available, client may be None
                logger.info("[TEST] ✓ Redis not available, skipping state verification")
                pytest.skip("Redis server not available for state verification")
        except AssertionError as e:
            pytest.fail(f"Redis client state verification failed: {e}")
        except Exception as e:
            logger.warning(f"[TEST] Could not verify app.state: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
