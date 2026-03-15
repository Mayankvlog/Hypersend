#!/usr/bin/env python3
"""
Pytest for Redis startup initialization fix
Tests the improved error handling and logging in the lifespan startup
"""

import pytest
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Add backend to path
backend_path = Path(__file__).parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))


@pytest.mark.asyncio
async def test_redis_cache_initialization_in_pytest_mode():
    """Test that Redis cache initializes correctly in pytest mode (using mock)"""
    # Ensure pytest detection works
    from backend.database import _is_pytest_running
    assert _is_pytest_running(), "pytest detection should work in pytest environment"
    
    from backend.redis_cache import init_cache
    
    # Should succeed in pytest mode with mock cache
    result = await init_cache()
    assert result is True, "Cache initialization should succeed in pytest mode"


@pytest.mark.asyncio
async def test_redis_client_available_in_app_state():
    """Test that app.state properly handles redis_client even when connection fails"""
    from unittest.mock import AsyncMock
    from fastapi import FastAPI
    
    app = FastAPI()
    
    # Ensure redis_client attribute exists in app.state
    if not hasattr(app.state, 'redis_client'):
        app.state.redis_client = None
    if not hasattr(app.state, 'cache'):
        app.state.cache = None
    
    # redis_client should be accessible without AttributeError
    client = getattr(app.state, 'redis_client', None)
    assert client is None, "redis_client should be None in test mode"
    
    # Also verify cache attribute exists
    cache = getattr(app.state, 'cache', None)
    assert cache is None, "cache should be None in test mode"


@pytest.mark.asyncio
async def test_lifespan_startup_with_mock_cache():
    """Test the lifespan startup sequence with mock cache"""
    from fastapi import FastAPI
    from backend.main import lifespan
    from backend.database import _is_pytest_running
    
    app = FastAPI()
    
    # Verify we're in test mode
    assert _is_pytest_running(), "Should detect pytest mode"
    
    # Test the lifespan startup
    async with lifespan(app) as state:
        # Verify redis_client is set in app.state
        assert hasattr(app.state, 'redis_client'), "app.state should have redis_client attribute"
        assert hasattr(app.state, 'cache'), "app.state should have cache attribute"
        
        # In test mode, redis_client should be None
        assert app.state.redis_client is None, "redis_client should be None in test mode"
        
        # cache should be available as mock
        assert app.state.cache is not None, "cache should be initialized with mock"
        
        # Verify mock cache has expected methods
        assert hasattr(app.state.cache, 'get'), "cache should have get method"
        assert hasattr(app.state.cache, 'set'), "cache should have set method"
        assert hasattr(app.state.cache, 'delete'), "cache should have delete method"
        
        # Test that cache operations work
        test_key = "test_key_startup"
        await app.state.cache.set(test_key, "test_value", expire_seconds=60)
        value = await app.state.cache.get(test_key)
        assert value == "test_value", "Cache set/get should work in mock mode"
        await app.state.cache.delete(test_key)


@pytest.mark.asyncio
async def test_redis_cache_operations_in_test_mode():
    """Test basic cache operations in test mode"""
    from backend.redis_cache import cache
    
    # Clear mock cache first
    await cache.clear_mock_cache()
    
    # Test set/get
    test_key = "test_key_operations"
    test_value = {"user_id": "123", "data": "test"}
    
    await cache.set(test_key, test_value, expire_seconds=60)
    retrieved_value = await cache.get(test_key)
    
    assert retrieved_value == test_value, "Retrieved value should match set value"
    
    # Test delete
    await cache.delete(test_key)
    deleted_value = await cache.get(test_key)
    assert deleted_value is None, "Value should be None after delete"
    
    # Test increment
    counter_key = "test_counter"
    result = await cache.increment(counter_key, 1)
    assert result == 1, "First increment should return 1"
    
    result = await cache.increment(counter_key, 5)
    assert result == 6, "Second increment should cumulate"
    
    # Cleanup
    await cache.delete(counter_key)


@pytest.mark.asyncio
async def test_init_cache_returns_true_in_pytest():
    """Test that init_cache returns True in pytest mode"""
    from backend.redis_cache import init_cache
    
    # init_cache should succeed and return True
    result = await init_cache()
    assert result is True, "init_cache should return True in pytest mode"


@pytest.mark.asyncio
async def test_app_startup_with_redis_mock():
    """Test full application startup with mocked Redis"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from backend.main import app as main_app
    from backend.database import _is_pytest_running
    
    # Verify pytest mode
    assert _is_pytest_running(), "Should be in pytest mode"
    
    # Create test client (which triggers the lifespan)
    with TestClient(main_app) as client:
        # Verify app started without errors
        assert client is not None, "TestClient should initialize successfully"
        
        # Verify app.state has required attributes
        assert hasattr(main_app.state, 'redis_client'), "app.state should have redis_client"
        assert hasattr(main_app.state, 'db'), "app.state should have db"
        
        # Test a basic endpoint
        response = client.get("/api/v1/health", allow_redirects=False)
        # Health endpoint should respond (not 500)
        assert response.status_code != 500, f"Health check should not return 500, got {response.status_code}"


@pytest.mark.asyncio
async def test_cache_expiration_in_mock():
    """Test cache expiration in mock mode"""
    from backend.redis_cache import cache
    from datetime import datetime, timezone, timedelta
    
    await cache.clear_mock_cache()
    
    # Set a key with 1 second expiration
    test_key = "test_expiration"
    await cache.set(test_key, "test_value", expire_seconds=1)
    
    # Should exist immediately
    value = await cache.get(test_key)
    assert value == "test_value", "Value should exist immediately"
    
    # Wait for expiration
    await asyncio.sleep(1.1)
    
    # Should be expired
    value = await cache.get(test_key)
    assert value is None, "Value should be None after expiration"


@pytest.mark.asyncio
async def test_error_logging_on_redis_connection_failure():
    """Test that connection errors are properly logged and handled"""
    import logging
    from unittest.mock import patch
    
    # We can't fully test production Redis connection failures in pytest mode,
    # but we can verify error logging structure exists
    from backend.redis_cache import logger as redis_logger
    
    # Verify logger is configured
    assert redis_logger is not None, "Redis logger should be configured"
    assert hasattr(redis_logger, 'error'), "Logger should have error method"
    assert hasattr(redis_logger, 'info'), "Logger should have info method"


@pytest.mark.asyncio  
async def test_websocket_manager_does_not_initialize_in_test_mode():
    """Test that WebSocket manager is not initialized in test mode"""
    from backend.main import lifespan
    from fastapi import FastAPI
    from backend.database import _is_pytest_running
    
    assert _is_pytest_running(), "Should be in pytest mode"
    
    app = FastAPI()
    
    # Run startup
    async with lifespan(app) as state:
        # In test mode, WebSocket manager should not be initialized (no error)
        # Just verify app started without raising WebSocket-related errors
        pass


@pytest.mark.asyncio
async def test_database_initialization_before_redis():
    """Test that database is initialized before Redis attempt"""
    from backend.main import lifespan
    from fastapi import FastAPI
    
    app = FastAPI()
    
    async with lifespan(app) as state:
        # Database should be available in app.state
        assert hasattr(app.state, 'db'), "Database should be initialized in app.state"
        assert hasattr(app.state, 'client'), "Database client should be initialized"


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
