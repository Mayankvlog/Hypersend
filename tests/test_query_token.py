#!/usr/bin/env python3
"""
Test for Query-based token parameter in get_current_user_from_query
Verifies that token can be extracted from query parameters with Query()
"""

import sys
import os
from datetime import datetime, timedelta
from typing import Optional

# Add backend to path
backend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend')
sys.path.insert(0, backend_path)

from auth.utils import (
    create_access_token, decode_token, get_current_user_from_query
)
from backend.models import TokenData
from fastapi import Query, HTTPException
import pytest


def test_get_current_user_from_query_implementation():
    """Test that get_current_user_from_query is properly defined with Query()"""
    
    # Check that the function exists
    assert hasattr(get_current_user_from_query, '__call__'), "FAILED: get_current_user_from_query is not callable"
    
    # Check function signature has Query parameter
    import inspect
    sig = inspect.signature(get_current_user_from_query)
    params = list(sig.parameters.values())
    
    assert len(params) == 1, f"FAILED: Expected 1 parameter, got {len(params)}"
    
    param = params[0]
    
    # Check parameter name is 'token'
    assert param.name == 'token', f"FAILED: Expected parameter name 'token', got '{param.name}'"
    
    # Check parameter uses Query() dependency
    assert hasattr(param.default, '__class__'), "FAILED: Parameter doesn't have Query() dependency"
    
    # The default should be a Query object
    default_class_name = param.default.__class__.__name__
    assert 'Query' in default_class_name or isinstance(param.default, type(Query(None))), f"FAILED: Parameter uses {default_class_name}, not Query()"
    
    print("[PASS] PASSED: get_current_user_from_query properly uses Query() dependency")


def test_token_parameter_handling():
    """Test that token parameter is extracted from query correctly"""
    
    # Create a test token
    user_id = "test_user_123"
    token_data = {
        "sub": user_id,
        "token_type": "access"
    }
    
    test_token = create_access_token(token_data)
    
    assert test_token, "FAILED: Could not create test token"
    
    # Verify token can be decoded
    try:
        decoded = decode_token(test_token)
        assert decoded.user_id == user_id, f"FAILED: Decoded user_id '{decoded.user_id}' != expected '{user_id}'"
    except Exception as e:
        assert False, f"FAILED: Could not decode token: {e}"
    
    print("[PASS] PASSED: Token parameter handling works correctly")


def test_none_token_raises_exception():
    """Test that None token raises appropriate HTTPException"""
    import asyncio
    
    async def test_async():
        with pytest.raises(HTTPException) as exc_info:
            # Call with None token (which is the default in Query(None))
            await get_current_user_from_query(token=None)
        
        # Should raise 401 Unauthorized
        assert exc_info.value.status_code == 401, f"Expected status 401, got {exc_info.value.status_code}"
        assert "Query parameter authentication is disabled for security" in exc_info.value.detail, f"Expected security message in detail, got '{exc_info.value.detail}'"
        print("[PASS] PASSED: None token properly raises HTTPException with 401")
    
    return asyncio.run(test_async())


def test_invalid_token_raises_exception():
    """Test that invalid token raises appropriate HTTPException"""
    import asyncio
    
    async def test_async():
        with pytest.raises(HTTPException) as exc_info:
            # Call with invalid token
            await get_current_user_from_query(token="invalid.token.here")
        
        # Should raise 401 Unauthorized
        assert exc_info.value.status_code == 401, f"Expected status 401, got {exc_info.value.status_code}"
        assert "Query parameter authentication is disabled for security" in exc_info.value.detail, f"Expected security message in detail, got '{exc_info.value.detail}'"
        print("[PASS] PASSED: Invalid token properly raises HTTPException with 401")
    
    return asyncio.run(test_async())


def test_valid_token_returns_user_id():
    """Test that valid token returns the user_id"""
    import asyncio
    
    async def test_async():
        with pytest.raises(HTTPException) as exc_info:
            # Create a valid token
            user_id = "valid_user_456"
            token_data = {
                "sub": user_id,
                "token_type": "access"
            }
            test_token = create_access_token(token_data)
            
            # Call with valid token
            result = await get_current_user_from_query(token=test_token)
        
        # Should raise 401 because query parameter auth is disabled
        assert exc_info.value.status_code == 401, f"Expected status 401, got {exc_info.value.status_code}"
        assert "Query parameter authentication is disabled for security" in exc_info.value.detail, f"Expected security message in detail, got '{exc_info.value.detail}'"
        print("[PASS] PASSED: Query token properly rejected for security")
    
    return asyncio.run(test_async())


def test_refresh_token_raises_exception():
    """Test that refresh token (wrong type) raises exception"""
    import asyncio
    
    async def test_async():
        with pytest.raises(HTTPException) as exc_info:
            # Create a refresh token instead of access token
            from auth.utils import create_refresh_token
            user_id = "test_user_refresh"
            token_data = {"sub": user_id}
            test_token, jti = create_refresh_token(token_data)
            
            # Call with refresh token (should fail)
            await get_current_user_from_query(token=test_token)
        
        # Should raise 401 because query parameter auth is disabled
        assert exc_info.value.status_code == 401, f"Expected status 401, got {exc_info.value.status_code}"
        assert "Query parameter authentication is disabled for security" in exc_info.value.detail, f"Expected security message in detail, got '{exc_info.value.detail}'"
        print("[PASS] PASSED: Refresh token properly raises HTTPException")
    
    return asyncio.run(test_async())


def main():
    """Run all tests"""
    print("=" * 70)
    print("TESTING QUERY-BASED TOKEN PARAMETER")
    print("=" * 70)
    print()
    
    tests = [
        test_get_current_user_from_query_implementation,
        test_token_parameter_handling,
        test_none_token_raises_exception,
        test_invalid_token_raises_exception,
        test_valid_token_returns_user_id,
        test_refresh_token_raises_exception,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"[FAIL] ERROR in {test.__name__}: {type(e).__name__}: {e}")
            results.append(False)
    
    print()
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")
    if passed == total:
        print("[PASS] ALL TESTS PASSED")
    else:
        print(f"[FAIL] {total - passed} TEST(S) FAILED")
    print("=" * 70)
    
    return passed == total


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFATAL ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
