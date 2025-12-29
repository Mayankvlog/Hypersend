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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.auth.utils import (
    create_access_token, decode_token, get_current_user_from_query
)
from backend.models import TokenData
from fastapi import Query, HTTPException


def test_get_current_user_from_query_implementation():
    """Test that get_current_user_from_query is properly defined with Query()"""
    
    # Check that the function exists
    if not hasattr(get_current_user_from_query, '__call__'):
        print("✗ FAILED: get_current_user_from_query is not callable")
        return False
    
    # Check function signature has Query parameter
    import inspect
    sig = inspect.signature(get_current_user_from_query)
    params = list(sig.parameters.values())
    
    if len(params) != 1:
        print(f"✗ FAILED: Expected 1 parameter, got {len(params)}")
        return False
    
    param = params[0]
    
    # Check parameter name is 'token'
    if param.name != 'token':
        print(f"✗ FAILED: Expected parameter name 'token', got '{param.name}'")
        return False
    
    # Check parameter uses Query() dependency
    if not hasattr(param.default, '__class__'):
        print("✗ FAILED: Parameter doesn't have Query() dependency")
        return False
    
    # The default should be a Query object
    default_class_name = param.default.__class__.__name__
    if 'Query' not in default_class_name and not isinstance(param.default, type(Query(None))):
        print(f"✗ FAILED: Parameter uses {default_class_name}, not Query()")
        return False
    
    print("✓ PASSED: get_current_user_from_query properly uses Query() dependency")
    return True


def test_token_parameter_handling():
    """Test that token parameter is extracted from query correctly"""
    
    # Create a test token
    user_id = "test_user_123"
    token_data = {
        "sub": user_id,
        "token_type": "access"
    }
    
    test_token = create_access_token(token_data)
    
    if not test_token:
        print("✗ FAILED: Could not create test token")
        return False
    
    # Verify token can be decoded
    try:
        decoded = decode_token(test_token)
        if decoded.user_id != user_id:
            print(f"✗ FAILED: Decoded user_id '{decoded.user_id}' != expected '{user_id}'")
            return False
    except Exception as e:
        print(f"✗ FAILED: Could not decode token: {e}")
        return False
    
    print("✓ PASSED: Token parameter handling works correctly")
    return True


def test_none_token_raises_exception():
    """Test that None token raises appropriate HTTPException"""
    import asyncio
    
    async def test_async():
        try:
            # Call with None token (which is the default in Query(None))
            result = await get_current_user_from_query(token=None)
            print("✗ FAILED: Expected HTTPException for None token, but got result")
            return False
        except HTTPException as e:
            # Should raise 401 Unauthorized
            if e.status_code != 401:
                print(f"✗ FAILED: Expected status 401, got {e.status_code}")
                return False
            if "required in query parameters" not in e.detail:
                print(f"✗ FAILED: Expected 'required in query parameters' in detail, got '{e.detail}'")
                return False
            print("✓ PASSED: None token properly raises HTTPException with 401")
            return True
        except Exception as e:
            print(f"✗ FAILED: Unexpected exception: {type(e).__name__}: {e}")
            return False
    
    return asyncio.run(test_async())


def test_invalid_token_raises_exception():
    """Test that invalid token raises appropriate HTTPException"""
    import asyncio
    
    async def test_async():
        try:
            # Call with invalid token
            result = await get_current_user_from_query(token="invalid.token.here")
            print("✗ FAILED: Expected HTTPException for invalid token")
            return False
        except HTTPException as e:
            # Should raise 401 Unauthorized
            if e.status_code != 401:
                print(f"✗ FAILED: Expected status 401, got {e.status_code}")
                return False
            print("✓ PASSED: Invalid token properly raises HTTPException with 401")
            return True
        except Exception as e:
            print(f"✗ FAILED: Unexpected exception: {type(e).__name__}: {e}")
            return False
    
    return asyncio.run(test_async())


def test_valid_token_returns_user_id():
    """Test that valid token returns the user_id"""
    import asyncio
    
    async def test_async():
        try:
            # Create a valid token
            user_id = "valid_user_456"
            token_data = {
                "sub": user_id,
                "token_type": "access"
            }
            test_token = create_access_token(token_data)
            
            # Call with valid token
            result = await get_current_user_from_query(token=test_token)
            
            if result != user_id:
                print(f"✗ FAILED: Expected user_id '{user_id}', got '{result}'")
                return False
            
            print("✓ PASSED: Valid token properly returns user_id")
            return True
        except Exception as e:
            print(f"✗ FAILED: Unexpected exception: {type(e).__name__}: {e}")
            return False
    
    return asyncio.run(test_async())


def test_refresh_token_raises_exception():
    """Test that refresh token (wrong type) raises exception"""
    import asyncio
    
    async def test_async():
        try:
            # Create a refresh token instead of access token
            from backend.auth.utils import create_refresh_token
            user_id = "test_user_refresh"
            token_data = {"sub": user_id}
            test_token, jti = create_refresh_token(token_data)
            
            # Call with refresh token (should fail)
            result = await get_current_user_from_query(token=test_token)
            print("✗ FAILED: Expected HTTPException for refresh token (wrong type)")
            return False
        except HTTPException as e:
            if e.status_code != 401:
                print(f"✗ FAILED: Expected status 401, got {e.status_code}")
                return False
            if "Invalid token type" not in e.detail:
                print(f"✗ FAILED: Expected 'Invalid token type' in detail, got '{e.detail}'")
                return False
            print("✓ PASSED: Refresh token properly raises HTTPException")
            return True
        except Exception as e:
            print(f"✗ FAILED: Unexpected exception: {type(e).__name__}: {e}")
            return False
    
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
            print(f"✗ ERROR in {test.__name__}: {type(e).__name__}: {e}")
            results.append(False)
    
    print()
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")
    if passed == total:
        print("✓ ALL TESTS PASSED")
    else:
        print(f"✗ {total - passed} TEST(S) FAILED")
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
