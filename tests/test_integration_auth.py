#!/usr/bin/env python3
"""
Comprehensive integration test demonstrating both token authentication methods
"""

import sys
import os
import asyncio
from datetime import datetime, timedelta

# Add backend to Python path
backend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend')
sys.path.insert(0, backend_path)

from auth.utils import (
    create_access_token,
    get_current_user,
    get_current_user_from_query
)
from security import SecurityConfig
from fastapi.security import HTTPAuthorizationCredentials


async def test_bearer_token_authentication():
    """Test original Bearer token authentication method"""
    print("\n[TEST 1] Bearer Token Authentication (Original Method)")
    print("-" * 70)
    
    try:
        # Create test token
        user_id = "user_bearer_123"
        token_data = {
            "sub": user_id,
            "token_type": "access"
        }
        token = create_access_token(token_data)
        print(f"[PASS] Created token for user: {user_id}")
        print(f"  Token (first 50 chars): {token[:50]}...")
        
        # Simulate Bearer authentication
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        print(f"[PASS] Created Bearer credentials")
        
        # Call get_current_user
        result = await get_current_user(credentials)
        
        if result == user_id:
            print(f"[PASS] PASSED: get_current_user returned correct user_id: {result}")
            return True
        else:
            print(f"[FAIL] FAILED: Expected {user_id}, got {result}")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {type(e).__name__}: {e}")
        return False


async def test_query_token_authentication():
    """Test new Query parameter token authentication method"""
    print("\n[TEST 2] Query Parameter Token Authentication (New Method)")
    print("-" * 70)
    
    try:
        # Create test token
        user_id = "user_query_456"
        token_data = {
            "sub": user_id,
            "token_type": "access"
        }
        token = create_access_token(token_data)
        print(f"[PASS] Created token for user: {user_id}")
        print(f"  Token would be passed as: ?token={token[:20]}...")
        
        # Call get_current_user_from_query with token from query
        result = await get_current_user_from_query(token=token)
        
        if result == user_id:
            print(f"[PASS] PASSED: get_current_user_from_query returned correct user_id: {result}")
            return True
        else:
            print(f"[FAIL] FAILED: Expected {user_id}, got {result}")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {type(e).__name__}: {e}")
        return False


async def test_query_missing_token():
    """Test Query authentication with missing token"""
    print("\n[TEST 3] Query Authentication - Missing Token")
    print("-" * 70)
    
    try:
        # Call without token (default None)
        result = await get_current_user_from_query(token=None)
        print(f"[FAIL] FAILED: Should have raised HTTPException, got: {result}")
        return False
        
    except Exception as e:
        if "401" in str(e) or "Unauthorized" in str(e):
            print(f"[PASS] PASSED: Correctly raised HTTPException for missing token")
            print(f"  Error: {e}")
            return True
        else:
            print(f"[FAIL] FAILED: Wrong exception: {type(e).__name__}: {e}")
            return False


async def test_mixed_usage_scenario():
    """Test realistic scenario with both auth methods in same system"""
    print("\n[TEST 4] Mixed Usage Scenario")
    print("-" * 70)
    
    try:
        # Simulate API with both authentication options
        api_users = {
            "user_web": "Uses Bearer token (web browser)",
            "user_mobile": "Uses Query parameter (mobile/legacy)",
            "user_desktop": "Uses Bearer token (desktop app)",
        }
        
        print("Simulating endpoints with dual authentication support:")
        print()
        
        successful = 0
        
        # Web user with Bearer
        user_web = "user_web"
        token_web = create_access_token({
            "sub": user_web,
            "token_type": "access"
        })
        creds_web = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_web)
        result_web = await get_current_user(creds_web)
        if result_web == user_web:
            print(f"  [PASS] {user_web}: Bearer auth successful")
            successful += 1
        
        # Mobile user with Query
        user_mobile = "user_mobile"
        token_mobile = create_access_token({
            "sub": user_mobile,
            "token_type": "access"
        })
        result_mobile = await get_current_user_from_query(token=token_mobile)
        if result_mobile == user_mobile:
            print(f"  [PASS] {user_mobile}: Query auth successful")
            successful += 1
        
        # Desktop user with Bearer
        user_desktop = "user_desktop"
        token_desktop = create_access_token({
            "sub": user_desktop,
            "token_type": "access"
        })
        creds_desktop = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_desktop)
        result_desktop = await get_current_user(creds_desktop)
        if result_desktop == user_desktop:
            print(f"  [PASS] {user_desktop}: Bearer auth successful")
            successful += 1
        
        print()
        if successful == 3:
            print(f"[PASS] PASSED: All {successful} auth methods working in mixed scenario")
            return True
        else:
            print(f"[FAIL] FAILED: Only {successful}/3 auth methods succeeded")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {type(e).__name__}: {e}")
        return False


async def test_token_validation_consistency():
    """Test that both methods validate tokens the same way"""
    print("\n[TEST 5] Token Validation Consistency")
    print("-" * 70)
    
    try:
        user_id = "validation_test"
        token_data = {
            "sub": user_id,
            "token_type": "access"
        }
        token = create_access_token(token_data)
        
        # Test with Bearer
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        result_bearer = await get_current_user(creds)
        
        # Test with Query
        result_query = await get_current_user_from_query(token=token)
        
        if result_bearer == result_query == user_id:
            print(f"[PASS] PASSED: Both methods validate tokens identically")
            print(f"  Bearer result: {result_bearer}")
            print(f"  Query result: {result_query}")
            return True
        else:
            print(f"[FAIL] FAILED: Results differ")
            print(f"  Bearer: {result_bearer}")
            print(f"  Query: {result_query}")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {type(e).__name__}: {e}")
        return False


async def main():
    """Run all integration tests"""
    print("=" * 70)
    print("INTEGRATION TEST: BEARER vs QUERY TOKEN AUTHENTICATION")
    print("=" * 70)
    
    tests = [
        test_bearer_token_authentication,
        test_query_token_authentication,
        test_query_missing_token,
        test_mixed_usage_scenario,
        test_token_validation_consistency,
    ]
    
    results = []
    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"\n[FAIL] ERROR in {test.__name__}: {type(e).__name__}: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "=" * 70)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    
    for i, (test, result) in enumerate(zip(tests, results)):
        status = "[PASS]" if result else "[FAIL]"
        test_name = test.__name__.replace('test_', '').replace('_', ' ').title()
        print(f"{status} Test {i+1}: {test_name}")
    
    print()
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[PASS] ALL INTEGRATION TESTS PASSED")
        print("Both Bearer and Query token authentication methods are working correctly!")
        return True
    else:
        print(f"\n[FAIL] {total - passed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFATAL ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
