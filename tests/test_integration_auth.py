#!/usr/bin/env python3
"""
Comprehensive integration test for current authentication methods
"""

import os
import sys
import os
import asyncio
import pytest
from datetime import datetime, timedelta

# Add backend to Python path
backend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend')
sys.path.insert(0, backend_path)

from auth.utils import (
    create_access_token,
    decode_token
)


@pytest.mark.asyncio
async def test_bearer_token_authentication():
    """Test token creation and basic validation"""
    print("\n[TEST 1] Bearer Token Authentication")
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
        
        # Decode the token to verify it was created correctly
        decoded = decode_token(token)
        
        if decoded.user_id == user_id and decoded.token_type == "access":
            print(f"[PASS] PASSED: Token created and decoded correctly")
            print(f"  User ID: {decoded.user_id}")
            print(f"  Token Type: {decoded.token_type}")
            return True
        else:
            print(f"[FAIL] FAILED: Token validation failed")
            print(f"  Expected user_id: {user_id}, got: {decoded.user_id}")
            print(f"  Expected token_type: access, got: {decoded.token_type}")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {type(e).__name__}: {e}")
        return False


@pytest.mark.asyncio
async def test_token_validation():
    """Test JWT token validation and decoding"""
    print("\n[TEST 2] JWT Token Validation and Decoding")
    print("-" * 70)
    
    try:
        # Create test token
        user_id = "user_validation_456"
        token_data = {
            "sub": user_id,
            "token_type": "access"
        }
        token = create_access_token(token_data)
        print(f"[PASS] Created token for user: {user_id}")
        print(f"  Token (first 50 chars): {token[:50]}...")
        
        # Decode and validate token
        decoded = decode_token(token)
        
        if decoded.user_id == user_id and decoded.token_type == "access":
            print(f"[PASS] PASSED: Token decoded correctly")
            print(f"  User ID: {decoded.user_id}")
            print(f"  Token Type: {decoded.token_type}")
            return True
        else:
            print(f"[FAIL] FAILED: Token validation failed")
            print(f"  Expected user_id: {user_id}, got: {decoded.user_id}")
            print(f"  Expected token_type: access, got: {decoded.token_type}")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {type(e).__name__}: {e}")
        return False


@pytest.mark.asyncio
async def test_invalid_token():
    """Test authentication with invalid token"""
    print("\n[TEST 3] Invalid Token Authentication")
    print("-" * 70)
    
    try:
        # Test with completely invalid token
        invalid_token = "this.is.not.a.valid.jwt.token"
        
        print(f"[PASS] Testing invalid token: {invalid_token}")
        
        # This should raise an exception when trying to decode
        decoded = decode_token(invalid_token)
        print(f"[FAIL] FAILED: Should have raised exception for invalid token, got: {decoded}")
        return False
        
    except Exception as e:
        if "invalid" in str(e).lower() or "decode" in str(e).lower() or "signature" in str(e).lower() or "validate" in str(e).lower():
            print(f"[PASS] PASSED: Correctly raised exception for invalid token")
            print(f"  Error type: {type(e).__name__}")
            return True
        else:
            print(f"[FAIL] FAILED: Wrong exception: {type(e).__name__}: {e}")
            return False


@pytest.mark.asyncio
async def test_mixed_usage_scenario():
    """Test realistic scenario with multiple users using token authentication"""
    print("\n[TEST 4] Multiple Users Scenario")
    print("-" * 70)
    
    try:
        # Simulate API with multiple users using token authentication
        api_users = {
            "user_web": "Uses token authentication (web browser)",
            "user_mobile": "Uses token authentication (mobile app)",
            "user_desktop": "Uses token authentication (desktop app)",
        }
        
        print("Simulating endpoints with token authentication support:")
        print()
        
        successful = 0
        
        # Test each user
        for user_name, description in api_users.items():
            token = create_access_token({
                "sub": user_name,
                "token_type": "access"
            })
            
            # Validate token via decode
            decoded = decode_token(token)
            
            if decoded.user_id == user_name and decoded.token_type == "access":
                print(f"  [PASS] {user_name}: Token auth successful")
                successful += 1
            else:
                print(f"  [FAIL] {user_name}: Token validation failed")
        
        print()
        if successful == 3:
            print(f"[PASS] PASSED: All {successful} users authenticated successfully")
            return True
        else:
            print(f"[FAIL] FAILED: Only {successful}/3 users authenticated successfully")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {type(e).__name__}: {e}")
        return False


@pytest.mark.asyncio
async def test_token_validation_consistency():
    """Test token creation and validation consistency"""
    print("\n[TEST 5] Token Validation Consistency")
    print("-" * 70)
    
    try:
        # Create multiple tokens and verify consistency
        test_users = ["user_consistency_1", "user_consistency_2", "user_consistency_3"]
        tokens = []
        
        # Create tokens
        for user_id in test_users:
            token = create_access_token({
                "sub": user_id,
                "token_type": "access"
            })
            tokens.append((user_id, token))
            print(f"[PASS] Created token for {user_id}")
        
        # Validate all tokens via decode_token
        successful = 0
        for user_id, token in tokens:
            decoded = decode_token(token)
            if decoded.user_id == user_id and decoded.token_type == "access":
                successful += 1
                print(f"  [PASS] {user_id}: Token validation consistent")
            else:
                print(f"  [FAIL] {user_id}: Expected {user_id}, got {decoded.user_id}")
        
        print()
        if successful == len(test_users):
            print(f"[PASS] PASSED: All {len(test_users)} tokens validated consistently")
            return True
        else:
            print(f"[FAIL] FAILED: Only {successful}/{len(test_users)} tokens validated correctly")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {type(e).__name__}: {e}")
        return False


async def main():
    """Run all integration tests"""
    print("=" * 70)
    print("INTEGRATION TEST: AUTHENTICATION SYSTEM")
    print("=" * 70)
    
    tests = [
        test_bearer_token_authentication,
        test_token_validation,
        test_invalid_token,
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
        print("Authentication system is working correctly!")
        return True
    else:
        print(f"\n[FAIL] {total - passed} TEST(S) FAILED")
        return False


@pytest.mark.asyncio
async def test_integration_auth():
    """Pytest wrapper for integration tests"""
    success = await main()
    assert success, "Integration tests failed"


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
