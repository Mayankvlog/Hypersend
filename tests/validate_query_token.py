#!/usr/bin/env python3
"""
Validation script to ensure Query-based token parameter doesn't break existing code
Checks all route files for proper usage of get_current_user and get_current_user_from_query
"""

import os
import re
import sys


def validate_imports():
    """Validate that new function is properly exported and imports work"""
    print("\n[1] VALIDATING IMPORTS")
    print("-" * 70)
    
    # Add backend to path
    backend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend')
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)
    
    try:
        from auth.utils import (
            get_current_user, 
            get_current_user_from_query,
            create_access_token,
            decode_token
        )
        print("✓ All functions imported successfully from auth.utils")
        
        from routes.auth import get_current_user_from_query as auth_import
        print("✓ get_current_user_from_query imported in routes.auth")
        
        return True
    except ImportError as e:
        print(f"✗ FAILED: Import error: {e}")
        return False


def check_function_signatures():
    """Check that functions have correct signatures"""
    print("\n[2] VALIDATING FUNCTION SIGNATURES")
    print("-" * 70)
    
    import inspect
    from auth.utils import get_current_user, get_current_user_from_query
    
    # Check get_current_user (should use HTTPAuthorizationCredentials = Depends(security))
    sig1 = inspect.signature(get_current_user)
    params1 = list(sig1.parameters.values())
    
    if len(params1) != 1:
        print(f"✗ FAILED: get_current_user has {len(params1)} params, expected 1")
        return False
    
    param1 = params1[0]
    if param1.name != 'credentials':
        print(f"✗ FAILED: get_current_user param is '{param1.name}', expected 'credentials'")
        return False
    
    print("✓ get_current_user has correct signature (credentials: HTTPAuthorizationCredentials = Depends(security))")
    
    # Check get_current_user_from_query (should use token: Optional[str] = Query(None))
    sig2 = inspect.signature(get_current_user_from_query)
    params2 = list(sig2.parameters.values())
    
    if len(params2) != 1:
        print(f"✗ FAILED: get_current_user_from_query has {len(params2)} params, expected 1")
        return False
    
    param2 = params2[0]
    if param2.name != 'token':
        print(f"✗ FAILED: get_current_user_from_query param is '{param2.name}', expected 'token'")
        return False
    
    # Check that it uses Query
    if 'Query' not in str(param2.default.__class__.__name__):
        print(f"✗ FAILED: get_current_user_from_query doesn't use Query() - uses {param2.default.__class__.__name__}")
        return False
    
    print("✓ get_current_user_from_query has correct signature (token: Optional[str] = Query(None))")
    
    return True


def validate_all_route_usages():
    """Check that all route files properly use get_current_user"""
    print("\n[3] VALIDATING ROUTE USAGES")
    print("-" * 70)
    
    route_files = [
        'backend/routes/auth.py',
        'backend/routes/debug.py',
        'backend/routes/users.py',
        'backend/routes/updates.py',
        'backend/routes/p2p_transfer.py',
        'backend/routes/channels.py',
        'backend/routes/chats.py',
        'backend/routes/files.py',
        'backend/routes/groups.py',
        'backend/routes/messages.py',
    ]
    
    issues = []
    all_valid = True
    
    for route_file in route_files:
        if not os.path.exists(route_file):
            print(f"⊘ {route_file} - NOT FOUND (skipped)")
            continue
        
        with open(route_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for get_current_user usage
        if 'get_current_user' in content:
            # Should always be used with Depends()
            pattern = r'Depends\s*\(\s*get_current_user'
            if re.search(pattern, content):
                usage_count = len(re.findall(pattern, content))
                print(f"✓ {route_file}: {usage_count} correct usage(s) of get_current_user")
            else:
                # Check for bare usage (which would be wrong)
                if re.search(r':\s*get_current_user\b', content):
                    print(f"✗ {route_file}: Found bare get_current_user usage (missing Depends)")
                    issues.append(f"{route_file}: bare get_current_user")
                    all_valid = False
    
    if all_valid:
        print("\n✓ All route usages are valid")
    else:
        print(f"\n✗ Found {len(issues)} usage issue(s)")
        for issue in issues:
            print(f"  - {issue}")
    
    return all_valid


def validate_query_parameter_usage():
    """Validate that Query() is properly imported and used"""
    print("\n[4] VALIDATING QUERY PARAMETER USAGE")
    print("-" * 70)
    
    # Check auth/utils.py
    with open('backend/auth/utils.py', 'r', encoding='utf-8') as f:
        utils_content = f.read()
    
    # Check for Query import
    if 'from fastapi import' in utils_content and 'Query' in utils_content:
        print("✓ Query is imported in backend/auth/utils.py")
    else:
        print("✗ FAILED: Query not imported in backend/auth/utils.py")
        return False
    
    # Check for Query usage in get_current_user_from_query
    if 'Query(None)' in utils_content:
        print("✓ Query(None) is used in get_current_user_from_query")
    else:
        print("✗ FAILED: Query(None) not found in get_current_user_from_query")
        return False
    
    return True


def validate_no_breaking_changes():
    """Ensure existing get_current_user still works"""
    print("\n[5] VALIDATING NO BREAKING CHANGES")
    print("-" * 70)
    
    import asyncio
    from auth.utils import (
        get_current_user, 
        create_access_token,
        HTTPAuthorizationCredentials
    )
    from fastapi.security import HTTPBearer
    
    # Test that get_current_user still works with Bearer token
    async def test_header_auth():
        try:
            # Create a test token
            user_id = "test_user"
            token_data = {"sub": user_id, "token_type": "access"}
            test_token = create_access_token(token_data)
            
            # Create mock credentials
            mock_credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials=test_token
            )
            
            # Call get_current_user
            result = await get_current_user(mock_credentials)
            
            if result == user_id:
                print("✓ get_current_user still works with Bearer token (no breaking changes)")
                return True
            else:
                print(f"✗ FAILED: get_current_user returned '{result}', expected '{user_id}'")
                return False
        except Exception as e:
            print(f"✗ FAILED: get_current_user error: {type(e).__name__}: {e}")
            return False
    
    return asyncio.run(test_header_auth())


def main():
    """Run all validations"""
    print("=" * 70)
    print("VALIDATION: QUERY-BASED TOKEN PARAMETER")
    print("=" * 70)
    
    checks = [
        ("Imports", validate_imports),
        ("Function Signatures", check_function_signatures),
        ("Route Usages", validate_all_route_usages),
        ("Query Parameter Usage", validate_query_parameter_usage),
        ("No Breaking Changes", validate_no_breaking_changes),
    ]
    
    results = []
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ ERROR in {name}: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    print()
    print(f"Total: {passed}/{total} validations passed")
    
    if passed == total:
        print("\n✓ ALL VALIDATIONS PASSED - NO BREAKING CHANGES DETECTED")
        return True
    else:
        print(f"\n✗ {total - passed} VALIDATION(S) FAILED")
        return False


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nValidation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFATAL ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
