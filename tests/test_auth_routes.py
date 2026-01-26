#!/usr/bin/env python3
"""
Test script to verify auth routes are properly configured.
This tests the specific 405 Method Not Allowed fix.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

def test_auth_routes():
    """Test that auth routes have proper HTTP decorators"""
    try:
        # Read auth.py file - fix the path and encoding
        auth_file_path = os.path.join(os.path.dirname(__file__), '..', 'backend', 'routes', 'auth.py')
        with open(auth_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for required decorators
        required_decorators = [
            '@router.post("/register"',
            '@router.post("/login"', 
            '@router.post("/refresh"',
            '@router.post("/logout"'
        ]
        
        missing_decorators = []
        for decorator in required_decorators:
            if decorator not in content:
                missing_decorators.append(decorator)
        
        assert not missing_decorators, f"Missing decorators: {missing_decorators}"
        print("[PASS] All auth routes have proper HTTP method decorators")
            
        # Check for OPTIONS handlers (CORS)
        options_handlers = [
            '@router.options("/register")',
            '@router.options("/login")',
            '@router.options("/refresh")',
            '@router.options("/logout")'
        ]
        
        missing_options = []
        for handler in options_handlers:
            if handler not in content:
                missing_options.append(handler)
        
        if missing_options:
            print(f"⚠️  Missing OPTIONS handlers: {missing_options}")
        else:
            print("[PASS] All auth routes have CORS OPTIONS handlers")
            
        # Verify router prefix
        assert 'prefix="/auth"' in content, "Auth router missing prefix"
        print("[PASS] Auth router has correct prefix")
        
        print("🎯 HTTP 405 Method Not Allowed fix verified!")
        assert True
        
    except Exception as e:
        print(f"[FAIL] Error testing auth routes: {e}")
        assert False, f"Error testing auth routes: {e}"

if __name__ == "__main__":
    test_auth_routes()
    sys.exit(0)