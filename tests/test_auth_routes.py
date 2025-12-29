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
        # Read auth.py file
        with open('routes/auth.py', 'r') as f:
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
        
        if missing_decorators:
            print(f"❌ Missing decorators: {missing_decorators}")
            return False
        else:
            print("✅ All auth routes have proper HTTP method decorators")
            
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
            print("✅ All auth routes have CORS OPTIONS handlers")
            
        # Verify router prefix
        if 'prefix="/auth"' in content:
            print("✅ Auth router has correct prefix")
        else:
            print("❌ Auth router missing prefix")
            return False
        
        print("🎯 HTTP 405 Method Not Allowed fix verified!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing auth routes: {e}")
        return False

if __name__ == "__main__":
    success = test_auth_routes()
    sys.exit(0 if success else 1)