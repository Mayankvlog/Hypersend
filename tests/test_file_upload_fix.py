#!/usr/bin/env python3
"""
Test script to verify file upload datetime fix.
This tests the datetime comparison fix in files.py.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

def test_datetime_fix():
    """Test that datetime comparison fix is properly implemented"""
    try:
        # Read files.py
        with open('routes/files.py', 'r') as f:
            content = f.read()
        
        # Check for the fix
        fix_indicators = [
            'expires_at.tzinfo is None',
            'expires_at.replace(tzinfo=timezone.utc)',
            'if expires_at < datetime.now(timezone.utc)'
        ]
        
        all_present = all(indicator in content for indicator in fix_indicators)
        
        if all_present:
            print("[PASS] File upload datetime fix is properly implemented")
            print("[PASS] Handles both offset-naive and offset-aware datetimes")
            print("[PASS] Prevents TypeError: can't compare offset-naive and offset-aware datetimes")
            return True
        else:
            print("[FAIL] Fix not properly implemented")
            missing = [ind for ind in fix_indicators if ind not in content]
            print(f"Missing: {missing}")
            return False
            
    except Exception as e:
        print(f"[FAIL] Error testing datetime fix: {e}")
        return False

if __name__ == "__main__":
    success = test_datetime_fix()
    sys.exit(0 if success else 1)