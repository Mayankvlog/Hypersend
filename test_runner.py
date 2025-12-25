#!/usr/bin/env python3
"""
Comprehensive test runner for 401 and 409 error handling
Includes setup, test execution, and result reporting
"""

import subprocess
import sys
import time
import os

def run_tests():
    """Run the error handling tests"""
    print("\n" + "="*80)
    print("HYPERSEND ERROR HANDLING TEST SUITE")
    print("="*80)
    
    # Run the main test file
    print("\n📋 Running 401/409 error tests...")
    try:
        result = subprocess.run(
            [sys.executable, "test_401_409_errors.py"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=False,
            timeout=60
        )
        
        if result.returncode == 0:
            print("\n✅ Tests completed successfully")
            return True
        else:
            print(f"\n❌ Tests failed with exit code {result.returncode}")
            return False
    except subprocess.TimeoutExpired:
        print("\n❌ Tests timed out")
        return False
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
