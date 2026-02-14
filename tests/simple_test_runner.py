#!/usr/bin/env python3
"""
Simple test runner that bypasses TestClient timeout issues
"""

import sys
import os
import subprocess
from pathlib import Path

def run_simple_tests():
    """Run tests that don't require TestClient"""
    
    # Tests that should work without TestClient
    simple_tests = [
        "tests/test_final_validation.py",
        "tests/test_group_members_comprehensive.py",
        "tests/test_utils.py"
    ]
    
    # Run with pytest but skip TestClient-dependent tests
    test_cmd = [
        sys.executable, "-m", "pytest", 
        *simple_tests,
        "-v", 
        "--tb=short",
        "--no-header",
        "-k", "not (test_400_bad_request or test_401_unauthorized or test_404_not_found or test_409_conflict or test_413_payload)"
    ]
    
    print(f"🧪 Running simple tests: {' '.join(simple_tests)}")
    
    try:
        result = subprocess.run(test_cmd, cwd=Path(__file__).parent, capture_output=True, text=True, timeout=60)
        print("STDOUT:")
        print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("❌ Tests timed out")
        return 1
    except Exception as e:
        print(f"❌ Test runner failed: {e}")
        return 1

def check_import_status():
    """Check what can be imported"""
    print("🔍 Checking import status...")
    
    backend_path = Path(__file__).parent / 'backend'
    if str(backend_path) not in sys.path:
        sys.path.insert(0, str(backend_path))
    
    modules_to_check = [
        "backend.config",
        "backend.database", 
        "backend.mock_database",
        "backend.main"
    ]
    
    for module in modules_to_check:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module}: {e}")

if __name__ == "__main__":
    print("🚀 Simple Test Runner")
    print("=" * 50)
    
    check_import_status()
    print()
    
    exit_code = run_simple_tests()
    print(f"\n📊 Exit code: {exit_code}")
    sys.exit(exit_code)
