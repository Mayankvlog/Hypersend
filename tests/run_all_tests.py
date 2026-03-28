#!/usr/bin/env python3
"""
Run all test files to verify 404 error fix
"""

import subprocess
import sys
import os

def run_test_file(test_file):
    """Run a single test file"""
    print(f"\n🧪 Running {test_file}...")
    try:
        result = subprocess.run([sys.executable, test_file], 
                              capture_output=True, text=True, 
                              cwd=os.path.dirname(__file__))
        
        print(f"📊 Exit code: {result.returncode}")
        if result.stdout:
            print(f"📝 Output:\n{result.stdout}")
        if result.stderr:
            print(f"❌ Error:\n{result.stderr}")
            
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Error running {test_file}: {e}")
        return False

def main():
    """Run all test files"""
    print("🎯 RUNNING ALL 404 ERROR FIX TESTS")
    print("=" * 60)
    
    # List of test files to run
    test_files = [
        "tests/test_download_only.py",
        "tests/test_final_fix.py", 
        "tests/test_immediate_download.py",
        "tests/test_real_upload_download.py",
        "tests/test_upload_download_fix.py",
        "tests/test_database_connection.py",
        "tests/test_direct_database.py",
        "tests/test_upload_db_debug.py"
    ]
    
    results = []
    
    for test_file in test_files:
        if os.path.exists(test_file):
            success = run_test_file(test_file)
            results.append((test_file, success))
        else:
            print(f"❌ Test file not found: {test_file}")
            results.append((test_file, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for test_file, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_file}")
        if success:
            passed += 1
        else:
            failed += 1
    
    print(f"\n📈 Total Tests: {len(results)}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
        print("📌 404 ERROR FIX SUCCESSFUL!")
    else:
        print(f"\n❌ {failed} TESTS FAILED")
        print("📌 404 ERROR FIX IN PROGRESS")

if __name__ == "__main__":
    main()
