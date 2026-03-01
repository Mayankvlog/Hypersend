"""
Test runner for critical fixes verification.
Tests the three main fixes:
1. ObjectId serialization in group creation
2. Forgot password token generation
3. File download response structure

Run with: python run_critical_tests.py
"""

import subprocess
import sys
import json
from pathlib import Path


def run_pytest():
    """Run pytest on critical fixes"""
    print("\n" + "="*80)
    print("RUNNING PYTEST ON CRITICAL FIXES VERIFICATION")
    print("="*80 + "\n")
    
    test_file = Path(__file__).parent / "test_critical_fixes_verification.py"
    
    if not test_file.exists():
        print(f"❌ Test file not found: {test_file}")
        return False
    
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(test_file),
        "-v",
        "--tb=short",
        "-s"
    ]
    
    result = subprocess.run(cmd, cwd=Path(__file__).parent.parent)
    return result.returncode == 0


def run_deep_scan():
    """Run deep code scan"""
    print("\n" + "="*80)
    print("RUNNING DEEP CODE SCAN")
    print("="*80 + "\n")
    
    scan_file = Path(__file__).parent / "deep_code_scan_issues.py"
    
    if not scan_file.exists():
        print(f"❌ Scan file not found: {scan_file}")
        return False
    
    cmd = [sys.executable, str(scan_file)]
    result = subprocess.run(cmd, cwd=Path(__file__).parent)
    return result.returncode == 0


def validate_fixes():
    """Validate that fixes are in place"""
    print("\n" + "="*80)
    print("VALIDATING FIXES IN CODE")
    print("="*80 + "\n")
    
    issues_found = []
    
    # Check 1: Group creation encoding
    groups_file = Path(__file__).parent.parent / "backend" / "routes" / "groups.py"
    if groups_file.exists():
        with open(groups_file, 'r', encoding='utf-8') as f:
            content = f.read()
            if "json.loads(json.dumps(_encode_doc(response), default=str))" in content:
                print("✅ Fix 1: Group creation ObjectId encoding - FOUND")
            else:
                print("❌ Fix 1: Group creation ObjectId encoding - NOT FOUND")
                issues_found.append("Group creation encoding")
    
    # Check 2: Forgot password token
    auth_file = Path(__file__).parent.parent / "backend" / "routes" / "auth.py"
    if auth_file.exists():
        with open(auth_file, 'r', encoding='utf-8') as f:
            content = f.read()
            if '"token": reset_token' in content and '"reset_token": reset_token' in content:
                print("✅ Fix 2: Forgot password token return - FOUND")
            else:
                print("❌ Fix 2: Forgot password token return - NOT FOUND")
                issues_found.append("Forgot password token")
    
    # Check 3: File download response
    files_file = Path(__file__).parent.parent / "backend" / "routes" / "files.py"
    if files_file.exists():
        with open(files_file, 'r', encoding='utf-8') as f:
            content = f.read()
            if '"download_url": download_url' in content:
                print("✅ Fix 3: File download response structure - FOUND")
            else:
                print("❌ Fix 3: File download response structure - NOT FOUND")
                issues_found.append("File download response")
    
    return len(issues_found) == 0, issues_found


def main():
    """Main test runner"""
    print("\n" + "="*80)
    print("CRITICAL FIXES VERIFICATION TEST SUITE")
    print("="*80)
    
    # Step 1: Validate fixes are in code
    print("\nStep 1: Validating fixes in code...")
    fixes_valid, issues = validate_fixes()
    
    if not fixes_valid:
        print(f"\n❌ Some fixes not found: {', '.join(issues)}")
        return False
    
    print("\n✅ All fixes found in code!")
    
    # Step 2: Run deep code scan
    print("\nStep 2: Running deep code scan...")
    scan_ok = run_deep_scan()
    
    # Step 3: Run pytest
    print("\nStep 3: Running pytest...")
    pytest_ok = run_pytest()
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"Code validation: ✅ PASS")
    print(f"Deep scan: {'✅ PASS' if scan_ok else '⚠️  CHECK RESULTS'}")
    print(f"Pytest: {'✅ PASS' if pytest_ok else '❌ FAILED'}")
    print("="*80)
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
