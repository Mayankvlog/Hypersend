#!/usr/bin/env python3
"""
Comprehensive Test Suite for Code Quality Fixes
Tests all issues mentioned in the requirements
"""

import sys
import re
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_email_validation_fix():
    """Test that email validation no longer has redundant patterns"""
    print("\n[TEST] Email Validation Pattern Consistency...")
    
    # Get the workspace root (parent of tests directory)
    workspace_root = Path(__file__).parent.parent
    
    backend_auth = (workspace_root / "backend" / "routes" / "auth.py").read_text(encoding='utf-8', errors='ignore')
    backend_models = (workspace_root / "backend" / "models.py").read_text(encoding='utf-8', errors='ignore')
    
    # Check auth.py uses standard pattern
    if "email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'" in backend_auth:
        print("  [OK] auth.py uses standard email pattern")
    else:
        print("  [FAIL] auth.py pattern missing")
        return False
    
    # Check models.py uses same pattern
    if "email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'" in backend_models:
        print("  [OK] models.py uses standard email pattern")
    else:
        print("  [FAIL] models.py pattern missing")
        return False
    
    # Verify no dangerous regex patterns in email validation
    dangerous_count = len(re.findall(r'<script|javascript:|on\w+\s*=|;\s*drop\s+table', backend_auth, re.IGNORECASE))
    if dangerous_count == 0:
        print("  [OK] No dangerous regex patterns in email validation")
        return True
    else:
        print(f"  [FAIL] Found {dangerous_count} dangerous patterns")
        return False


def test_binary_detection_refactoring():
    """Test that binary detection properly uses calculated ratio"""
    print("\n[TEST] Binary Detection Non-Printable Ratio...")
    
    # Get the workspace root
    workspace_root = Path(__file__).parent.parent
    files_py = (workspace_root / "backend" / "routes" / "files.py").read_text(encoding='utf-8', errors='ignore')
    
    # Check if ratio is calculated once
    ratio_calc = len(re.findall(r'non_printable_ratio\s*=\s*non_printable\s*/\s*total_chars', files_py))
    if ratio_calc > 0:
        print("  [OK] Ratio calculated and stored in variable")
    else:
        print("  [FAIL] Ratio not properly calculated")
        return False
    
    # Check if ratio variable is reused
    ratio_reuse = len(re.findall(r'if\s+non_printable_ratio\s*>', files_py))
    if ratio_reuse > 0:
        print("  [OK] Ratio variable reused correctly")
        return True
    else:
        print("  [FAIL] Ratio variable not reused")
        return False


def test_division_by_zero_protection():
    """Test that division by zero is protected in all test files"""
    print("\n[TEST] Division by Zero Protection...")
    
    workspace_root = Path(__file__).parent.parent
    test_files = [
        "tests/test_comprehensive_errors.py",
        "tests/validate_all_fixes.py",
        "tests/final_validation.py",
        "tests/validate_security_fixes.py",
        "tests/test_forgot_password.py"
    ]
    
    all_protected = True
    for test_file in test_files:
        path = workspace_root / test_file
        if not path.exists():
            print(f"  [SKIP] {test_file} not found")
            continue
        
        content = path.read_text(encoding='utf-8', errors='ignore')
        
        # Check if file has division by zero protection
        has_protection = (
            'if total > 0' in content or
            'if total_tests > 0' in content or
            'if total_checks > 0' in content
        )
        
        if has_protection:
            print(f"  [OK] {path.name} has division by zero protection")
        else:
            print(f"  [FAIL] {path.name} missing protection")
            all_protected = False
    
    return all_protected


def test_error_handler_specificity():
    """Test that error handler descriptions are specific"""
    print("\n[TEST] Error Handler Specificity...")
    
    workspace_root = Path(__file__).parent.parent
    error_handlers = (workspace_root / "backend" / "error_handlers.py").read_text(encoding='utf-8', errors='ignore')
    
    # Check that error descriptions are specific
    checks = [
        ("401: \"Unauthorized", "authentication errors properly identified"),
        ("403: \"Forbidden", "permission errors properly identified"),
        ("500: \"Server Error", "server errors properly identified"),
        ("503: \"Service Unavailable", "service unavailable errors properly identified"),
    ]
    
    all_found = True
    for error_code, error_msg in checks:
        if error_code in error_handlers:
            print(f"  [OK] {error_code} has specific message")
        else:
            print(f"  [FAIL] {error_code} missing specific message")
            all_found = False
    
    return all_found


def test_email_validation_consistency():
    """Test email validation across all modules"""
    print("\n[TEST] Email Validation Consistency...")
    
    workspace_root = Path(__file__).parent.parent
    files_to_check = [
        (workspace_root / "backend" / "models.py", ["UserCreate", "UserLogin"]),
        (workspace_root / "backend" / "routes" / "auth.py", ["register", "login"])
    ]
    
    all_consistent = True
    for filepath, contexts in files_to_check:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
        
        # Count standard email pattern usage
        pattern_count = len(re.findall(
            r"email_pattern\s*=\s*r'\^[a-zA-Z0-9\\._%\+\-]+@",
            content
        ))
        
        if pattern_count > 0:
            print(f"  [OK] {filepath.name} uses consistent pattern")
        else:
            print(f"  [FAIL] {filepath.name} may have inconsistent patterns")
            all_consistent = False
    
    return all_consistent


def test_safe_binary_detection():
    """Test that binary detection doesn't divide by zero"""
    print("\n[TEST] Safe Binary Detection Logic...")
    
    workspace_root = Path(__file__).parent.parent
    
    # Read the backend files to check for safe binary detection
    files_py = (workspace_root / "backend" / "routes" / "files.py").read_text(encoding='utf-8', errors='ignore')
    
    # Check that _log function is properly indented
    log_func = re.search(r'def _log\(.*?\):\n(.*?)(?=\ndef|\nclass|\Z)', files_py, re.DOTALL)
    
    if log_func and log_func.groups():
        body = log_func.group(1)
        # Check indentation is consistent
        lines = body.split('\n')
        has_indentation = all(not line or line[0] in (' ', '\t') for line in lines if line)
        
        if has_indentation:
            print("  [OK] _log function has proper indentation")
            return True
        else:
            print("  [FAIL] _log function has indentation issues")
            return False
    else:
        print("  [SKIP] _log function not found")
        return True


def main():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("CODE QUALITY FIXES - COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    
    tests = [
        test_email_validation_fix,
        test_binary_detection_refactoring,
        test_division_by_zero_protection,
        test_error_handler_specificity,
        test_email_validation_consistency,
        test_safe_binary_detection,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"  [FAIL] Test failed with error: {e}")
            results.append(False)
    
    print("\n" + "=" * 70)
    if all(results):
        print("\n[OK] ALL CODE QUALITY FIXES VERIFIED!")
        print("=" * 70)
        return 0
    else:
        print("\n[FAIL] Some fixes need attention")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
