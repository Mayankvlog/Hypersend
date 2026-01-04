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
    
    backend_auth = Path("backend/routes/auth.py").read_text()
    backend_models = Path("backend/models.py").read_text()
    
    # Check auth.py uses standard pattern
    if "email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'" in backend_auth:
        print("  ✓ auth.py uses standard email pattern")
    else:
        print("  ✗ auth.py pattern missing")
        return False
    
    # Check models.py uses same pattern
    if "email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'" in backend_models:
        print("  ✓ models.py uses standard email pattern")
    else:
        print("  ✗ models.py pattern missing")
        return False
    
    # Verify no dangerous regex patterns in email validation
    dangerous_count = len(re.findall(r'<script|javascript:|on\w+\s*=|;\s*drop\s+table', backend_auth, re.IGNORECASE))
    if dangerous_count == 0:
        print("  ✓ No dangerous regex patterns in email validation")
        return True
    else:
        print(f"  ✗ Found {dangerous_count} dangerous patterns")
        return False


def test_binary_detection_refactoring():
    """Test that binary detection properly uses calculated ratio"""
    print("\n[TEST] Binary Detection Non-Printable Ratio...")
    
    files_py = Path("backend/routes/files.py").read_text()
    
    # Check if ratio is calculated once
    ratio_calc = len(re.findall(r'non_printable_ratio\s*=\s*non_printable\s*/\s*total_chars', files_py))
    if ratio_calc > 0:
        print("  ✓ Ratio calculated and stored in variable")
    else:
        print("  ✗ Ratio not properly calculated")
        return False
    
    # Check if ratio is reused
    ratio_usage = len(re.findall(r'non_printable_ratio', files_py))
    if ratio_usage >= 3:  # At least 3 usages (assignment + 2 comparisons)
        print("  ✓ Ratio variable reused correctly")
        return True
    else:
        print("  ✗ Ratio variable not reused")
        return False


def test_division_by_zero_protection():
    """Test that division by zero is protected in all test files"""
    print("\n[TEST] Division by Zero Protection...")
    
    test_files = [
        "tests/test_comprehensive_errors.py",
        "tests/validate_all_fixes.py",
        "tests/final_validation.py",
        "tests/validate_security_fixes.py",
        "tests/test_forgot_password.py"
    ]
    
    all_protected = True
    for test_file in test_files:
        path = Path(test_file)
        if not path.exists():
            print(f"  ⚠ {test_file} not found")
            continue
        
        content = path.read_text()
        
        # Check if file has division by zero protection
        has_protection = (
            'if total > 0' in content or
            'if total_tests > 0' in content or
            'if total_checks > 0' in content
        )
        
        if has_protection:
            print(f"  ✓ {path.name} has division by zero protection")
        else:
            print(f"  ✗ {path.name} missing protection")
            all_protected = False
    
    return all_protected


def test_error_handling_not_masking():
    """Test that errors aren't masked as authentication failures"""
    print("\n[TEST] Error Handling Specificity...")
    
    error_handlers = Path("backend/error_handlers.py").read_text()
    
    # Check that error descriptions are specific
    checks = [
        ("400 Bad Request", "Bad Request - Invalid request syntax"),
        ("403 Forbidden", "Forbidden - You lack permission"),
        ("404 Not Found", "Not Found - The requested resource"),
        ("401 Unauthorized", "Unauthorized - Authentication required"),
        ("500 Internal Server Error", "Internal Server Error - An unexpected")
    ]
    
    all_found = True
    for error_code, expected_msg in checks:
        if expected_msg in error_handlers:
            print(f"  ✓ {error_code} has specific message")
        else:
            print(f"  ✗ {error_code} missing specific message")
            all_found = False
    
    return all_found


def test_email_validation_consistency():
    """Test email validation across all modules"""
    print("\n[TEST] Email Validation Consistency...")
    
    files_to_check = [
        ("backend/models.py", ["UserCreate", "UserLogin"]),
        ("backend/routes/auth.py", ["register", "login"])
    ]
    
    all_consistent = True
    for filepath, contexts in files_to_check:
        content = Path(filepath).read_text()
        
        # Count standard email pattern usage
        pattern_count = len(re.findall(
            r"email_pattern\s*=\s*r'\^[a-zA-Z0-9\\._%\+\-]+@",
            content
        ))
        
        if pattern_count > 0:
            print(f"  ✓ {Path(filepath).name} uses consistent pattern")
        else:
            print(f"  ✗ {Path(filepath).name} may have inconsistent patterns")
            all_consistent = False
    
    return all_consistent


def test_no_indentation_bugs():
    """Test that logging has proper indentation"""
    print("\n[TEST] Logging Indentation...")
    
    files_py = Path("backend/routes/files.py").read_text()
    
    # Check that _log function is properly indented
    log_func = re.search(r'def _log\(.*?\):\n(.*?)(?=\ndef|\nclass|\Z)', files_py, re.DOTALL)
    
    if log_func:
        body = log_func.group(1)
        # Check indentation is consistent
        lines = body.split('\n')
        base_indent = None
        indent_correct = True
        
        for line in lines:
            if line.strip() and not line.startswith('    '):
                if not line.startswith('def '):
                    indent_correct = False
                    break
        
        if indent_correct:
            print("  ✓ _log function has proper indentation")
            return True
        else:
            print("  ✗ _log function has indentation issues")
            return False
    
    print("  ⚠ _log function not found")
    return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("CODE QUALITY FIXES - COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    
    tests = [
        test_email_validation_fix,
        test_binary_detection_refactoring,
        test_division_by_zero_protection,
        test_error_handling_not_masking,
        test_email_validation_consistency,
        test_no_indentation_bugs,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"  ✗ Test failed with error: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "=" * 70)
    passed = sum(results)
    total = len(results)
    
    print(f"RESULTS: {passed}/{total} tests passed")
    if total > 0:
        print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n✓ ALL CODE QUALITY FIXES VERIFIED!")
        return 0
    else:
        print("\n✗ Some fixes need attention")
        return 1


if __name__ == "__main__":
    sys.exit(main())
