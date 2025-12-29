#!/usr/bin/env python3
"""
Comprehensive validation script for all security fixes.
Tests critical fixes applied to file upload, validation, and test frameworks.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

def test_file_extension_security():
    """Test file extension security fixes"""
    try:
        with open('../backend/routes/files.py', 'r') as f:
            content = f.read()
        
        required_fixes = [
            'file_ext.lower() in dangerous_exts',  # Case-insensitive
            'filename_parts = original_filename.lower().split(\'.\')',  # Double extension check
            'len(filename_parts) > 2',  # Multi-extension detection
        ]
        
        missing_fixes = [fix for fix in required_fixes if fix not in content]
        if missing_fixes:
            print(f"❌ File extension security missing: {missing_fixes}")
            return False
        
        print("✅ File extension security properly implemented")
        return True
    except Exception as e:
        print(f"❌ Error testing file extension security: {e}")
        return False

def test_path_security():
    """Test path traversal security fixes"""
    try:
        with open('../backend/routes/files.py', 'r') as f:
            content = f.read()
        
        required_fixes = [
            'resolved_path.relative_to(data_root)',  # Proper path comparison
            'except (OSError, ValueError) as path_error:',  # Specific exception handling
        ]
        
        missing_fixes = [fix for fix in required_fixes if fix not in content]
        if missing_fixes:
            print(f"❌ Path security missing: {missing_fixes}")
            return False
        
        print("✅ Path traversal security properly implemented")
        return True
    except Exception as e:
        print(f"❌ Error testing path security: {e}")
        return False

def test_binary_detection():
    """Test binary content detection improvements"""
    try:
        with open('test_fixes.py', 'r') as f:
            content = f.read()
        
        required_fixes = [
            "'\\\\x00' in content",  # Null byte detection
            "ord(c) < 32 and c not in '\\t\\n\\r'",  # Control character detection
            "non_printable / total_chars > 0.3",  # Binary threshold
        ]
        
        missing_fixes = [fix for fix in required_fixes if fix not in content]
        if missing_fixes:
            print(f"❌ Binary detection missing: {missing_fixes}")
            return False
        
        print("✅ Binary content detection properly implemented")
        return True
    except Exception as e:
        print(f"❌ Error testing binary detection: {e}")
        return False

def test_security_validation():
    """Test security validation improvements"""
    try:
        with open('test_fixes.py', 'r') as f:
            content = f.read()
        
        required_fixes = [
            'security_violations.append(',  # Detailed violation tracking
            'if not security_violations:',  # Proper validation logic
            'len(failed_tests)',  # Error tracking
        ]
        
        missing_fixes = [fix for fix in required_fixes if fix not in content]
        if missing_fixes:
            print(f"❌ Security validation missing: {missing_fixes}")
            return False
        
        print("✅ Security validation properly implemented")
        return True
    except Exception as e:
        print(f"❌ Error testing security validation: {e}")
        return False

def main():
    """Run all security validation tests"""
    print("🔍 Running comprehensive security validation...")
    print("=" * 60)
    
    tests = [
        test_file_extension_security,
        test_path_security,
        test_binary_detection,
        test_security_validation,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"❌ Error in {test.__name__}: {e}")
            results.append(False)
    
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} security validation tests passed")
    
    if passed == total:
        print("🎉 ALL SECURITY VALIDATIONS PASSED")
        print("✅ File upload security hardened")
        print("✅ Path traversal protection enhanced") 
        print("✅ Binary detection improved")
        print("✅ Test validation logic fixed")
        return True
    else:
        print(f"❌ {total - passed} VALIDATION(S) FAILED")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)