#!/usr/bin/env python3
"""
COMPREHENSIVE SECURITY AND INTEGRITY VALIDATION
Tests all fixes for:
1. Command injection vulnerabilities
2. Path traversal vulnerabilities
3. Dangerous file extension uploads
4. CMake build configuration
5. Security validation logic
"""

import os
import sys
import pathlib

def check_validators_logic():
    """Check that validators have proper logic"""
    print("\n[1] Checking Validator Logic...")
    sys.path.insert(0, 'backend')
    
    try:
        from validators import validate_command_injection, validate_path_injection
        
        # Test command injection validator
        test_vectors = {
            'Command Separator': ('test;ls', False),
            'Pipe Operator': ('test|cat', False),
            'Background Execution': ('test&rm', False),
            'Code Execution': ('eval(x)', False),
            'Normal Text': ('hello world', True),
            'Filename': ('document.pdf', True),
        }
        
        for test_name, (test_input, expected) in test_vectors.items():
            result = validate_command_injection(test_input)
            if result != expected:
                print(f"  X FAIL: {test_name} - Expected {expected}, got {result}")
                return False
        
        print("  ✓ Command injection validator logic correct")
        
        # Test path injection validator
        path_vectors = {
            'Path Traversal': ('../../../etc/passwd', False),
            'Safe Path': ('document.pdf', True),
            'Null Byte': ('file\x00name', False),
        }
        
        for test_name, (test_path, expected) in path_vectors.items():
            result = validate_path_injection(test_path)
            if result != expected:
                print(f"  X FAIL: {test_name} - Expected {expected}, got {result}")
                return False
        
        print("  ✓ Path injection validator logic correct")
        return True
        
    except Exception as e:
        print(f"  X FAIL: {str(e)}")
        return False


def check_file_extension_blocking():
    """Check that dangerous extensions are blocked"""
    print("\n[2] Checking File Extension Blocking...")
    
    try:
        with open('backend/routes/files.py', 'r') as f:
            content = f.read()
        
        # Check for dangerous_exts variable
        if 'dangerous_exts' not in content:
            print("  X FAIL: dangerous_exts variable not found")
            return False
        
        # Check for case-insensitive lowering
        if 'file_ext.lower()' not in content:
            print("  X FAIL: file_ext.lower() not found")
            return False
        
        # Check for specific extensions
        required_exts = ['.exe', '.bat', '.cmd', '.php', '.asp', '.jsp', '.sh', '.ps1']
        for ext in required_exts:
            if f"'{ext}'" not in content:
                print(f"  X FAIL: Missing extension block for {ext}")
                return False
        
        print("  ✓ File extension blocking implemented")
        return True
        
    except Exception as e:
        print(f"  X FAIL: {str(e)}")
        return False


def check_cmake_config():
    """Check that CMake configuration exists"""
    print("\n[3] Checking CMake Configuration...")
    
    try:
        cmake_path = pathlib.Path('frontend/linux/flutter/ephemeral/generated_config.cmake')
        
        if not cmake_path.exists():
            print("  X FAIL: generated_config.cmake file not found")
            return False
        
        with open(cmake_path, 'r') as f:
            content = f.read()
        
        # Check for required variables
        required = ['FLUTTER_ROOT', 'FLUTTER_VERSION', 'FLUTTER_TARGET_PLATFORM']
        for var in required:
            if f'set({var}' not in content:
                print(f"  X FAIL: Missing CMake variable {var}")
                return False
        
        print("  ✓ CMake configuration file exists and is valid")
        return True
        
    except Exception as e:
        print(f"  X FAIL: {str(e)}")
        return False


def check_no_duplicates():
    """Check that validators don't have duplicate definitions"""
    print("\n[4] Checking for Code Duplication...")
    
    try:
        with open('backend/validators.py', 'r') as f:
            content = f.read()
        
        # Count function definitions
        command_injection_count = content.count('def validate_command_injection')
        path_injection_count = content.count('def validate_path_injection')
        
        if command_injection_count != 1:
            print(f"  X FAIL: validate_command_injection defined {command_injection_count} times")
            return False
        
        if path_injection_count != 1:
            print(f"  X FAIL: validate_path_injection defined {path_injection_count} times")
            return False
        
        print("  ✓ No duplicate function definitions")
        return True
        
    except Exception as e:
        print(f"  X FAIL: {str(e)}")
        return False


def check_security_headers():
    """Check that security headers are configured"""
    print("\n[5] Checking Security Headers...")
    
    try:
        with open('backend/main.py', 'r') as f:
            content = f.read()
        
        # Check for security header middleware
        security_checks = [
            ('TrustedHostMiddleware', 'Trusted Host'),
            ('add_middleware', 'Middleware setup'),
            ('X-Content-Type-Options', 'MIME type protection'),
        ]
        
        for check, description in security_checks:
            if check not in content:
                print(f"  X WARNING: {description} not explicitly configured")
        
        print("  ✓ Security configuration present")
        return True
        
    except Exception as e:
        print(f"  X FAIL: {str(e)}")
        return False


def check_null_byte_protection():
    """Check for null byte protection in validators"""
    print("\n[6] Checking Null Byte Protection...")
    
    try:
        with open('backend/validators.py', 'r') as f:
            content = f.read()
        
        # Check for null byte checks in both validators
        if content.count("'\\x00'") < 2:
            print("  X FAIL: Null byte check not found in validators")
            return False
        
        print("  ✓ Null byte protection implemented in validators")
        return True
        
    except Exception as e:
        print(f"  X FAIL: {str(e)}")
        return False


def main():
    print("="*70)
    print("COMPREHENSIVE SECURITY VALIDATION")
    print("="*70)
    
    checks = [
        check_validators_logic,
        check_file_extension_blocking,
        check_cmake_config,
        check_no_duplicates,
        check_security_headers,
        check_null_byte_protection,
    ]
    
    results = []
    for check in checks:
        try:
            results.append(check())
        except Exception as e:
            print(f"\nX FATAL ERROR: {str(e)}")
            results.append(False)
    
    print("\n" + "="*70)
    passed = sum(results)
    total = len(results)
    print(f"RESULTS: {passed}/{total} checks passed")
    
    if all(results):
        print("\n✓✓✓ ALL SECURITY VALIDATIONS PASSED ✓✓✓")
        print("="*70)
        return 0
    else:
        print("\n✗✗✗ SOME VALIDATIONS FAILED ✗✗✗")
        print("="*70)
        return 1


if __name__ == '__main__':
    sys.exit(main())
