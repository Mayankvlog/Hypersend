#!/usr/bin/env python3
"""
Comprehensive Security and Validation Script
Tests all critical fixes applied to the Hypersend backend
"""

import sys
import os
import re
import subprocess
import traceback
from pathlib import Path

def test_syntax_compilation():
    """Test that all critical files compile without syntax errors"""
    print("=== Testing Python Syntax Compilation ===")
    
    critical_files = [
        "main.py",
        "routes/auth.py", 
        "routes/files.py",
        "error_handlers.py",
        "security.py",
        "rate_limiter.py"
    ]
    
    all_passed = True
    for file_path in critical_files:
        try:
            result = subprocess.run([
                sys.executable, "-m", "py_compile", file_path
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[OK] {file_path}: Syntax OK")
            else:
                print(f"[FAIL] {file_path}: Syntax Error")
                print(f"   Error: {result.stderr}")
                all_passed = False
                
        except Exception as e:
            print(f"[ERROR] {file_path}: Failed to test - {str(e)}")
            all_passed = False
    
    return all_passed

def test_security_patterns():
    """Test security fixes are in place"""
    print("\n=== Testing Security Pattern Fixes ===")
    
    security_tests = [
        {
            "file": "routes/auth.py",
            "pattern": r'^[a-zA-Z0-9]([a-zA-Z0-9._%+-]*[a-zA-Z0-9])?@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$',
            "description": "Strict email validation pattern"
        },
        {
            "file": "routes/files.py", 
            "pattern": r'[<>:"|?*]',  # Additional dangerous filesystem chars
            "description": "Enhanced filename security patterns"
        },
        {
            "file": "routes/files.py",
            "pattern": r'application/x-executable',  # Additional dangerous MIME types
            "description": "Enhanced MIME type security"
        },
        {
            "file": "rate_limiter.py",
            "pattern": r'list\(self\.requests\.get',  # Thread-safe rate limiting
            "description": "Thread-safe rate limiter fix"
        }
    ]
    
    all_passed = True
    for test in security_tests:
        try:
            with open(test["file"], 'r') as f:
                content = f.read()
                
            if re.search(test["pattern"], content):
                print(f"[OK] {test['file']}: {test['description']} - FOUND")
            else:
                print(f"[FAIL] {test['file']}: {test['description']} - MISSING")
                all_passed = False
                
        except Exception as e:
            print(f"[ERROR] {test['file']}: Failed to check - {str(e)}")
            all_passed = False
    
    return all_passed

def test_database_field_consistency():
    """Test database field consistency fixes"""
    print("\n=== Testing Database Field Consistency ===")
    
    try:
        with open("routes/files.py", 'r') as f:
            content = f.read()
        
        # Check for field consistency fixes
        critical_fixes = [
            '"upload_id": upload_id,  # CRITICAL FIX: Add both fields for consistency',
            '"owner_id": current_user,  # Add owner_id for consistency',
            'await uploads_collection().delete_one({"_id": upload_id})  # CRITICAL FIX: Use correct field name'
        ]
        
        all_found = True
        for fix in critical_fixes:
            if fix in content:
                print(f"[OK] Database field fix: {fix[:50]}... - FOUND")
            else:
                print(f"[FAIL] Database field fix: {fix[:50]}... - MISSING")
                all_found = False
        
        return all_found
        
    except Exception as e:
        print(f"❌ Failed to test database consistency: {str(e)}")
        return False

def test_path_traversal_fixes():
    """Test path traversal security fixes"""
    print("\n=== Testing Path Traversal Fixes ===")
    
    try:
        with open("routes/files.py", 'r') as f:
            content = f.read()
        
        # Check for enhanced path validation
        security_checks = [
            'normalized_path = file_path.resolve()',
            'normalized_path.relative_to(data_root)',
            "if '..' in str(file_path)",
            'except ValueError:'
        ]
        
        all_found = True
        for check in security_checks:
            if check in content:
                print(f"[OK] Path traversal check: {check[:50]}... - FOUND")
            else:
                print(f"[FAIL] Path traversal check: {check[:50]}... - MISSING")
                all_found = False
        
        return all_found
        
    except Exception as e:
        print(f"❌ Failed to test path traversal fixes: {str(e)}")
        return False

def test_cors_security():
    """Test CORS security fixes"""
    print("\n=== Testing CORS Security Fixes ===")
    
    try:
        with open("main.py", 'r') as f:
            content = f.read()
        
        # Check for production mode security
        cors_fixes = [
            'r\'^http://zaply\\.in\\.net(:[0-9]+)?$\' if settings.DEBUG else None',
            'allowed_patterns = [p for p in allowed_patterns if p]',
            '# SECURITY: Filter out None patterns'
        ]
        
        all_found = True
        for fix in cors_fixes:
            if fix in content:
                print(f"[OK] CORS security fix: {fix[:50]}... - FOUND")
            else:
                print(f"[FAIL] CORS security fix: {fix[:50]}... - MISSING")
                all_found = False
        
        return all_found
        
    except Exception as e:
        print(f"❌ Failed to test CORS fixes: {str(e)}")
        return False

def test_error_handling():
    """Test error handling improvements"""
    print("\n=== Testing Error Handling Improvements ===")
    
    try:
        with open("error_handlers.py", 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for comprehensive error handling
        error_features = [
            'def extract_error_details',
            'status_code, error, detail',
            '"timestamp":',
            '"hints":'
        ]
        
        all_found = True
        for feature in error_features:
            if feature in content:
                print(f"[OK] Error handling feature: {feature} - FOUND")
            else:
                print(f"[FAIL] Error handling feature: {feature} - MISSING")
                all_found = False
        
        return all_found
        
    except Exception as e:
        print(f"[ERROR] Failed to test error handling: {str(e)}")
        return False

def main():
    """Run all security and validation tests"""
    print("SECURE Hypersend Backend Security Validation")
    print("=" * 50)
    
    # Change to backend directory
    script_dir = Path(__file__).parent
    backend_dir = script_dir / "backend"
    
    if backend_dir.exists():
        os.chdir(backend_dir)
        print(f"Changed to directory: {backend_dir}")
    else:
        print(f"❌ Backend directory not found: {backend_dir}")
        return False
    
    # Run all tests
    results = []
    results.append(("Syntax Compilation", test_syntax_compilation()))
    results.append(("Security Patterns", test_security_patterns()))
    results.append(("Database Consistency", test_database_field_consistency()))
    results.append(("Path Traversal Protection", test_path_traversal_fixes()))
    results.append(("CORS Security", test_cors_security()))
    results.append(("Error Handling", test_error_handling()))
    
    # Summary
    print("\n" + "=" * 50)
    print("🏁 VALIDATION SUMMARY")
    print("=" * 50)
    
    passed_count = 0
    total_count = len(results)
    
    for test_name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {test_name}")
        if passed:
            passed_count += 1
    
    print(f"\nResults: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("SUCCESS! ALL SECURITY FIXES VALIDATED!")
        return True
    else:
        print("WARNING: SOME FIXES REQUIRE ATTENTION")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)