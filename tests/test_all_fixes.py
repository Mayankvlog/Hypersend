#!/usr/bin/env python3
"""
Test all critical security fixes are working properly
"""

import subprocess
import sys
from pathlib import Path

def test_syntax_all():
    """Test syntax compilation of critical files"""
    backend_dir = Path(__file__).parent.parent / "backend"
    critical_files = [
        "auth/utils.py",
        "config.py",
        "main.py",
        "error_handlers.py",
        "validators.py",
        "rate_limiter.py"
    ]
    
    all_good = True
    for file in critical_files:
        try:
            result = subprocess.run([
                sys.executable, "-m", "py_compile", str(backend_dir / file)
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[OK] {file}: Compiles successfully")
            else:
                print(f"[FAIL] {file}: Compilation error")
                print(f"Error: {result.stderr}")
                all_good = False
        except Exception as e:
            print(f"[ERROR] {file}: {e}")
            all_good = False
    
    assert all_good, "Some critical files have syntax errors"

def test_critical_imports():
    """Test critical security functions can be imported"""
    try:
        # Test validators with absolute import
        from backend.validators import validate_command_injection, validate_path_injection
        print("[OK] Security validators import successfully")
        
        # Test security with absolute import
        from backend.security import SecurityConfig
        print("[OK] Security config imports successfully")
        
        # Test rate limiter with absolute import
        from backend.rate_limiter import RateLimiter
        print("[OK] Rate limiter imports successfully")
        
        assert True, "Critical imports failed"
    except Exception as e:
        print(f"[FAIL] Import error: {e}")
        assert False, "Critical imports failed"

def test_security_functions():
    """Test security functions work correctly"""
    try:
        # Use absolute imports
        from backend.validators import validate_command_injection, validate_path_injection
        
        # Test command injection validation
        dangerous_inputs = [
            "; rm -rf /",
            "$(whoami)", 
            "`cat /etc/passwd`",
            "eval('malicious code')",
            "system('ls -la')"
        ]
        
        all_blocked = True
        for dangerous in dangerous_inputs:
            if not validate_command_injection(dangerous):
                print(f"[OK] Command injection properly blocked: {dangerous}")
            else:
                print(f"[FAIL] Command injection not blocked: {dangerous}")
                all_blocked = False
        
        # Test path traversal validation
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "/etc/shadow",
            "normal/../dangerous"
        ]
        
        safe_paths = [
            "normal_file.txt",
            "document.pdf",
            "image.jpg",
            "allowed_relative/file.txt"  # This should be safe
        ]
        
        paths_blocked_correctly = all(
            not validate_path_injection(path) for path in dangerous_paths
        )
        
        paths_allowed_correctly = all(
            validate_path_injection(path) for path in safe_paths
        )
        
        if paths_blocked_correctly:
            print("[OK] Path traversal properly blocks dangerous paths")
        else:
            print("[FAIL] Path traversal allows dangerous paths")
        
        if paths_allowed_correctly:
            print("[OK] Path traversal allows safe paths")
        else:
            print("[FAIL] Path traversal blocks safe paths")
        
        assert all_blocked and paths_blocked_correctly and paths_allowed_correctly, "Security functions failed"
        
    except Exception as e:
        print(f"[FAIL] Security function test error: {e}")
        assert False, "Security functions failed"

def main():
    """Main test function"""
    print("TESTING ALL SECURITY FIXES")
    print("=" * 40)
    
    # Test 1: Syntax compilation
    print("\n1. Testing syntax compilation...")
    syntax_ok = test_syntax_all()
    
    # Test 2: Critical imports
    print("\n2. Testing critical imports...")
    imports_ok = test_critical_imports()
    
    # Test 3: Security functions
    print("\n3. Testing security functions...")
    functions_ok = test_security_functions()
    
    # Final result
    print("\n" + "=" * 40)
    print("FINAL RESULTS")
    print("=" * 40)
    
    if syntax_ok and imports_ok and functions_ok:
        print("SUCCESS: All security fixes are working!")
        return True
    else:
        print("FAILED: Some security fixes have issues!")
        print(f"Syntax: {'OK' if syntax_ok else 'FAIL'}")
        print(f"Imports: {'OK' if imports_ok else 'FAIL'}")
        print(f"Functions: {'OK' if functions_ok else 'FAIL'}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)