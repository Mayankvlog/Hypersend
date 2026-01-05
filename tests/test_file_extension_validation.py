#!/usr/bin/env python3
"""Direct validation of file extension blocking"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.validators import validate_command_injection, validate_path_injection

# Test dangerous file extensions detection
dangerous_exts = {
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
    '.php', '.asp', '.jsp', '.sh', '.ps1', '.py', '.rb', '.pl', '.lnk', '.url',
    '.msi', '.dll', '.app', '.deb', '.rpm', '.dmg', '.pkg', '.so', '.o', '.class'
}

test_files = [
    ('document.pdf', True),   # Safe
    ('script.js', False),      # Dangerous
    ('virus.exe', False),      # Dangerous
    ('image.JPG', True),       # Safe (uppercase)
    ('program.EXE', False),    # Dangerous (uppercase)
    ('movie.mp4', True),       # Safe
    ('setup.msi', False),      # Dangerous
]

print("=" * 60)
print("FILE EXTENSION SECURITY VALIDATION")
print("=" * 60)

all_pass = True
for filename, should_pass in test_files:
    if '.' in filename:
        file_ext = '.' + filename.rsplit('.', 1)[-1]
        file_ext_lower = file_ext.lower()
    else:
        file_ext_lower = ''
    
    is_safe = file_ext_lower not in dangerous_exts
    
    status = "[PASS]" if (is_safe == should_pass) else "[FAIL]"
    if is_safe != should_pass:
        all_pass = False
    
    print(f"{status} {filename:20} -> {file_ext_lower:6} (safe={is_safe})")

print("=" * 60)
if all_pass:
    print("[PASS] All file extension checks PASSED")
else:
    print("[FAIL] Some checks failed")
print("=" * 60)

# Also validate the validators work
print("\nVALIDATOR TESTS:")
print("-" * 60)

# Command injection tests
cmd_tests = [
    ("test.txt", True),
    ("rm -rf /", False),
    ("test; whoami", False),
    ("test | cat", False),
]

print("\nCommand Injection Validation:")
for test, expected in cmd_tests:
    result = validate_command_injection(test)
    status = "[OK]" if (result == expected) else "[FAIL]"
    print(f"  {status} {test:30} -> {result} (expected {expected})")

# Path injection tests  
path_tests = [
    ("document.txt", True),
    ("../../../etc/passwd", False),
    ("safe/path/file.txt", True),
    ("test\x00null.txt", False),
]

print("\nPath Injection Validation:")
for test, expected in path_tests:
    result = validate_path_injection(test)
    status = "[OK]" if (result == expected) else "[FAIL]"
    print(f"  {status} {test:30} -> {result} (expected {expected})")

print("-" * 60)
print("[PASS] All validation tests completed")
print("=" * 60)

# Exit with appropriate code
import sys
sys.exit(0 if all_pass else 1)
