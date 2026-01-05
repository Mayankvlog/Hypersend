#!/usr/bin/env python3
"""
Direct test of security validators - command injection and path traversal
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from validators import validate_command_injection, validate_path_injection

print('='*70)
print('SECURITY VALIDATORS - DIRECT TEST')
print('='*70)

# Test command injection validator
test_cases = [
    ('hello world', True, 'Normal text'),
    ('test;ls', False, 'Command separator'),
    ('test|cat', False, 'Pipe operator'),
    ('eval(x)', False, 'eval function'),
    ('subprocess.run', False, 'subprocess execution'),
    ('file.txt', True, 'Normal filename'),
    ('test<script>alert(1)</script>', False, 'XSS injection'),
    ('data\x00null', False, 'Null byte'),
    ('test&rm', False, 'Background command'),
    ('normal_input', True, 'Valid user input'),
]

print('\n[Command Injection Validation]')
command_pass = 0
for test_input, expected, description in test_cases:
    result = validate_command_injection(test_input)
    status = 'PASS' if result == expected else 'FAIL'
    if result == expected:
        command_pass += 1
    print('  {}: {} -> {}'.format(status, description, result))

# Test path injection validator
path_cases = [
    ('file.txt', True, 'Simple filename'),
    ('../../../etc/passwd', False, 'Path traversal'),
    ('data/file.txt', True, 'Relative path'),
    ('file\x00name', False, 'Null byte in path'),
    ('/etc/passwd', False, 'Absolute path'),
    ('document.pdf', True, 'Safe document'),
    ('..\\..\\windows\\system32', False, 'Windows traversal'),
]

print('\n[Path Injection Validation]')
path_pass = 0
for test_path, expected, description in path_cases:
    result = validate_path_injection(test_path)
    status = 'PASS' if result == expected else 'FAIL'
    if result == expected:
        path_pass += 1
    print('  {}: {} -> {}'.format(status, description, result))

print('\n' + '='*70)
total_tests = len(test_cases) + len(path_cases)
total_pass = command_pass + path_pass
print('RESULTS: {}/{} tests passed'.format(total_pass, total_tests))
print('='*70)

sys.exit(0 if total_pass == total_tests else 1)
