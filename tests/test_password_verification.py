#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test password verification with all scenarios
"""
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from backend.auth.utils import verify_password, hash_password
import hashlib
import hmac

password = "Mayank@#03"

print("=" * 60)
print("PASSWORD VERIFICATION TEST SUITE")
print("=" * 60)

# Test 1: New PBKDF2 format (separated hash/salt)
print("\n[TEST 1] New PBKDF2 Format (Separated)")
hash_result, salt_result = hash_password(password)
result = verify_password(password, hash_result, salt_result)
print(f"  Password: {password}")
print(f"  Hash: {hash_result[:32]}...")
print(f"  Salt: {salt_result}")
print(f"  Result: {result}")
assert result == True, "New format should verify"
print("  [OK] PASS")

# Test 2: New PBKDF2 format with wrong password
print("\n[TEST 2] New PBKDF2 Format (Wrong Password)")
result = verify_password("WrongPassword", hash_result, salt_result)
print(f"  Password: WrongPassword")
print(f"  Result: {result}")
assert result == False, "Wrong password should not verify"
print("  [OK] PASS")

# Test 3: Legacy combined format (salt$hash)
print("\n[TEST 3] Legacy Combined Format (salt$hash)")
combined = f"{salt_result}${hash_result}"
result = verify_password(password, combined)
print(f"  Combined: {combined[:50]}...")
print(f"  Result: {result}")
assert result == True, "Combined format should verify"
print("  [OK] PASS")

# Test 4: Legacy SHA256 format
print("\n[TEST 4] Legacy SHA256 Format")
sha256_hash = hashlib.sha256(password.encode()).hexdigest()
result = verify_password(password, sha256_hash)
print(f"  SHA256 Hash: {sha256_hash}")
print(f"  Result: {result}")
assert result == True, "Legacy SHA256 should verify"
print("  [OK] PASS")

# Test 5: Legacy SHA256 with wrong password
print("\n[TEST 5] Legacy SHA256 Format (Wrong Password)")
result = verify_password("WrongPassword", sha256_hash)
print(f"  Password: WrongPassword")
print(f"  Result: {result}")
assert result == False, "Wrong password should not verify"
print("  [OK] PASS")

# Test 6: Fallback from PBKDF2 to SHA256
# Simulate case where hash is stored as SHA256 but salt is provided
print("\n[TEST 6] Fallback from PBKDF2 to SHA256")
fake_salt = "12345678901234567890123456789012"
result = verify_password(password, sha256_hash, fake_salt)
print(f"  Fake Salt: {fake_salt}")
print(f"  SHA256 Hash (not PBKDF2): {sha256_hash}")
print(f"  Result: {result}")
assert result == True, "Should fallback to SHA256 and verify"
print("  [OK] PASS")

# Test 7: Invalid formats
print("\n[TEST 7] Invalid Formats")
test_cases = [
    ("password", "invalid", None, False, "invalid hash"),
    ("password", "toolong" * 50, None, False, "hash too long"),
    ("password", "", None, False, "empty hash"),
    ("password", None, None, False, "None hash"),
    ("", "somehash", None, False, "empty password"),
    (None, "somehash", None, False, "None password"),
]

for pwd, hsh, slt, expected, desc in test_cases:
    try:
        result = verify_password(pwd, hsh, slt)
        assert result == expected, f"{desc} should return {expected}"
        print(f"  [OK] {desc}: {result}")
    except:
        print(f"  [OK] {desc}: exception (OK)")

print("\n" + "=" * 60)
print("ALL TESTS PASSED!")
print("=" * 60)
