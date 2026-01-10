#!/usr/bin/env python3
"""
Comprehensive debug script to understand password storage and verification
"""
import sys
import os
import hashlib
import hmac
import secrets
from typing import Tuple

def pbkdf2_verify(password: str, salt: str, stored_hash: str) -> bool:
    """PBKDF2-HMAC-SHA256 verification"""
    try:
        password_bytes = password.encode('utf-8')
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt.encode('utf-8'),
            100000
        )
        computed_hex = password_hash.hex()
        return hmac.compare_digest(computed_hex, stored_hash)
    except Exception as e:
        print(f"PBKDF2 error: {e}")
        return False

def sha256_verify(password: str, stored_hash: str) -> bool:
    """Legacy SHA256 verification"""
    try:
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(legacy_hash, stored_hash)
    except Exception as e:
        print(f"SHA256 error: {e}")
        return False

password = 'Mayank@#03'

print("=== Password Analysis ===\n")
print(f"Password: {password}\n")

# Method 1: SHA256 (legacy)
sha256_hash = hashlib.sha256(password.encode()).hexdigest()
print(f"1. SHA256 hash: {sha256_hash}")
print(f"   Length: {len(sha256_hash)}")

# Method 2: PBKDF2 with a known salt (from test_correct_format.py)
test_salt = 'e3b0c44298fc1c149afbf4c8996fb924'
pbkdf2_test = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode('utf-8'),
    test_salt.encode('utf-8'),
    100000
).hex()
print(f"\n2. PBKDF2 with test salt ({test_salt}):")
print(f"   Hash: {pbkdf2_test}")
print(f"   Length: {len(pbkdf2_test)}")

# Method 3: PBKDF2 with a fresh salt
fresh_salt = secrets.token_hex(16)
pbkdf2_fresh = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode('utf-8'),
    fresh_salt.encode('utf-8'),
    100000
).hex()
print(f"\n3. PBKDF2 with fresh salt ({fresh_salt}):")
print(f"   Hash: {pbkdf2_fresh}")
print(f"   Length: {len(pbkdf2_fresh)}")

# Method 4: Try to match the test file's hash
test_hash = 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
print(f"\n4. Test file hash: {test_hash}")
print(f"   SHA256 match: {sha256_hash == test_hash}")
print(f"   PBKDF2 (test salt) match: {pbkdf2_test == test_hash}")

# Method 5: Test verification methods
print(f"\n5. Verification tests:")
print(f"   SHA256 verification: {sha256_verify(password, sha256_hash)}")
print(f"   PBKDF2 (fresh salt) verification: {pbkdf2_verify(password, fresh_salt, pbkdf2_fresh)}")
print(f"   PBKDF2 (test salt) verification: {pbkdf2_verify(password, test_salt, pbkdf2_test)}")

# Method 6: What should be stored in the database
print(f"\n6. Database storage formats:")
combined_format = f"{fresh_salt}${pbkdf2_fresh}"
print(f"   Combined (salt$hash): {combined_format[:50]}...")
print(f"   Length: {len(combined_format)}")
print(f"   Salt (separate): {fresh_salt}")
print(f"   Hash (separate): {pbkdf2_fresh}")
