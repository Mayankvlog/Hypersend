#!/usr/bin/env python3
"""
Check if the provided hash matches using different algorithms
"""
import hashlib

password = 'Mayank@#03'
provided_hash = 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'

# Try SHA256
sha256_hash = hashlib.sha256(password.encode()).hexdigest()
print(f"SHA256: {sha256_hash}")
print(f"Match: {sha256_hash == provided_hash}")

# Try MD5 (unlikely but check)
md5_hash = hashlib.md5(password.encode()).hexdigest()
print(f"\nMD5: {md5_hash}")
print(f"Match: {md5_hash == provided_hash}")

# Try the salt from the test
salt = 'e3b0c44298fc1c149afbf4c8996fb924'
import hashlib
pbkdf2_hash = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode('utf-8'),
    salt.encode('utf-8'),
    100000
)
pbkdf2_hex = pbkdf2_hash.hex()
print(f"\nPBKDF2 with test salt: {pbkdf2_hex}")
print(f"Match: {pbkdf2_hex == provided_hash}")
