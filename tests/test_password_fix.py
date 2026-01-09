#!/usr/bin/env python3
"""
Test password verification fix
"""

from backend.auth.utils import verify_password, hash_password

# Test the exact scenario from the logs
password = 'Mayank@#03'
combined_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855$a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'

print('Testing password verification...')
print(f'Password: {password}')
print(f'Combined hash: {combined_hash}')
print(f'Length: {len(combined_hash)}')

# Test with combined format (salt=None)
result1 = verify_password(password, combined_hash)
print(f'Combined format result: {result1}')

# Test separated format
if '$' in combined_hash:
    salt, hash_part = combined_hash.split('$')
    result2 = verify_password(password, hash_part, salt)
    print(f'Separated format result: {result2}')
    print(f'Salt: {salt}')
    print(f'Hash: {hash_part}')

# Test with a fresh password hash
fresh_hash, fresh_salt = hash_password(password)
fresh_combined = f"{fresh_salt}${fresh_hash}"
result3 = verify_password(password, fresh_combined)
print(f'Fresh combined format result: {result3}')

print('\nAll tests completed!')
