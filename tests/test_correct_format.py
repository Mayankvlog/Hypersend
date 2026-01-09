#!/usr/bin/env python3
"""
Test correct password format
"""

from backend.auth.utils import verify_password, hash_password

password = 'Mayank@#03'
hash_part = 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
salt = 'e3b0c44298fc1c149afbf4c8996fb924'  # 32 chars
combined = f'{salt}${hash_part}'

print(f'Correct format test:')
print(f'Salt (32 chars): {salt}')
print(f'Hash (64 chars): {hash_part}')
print(f'Combined: {combined}')
print(f'Length: {len(combined)}')

result = verify_password(password, combined)
print(f'Verification result: {result}')

# Test with fresh hash
fresh_hash, fresh_salt = hash_password(password)
fresh_combined = f'{fresh_salt}${fresh_hash}'
print(f'\nFresh hash test:')
print(f'Fresh salt: {fresh_salt}')
print(f'Fresh hash: {fresh_hash}')
print(f'Fresh combined: {fresh_combined}')
print(f'Fresh verification: {verify_password(password, fresh_combined)}')
