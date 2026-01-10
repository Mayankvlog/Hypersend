#!/usr/bin/env python3
"""
Debug script to test password hashing and verification
"""
import hashlib
import hmac
import secrets
from typing import Tuple

def hash_password(password: str) -> Tuple[str, str]:
    """Hash a password using PBKDF2 with SHA-256"""
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string")
    
    if len(password) < 1 or len(password) > 128:
        raise ValueError("Password length must be between 1 and 128 characters")
    
    try:
        salt = secrets.token_hex(16)  # 16 bytes -> 32 hex chars
    except Exception as e:
        raise ValueError(f"Failed to generate cryptographically secure salt: {type(e).__name__}")
    
    if not salt or len(salt) != 32:
        raise ValueError("Invalid salt generation - critical security issue")
    
    try:
        password_bytes = password.encode('utf-8')
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt.encode('utf-8'),
            100000  # 100,000 iterations (NIST recommendation)
        )
        
        hash_hex = password_hash.hex()
        if not hash_hex or len(hash_hex) != 64:  # SHA256 produces 64 hex chars
            raise ValueError("Invalid hash generation")
        
        # Return separate hash and salt for database storage
        return hash_hex, salt
    except Exception as e:
        raise ValueError(f"Password hashing failed: {type(e).__name__}")


def verify_password(plain_password: str, hashed_password: str, salt: str = None) -> bool:
    """Verify a password against its PBKDF2 hash"""
    try:
        if not plain_password or not hashed_password:
            print(f"[DEBUG] Missing input: password={bool(plain_password)}, hash={bool(hashed_password)}")
            return False
        
        # Handle both new format (separate hash/salt) and legacy format (combined)
        if salt is None:
            # Legacy format: hash contains "salt$hash"
            if '$' in hashed_password:
                parts = hashed_password.split('$')
                if len(parts) != 2:
                    print(f"[DEBUG] Invalid hash format: expected 2 parts, got {len(parts)}")
                    return False
                
                salt, stored_hash = parts
                if not salt or not stored_hash:
                    print(f"[DEBUG] Empty salt or hash in combined format")
                    return False
                
                if len(salt) != 32:
                    print(f"[DEBUG] Invalid salt length: expected 32, got {len(salt)}")
                    return False
                
                try:
                    password_bytes = plain_password.encode('utf-8')
                    password_hash = hashlib.pbkdf2_hmac(
                        'sha256',
                        password_bytes,
                        salt.encode('utf-8'),
                        100000
                    )
                    computed_hex = password_hash.hex()
                    # SECURITY: Use constant-time comparison to prevent timing attacks
                    is_valid = hmac.compare_digest(computed_hex, stored_hash)
                    print(f"[DEBUG] Combined format: salt_len={len(salt)}, hash_len={len(stored_hash)}, computed_matches={is_valid}")
                    return is_valid
                except (ValueError, UnicodeEncodeError) as e:
                    print(f"[DEBUG] Password verification failed: {type(e).__name__}")
                    return False
            else:
                # Just a plain hash without salt - shouldn't happen with new code
                print(f"[DEBUG] Hash without dollar sign and no salt provided")
                return False
        else:
            # New format: separate hash and salt provided
            if len(plain_password) > 128:
                print(f"[DEBUG] Password exceeds maximum length")
                return False
            
            if len(hashed_password) > 256:
                print(f"[DEBUG] Hash exceeds maximum length")
                return False
            
            if len(salt) != 32:
                print(f"[DEBUG] Invalid salt length: expected 32, got {len(salt)}")
                return False
            
            try:
                password_bytes = plain_password.encode('utf-8')
                password_hash = hashlib.pbkdf2_hmac(
                    'sha256',
                    password_bytes,
                    salt.encode('utf-8'),
                    100000
                )
                computed_hex = password_hash.hex()
                # SECURITY: Use constant-time comparison to prevent timing attacks
                is_valid = hmac.compare_digest(computed_hex, hashed_password)
                print(f"[DEBUG] Separated format: salt_len={len(salt)}, hash_len={len(hashed_password)}, computed_matches={is_valid}")
                return is_valid
            except (ValueError, UnicodeEncodeError) as e:
                print(f"[DEBUG] Password verification failed: {type(e).__name__}")
                return False
            
    except Exception as e:
        print(f"[DEBUG] Password verification exception: {type(e).__name__}: {str(e)}")
        return False


if __name__ == "__main__":
    password = "Mayank@#03"
    
    print("=== Password Hash Testing ===\n")
    
    # Test 1: Hash generation
    print("Test 1: Hash password")
    hash_result, salt_result = hash_password(password)
    print(f"Generated hash: {hash_result}")
    print(f"Generated salt: {salt_result}")
    print(f"Hash length: {len(hash_result)}")
    print(f"Salt length: {len(salt_result)}")
    combined = f"{salt_result}${hash_result}"
    print(f"Combined format: {combined}")
    print(f"Combined length: {len(combined)}")
    
    # Test 2: Verify with separate salt/hash
    print("\n\nTest 2: Verify with separate salt/hash")
    result = verify_password(password, hash_result, salt_result)
    print(f"Result: {result}")
    
    # Test 3: Verify with combined format
    print("\n\nTest 3: Verify with combined format (salt$hash)")
    result = verify_password(password, combined)
    print(f"Result: {result}")
    
    # Test 4: Wrong password
    print("\n\nTest 4: Wrong password")
    result = verify_password("WrongPassword", combined)
    print(f"Result: {result}")
    
    # Test 5: The problematic case - what if the hash/salt were swapped?
    print("\n\nTest 5: Check if salt and hash were swapped")
    swapped = f"{hash_result}${salt_result}"  # hash$salt instead of salt$hash
    print(f"Swapped format: {swapped}")
    result = verify_password(password, swapped)
    print(f"Result with swapped: {result}")
    
    print("\n\n=== Tests Complete ===")
