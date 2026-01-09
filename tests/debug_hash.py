#!/usr/bin/env python3
"""
Debug script to test password hashing
"""

import hashlib
import secrets

def hash_password(password: str):
    """Hash a password using PBKDF2 with SHA-256 and cryptographically secure salt"""
    
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string")
    
    if len(password) < 1 or len(password) > 128:
        raise ValueError("Password length must be between 1 and 128 characters")
    
    # CRITICAL FIX: Use secrets.token_hex for cryptographically secure salt
    # Generate 32 hex characters (16 bytes of random data)
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
        
        # CRITICAL FIX: Return combined format for tests AND separate salt for database
        combined = f"{salt}${hash_hex}"
        return combined  # Return just the combined string for tests
    except Exception as e:
        raise ValueError(f"Password hashing failed: {type(e).__name__}")

def verify_password(password: str, combined: str):
    """Verify a password against a stored hash"""
    
    if not password or not isinstance(password, str):
        return False
    
    if not combined or not isinstance(combined, str):
        return False
    
    try:
        if '$' not in combined:
            # Handle legacy hash format (64 hex chars)
            if len(combined) == 64 and all(c in '0123456789abcdefABCDEF' for c in combined):
                # Legacy SHA256 hash without salt
                password_bytes = password.encode('utf-8')
                legacy_hash = hashlib.sha256(password_bytes).hexdigest()
                return legacy_hash == combined
            else:
                return False
            
        parts = combined.split('$')
        if len(parts) != 2:
            return False
            
        salt, stored_hash = parts
        if len(salt) != 32 or len(stored_hash) != 64:
            return False
        
        password_bytes = password.encode('utf-8')
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt.encode('utf-8'),
            100000  # 100,000 iterations (NIST recommendation)
        )
        
        return password_hash.hex() == stored_hash
    except Exception as e:
        raise ValueError(f"Password verification failed: {type(e).__name__}")

def test():
    password = "TestPassword123!"
    
    print("=== Testing hash_password function ===")
    
    # Test 1: Basic functionality
    try:
        combined, salt = hash_password(password)
        print(f"✅ Hash generated successfully")
        print(f"   Salt: {salt} (length: {len(salt)})")
        print(f"   Hash: {combined.split('$')[1] if '$' in combined else combined} (length: {len(combined.split('$')[1]) if '$' in combined else len(combined)})")
        print(f"   Combined: {combined} (length: {len(combined)})")
        print(f"   Expected length: 97 (32 + 1 + 64)")
        
        # Test 2: Consistency
        combined2, salt2 = hash_password(password)
        print(f"✅ Second hash: {combined2}")
        print(f"   Hashes different: {combined != combined2}")
        
        # Test 3: Verify format
        if '$' in combined and len(combined) == 97:
            print("✅ Format is correct: salt$hash")
        else:
            print(f"❌ Format is wrong: no $ or wrong length")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test()
