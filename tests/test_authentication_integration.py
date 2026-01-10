#!/usr/bin/env python3
"""
Comprehensive integration test for authentication fixes
Tests all password formats and scenarios
"""
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from backend.auth.utils import verify_password, hash_password
import hashlib

def run_scenario(scenario_name, test_func):
    """Helper to run a test scenario"""
    print(f"\n[SCENARIO: {scenario_name}]")
    try:
        test_func()
        print(f"[PASS] {scenario_name} - All checks passed")
        return True
    except AssertionError as e:
        print(f"[FAIL] {scenario_name} - {e}")
        return False
    except Exception as e:
        print(f"[ERROR] {scenario_name} - {type(e).__name__}: {e}")
        return False

def scenario_new_pbkdf2():
    """New user registers with PBKDF2"""
    password = "TestPass123!@#"
    hash_result, salt_result = hash_password(password)
    
    # Verify hash format
    assert len(hash_result) == 64, f"Hash should be 64 chars, got {len(hash_result)}"
    assert len(salt_result) == 32, f"Salt should be 32 chars, got {len(salt_result)}"
    assert all(c in '0123456789abcdefABCDEF' for c in hash_result), "Hash should be hex"
    assert all(c in '0123456789abcdefABCDEF' for c in salt_result), "Salt should be hex"
    
    # Verify password
    result = verify_password(password, hash_result, salt_result)
    assert result == True, "Should verify with separated format"
    
    # Wrong password should fail
    result = verify_password("WrongPass", hash_result, salt_result)
    assert result == False, "Wrong password should not verify"

def scenario_legacy_combined():
    """User has legacy combined format (from before separation)"""
    password = "OldPassword456!@"
    hash_result, salt_result = hash_password(password)
    combined = f"{salt_result}${hash_result}"
    
    # Verify combined format
    assert len(combined) == 97, f"Combined should be 97 chars, got {len(combined)}"
    assert combined.count('$') == 1, "Combined should have exactly one $"
    
    # Verify password with combined format
    result = verify_password(password, combined)
    assert result == True, "Should verify with combined format"
    
    # Wrong password should fail
    result = verify_password("WrongPass", combined)
    assert result == False, "Wrong password should not verify with combined"

def scenario_legacy_sha256():
    """User has legacy SHA256 hash (from old authentication system)"""
    password = "VeryOldPassword1!@"
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Verify SHA256 format
    assert len(sha256_hash) == 64, f"SHA256 should be 64 chars, got {len(sha256_hash)}"
    assert all(c in '0123456789abcdefABCDEF' for c in sha256_hash), "SHA256 should be hex"
    
    # Verify with legacy SHA256
    result = verify_password(password, sha256_hash)
    assert result == True, "Should verify legacy SHA256"
    
    # Wrong password should fail
    result = verify_password("WrongPass", sha256_hash)
    assert result == False, "Wrong password should not verify with SHA256"

def scenario_sha256_with_fake_salt():
    """Migration scenario: SHA256 hash with a salt field (mismatch)"""
    password = "MigrationPass999!"
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    fake_salt = "12345678901234567890123456789012"
    
    # Should verify by falling back to SHA256
    result = verify_password(password, sha256_hash, fake_salt)
    assert result == True, "Should fallback to SHA256 when PBKDF2 fails"

def scenario_test_data_format():
    """Handle test data with non-standard format"""
    password = "TestData123"
    test_hash = "test_hash_value_" * 4  # 64 chars
    test_salt = "test_salt"  # Not 32 chars, but should still work
    
    # This will fail verification (not a real hash), but shouldn't crash
    result = verify_password(password, test_hash, test_salt)
    assert result == False, "Invalid hash should not verify"

def scenario_edge_cases():
    """Test edge cases"""
    # Empty password
    result = verify_password("", "somehash")
    assert result == False, "Empty password should not verify"
    
    # None password
    result = verify_password(None, "somehash")
    assert result == False, "None password should not verify"
    
    # Empty hash
    result = verify_password("password", "")
    assert result == False, "Empty hash should not verify"
    
    # None hash
    result = verify_password("password", None)
    assert result == False, "None hash should not verify"
    
    # Very long password (over 128 chars) with salt
    long_pass = "x" * 200
    result = verify_password(long_pass, "somehash", "somesalt")
    assert result == False, "Overly long password should not verify"
    
    # Very long hash
    long_hash = "x" * 500
    result = verify_password("password", long_hash)
    assert result == False, "Overly long hash should not verify"

def scenario_actual_password():
    """Test with actual production password format"""
    password = "Mayank@#03"
    
    # New format
    hash_result, salt_result = hash_password(password)
    result = verify_password(password, hash_result, salt_result)
    assert result == True, "Should verify actual password in new format"
    
    # Legacy SHA256
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    result = verify_password(password, sha256_hash)
    assert result == True, "Should verify actual password in SHA256 format"

if __name__ == "__main__":
    print("=" * 70)
    print("COMPREHENSIVE AUTHENTICATION INTEGRATION TEST")
    print("=" * 70)
    
    scenarios = [
        ("New User with PBKDF2", scenario_new_pbkdf2),
        ("Legacy Combined Format (salt$hash)", scenario_legacy_combined),
        ("Legacy SHA256 Hash", scenario_legacy_sha256),
        ("SHA256 Hash with Fake Salt (Migration)", scenario_sha256_with_fake_salt),
        ("Test Data Format (Non-standard)", scenario_test_data_format),
        ("Edge Cases", scenario_edge_cases),
        ("Actual Production Password", scenario_actual_password),
    ]
    
    passed = 0
    failed = 0
    
    for scenario_name, test_func in scenarios:
        if run_scenario(scenario_name, test_func):
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\n[SUCCESS] All authentication tests passed!")
        sys.exit(0)
    else:
        print(f"\n[FAILURE] {failed} test(s) failed!")
        sys.exit(1)
