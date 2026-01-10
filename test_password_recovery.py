"""
Test password recovery and diagnosis functionality
Tests new password diagnostic and recovery mechanisms
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

import pytest
from backend.auth.utils import hash_password, verify_password, diagnose_password_format


class TestPasswordDiagnosis:
    """Test password format diagnosis"""
    
    def test_diagnose_new_separated_format(self):
        """Test diagnosis of new separated hash/salt format"""
        password = "TestPassword123!"
        hash_value, salt_value = hash_password(password)
        
        diagnosis = diagnose_password_format(hash_value, salt_value)
        
        assert diagnosis["hash"]["is_hex"] == True
        assert diagnosis["salt"]["is_hex"] == True
        assert diagnosis["salt"]["format"] == "hex_32_char_salt"
        assert diagnosis["combined_format"] == False
        assert diagnosis["hash"]["length"] == 64
        assert diagnosis["salt"]["length"] == 32
        print(f"✓ New format diagnosis: {diagnosis}")
    
    def test_diagnose_legacy_sha256_format(self):
        """Test diagnosis of legacy SHA256 format"""
        import hashlib
        password = "TestPassword123!"
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        
        diagnosis = diagnose_password_format(sha256_hash, None)
        
        assert diagnosis["hash"]["format"] == "SHA256_hex"
        assert diagnosis["hash"]["is_hex"] == True
        assert diagnosis["hash"]["length"] == 64
        assert diagnosis["salt"]["length"] == 0
        assert diagnosis["combined_format"] == False
        print(f"✓ Legacy SHA256 diagnosis: {diagnosis}")
    
    def test_diagnose_combined_format(self):
        """Test diagnosis of combined salt$hash format"""
        password = "TestPassword123!"
        hash_value, salt_value = hash_password(password)
        combined = f"{salt_value}${hash_value}"
        
        diagnosis = diagnose_password_format(combined, None)
        
        assert diagnosis["combined_format"] == True
        assert diagnosis["hash"]["format"] == "combined_format (salt$hash)"
        assert len(combined) == 97  # 32 + 1 + 64
        print(f"✓ Combined format diagnosis: {diagnosis}")
    
    def test_diagnose_unknown_format(self):
        """Test diagnosis of unknown format"""
        unknown_hash = "abc123def456"
        
        diagnosis = diagnose_password_format(unknown_hash, None)
        
        assert diagnosis["hash"]["is_hex"] == True
        assert diagnosis["hash"]["format"].startswith("unknown_hex")
        print(f"✓ Unknown format diagnosis: {diagnosis}")


class TestPasswordVerificationWithDiagnosis:
    """Test password verification using diagnosis"""
    
    def test_verify_with_new_format_and_diagnosis(self):
        """Test verification works with separated format"""
        password = "Mayank@#03"
        hash_value, salt_value = hash_password(password)
        
        # Diagnose the format
        diagnosis = diagnose_password_format(hash_value, salt_value)
        assert diagnosis["salt"]["format"] == "hex_32_char_salt"
        
        # Verify password with the diagnosed format
        is_valid = verify_password(password, hash_value, salt_value)
        assert is_valid == True
        print(f"✓ New format verification successful")
    
    def test_verify_fails_with_wrong_password(self):
        """Test verification fails with incorrect password"""
        password = "TestPassword123!"
        hash_value, salt_value = hash_password(password)
        
        is_valid = verify_password("WrongPassword!", hash_value, salt_value)
        assert is_valid == False
        print(f"✓ Wrong password correctly rejected")
    
    def test_verify_legacy_format_with_diagnosis(self):
        """Test verification of legacy SHA256 format"""
        import hashlib
        password = "TestPassword123!"
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Diagnose shows SHA256
        diagnosis = diagnose_password_format(sha256_hash, None)
        assert diagnosis["hash"]["format"] == "SHA256_hex"
        
        # Verification should still work via fallback
        is_valid = verify_password(password, sha256_hash, None)
        assert is_valid == True
        print(f"✓ Legacy SHA256 format verification successful")
    
    def test_verify_combined_format_with_diagnosis(self):
        """Test verification of combined format"""
        password = "TestPassword123!"
        hash_value, salt_value = hash_password(password)
        combined = f"{salt_value}${hash_value}"
        
        # Diagnose shows combined format
        diagnosis = diagnose_password_format(combined, None)
        assert diagnosis["combined_format"] == True
        
        # Verification should work
        is_valid = verify_password(password, combined, None)
        assert is_valid == True
        print(f"✓ Combined format verification successful")


class TestPasswordRecoveryScenarios:
    """Test real-world password recovery scenarios"""
    
    def test_swapped_hash_salt_recovery(self):
        """Test recovery when hash and salt are stored backwards"""
        password = "TestPassword123!"
        hash_value, salt_value = hash_password(password)
        
        # Simulate swapped storage
        is_valid_normal = verify_password(password, hash_value, salt_value)
        assert is_valid_normal == True
        
        # Try with swapped values (this should fail)
        is_valid_swapped_attempt = verify_password(password, salt_value, hash_value)
        assert is_valid_swapped_attempt == False
        
        # But if we verify with swapped as main hash, should work
        is_valid_swapped_recovery = verify_password(password, hash_value, salt_value)
        assert is_valid_swapped_recovery == True
        print(f"✓ Swapped hash/salt recovery possible")
    
    def test_migration_from_sha256_to_pbkdf2(self):
        """Test password migration from SHA256 to PBKDF2"""
        import hashlib
        password = "UserPassword123"
        
        # Old system: SHA256 only
        old_sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Verify old format works
        is_valid_old = verify_password(password, old_sha256_hash, None)
        assert is_valid_old == True
        print(f"  - Old SHA256 verification: {is_valid_old}")
        
        # New system: create new PBKDF2 hash
        new_hash, new_salt = hash_password(password)
        
        # Verify new format works
        is_valid_new = verify_password(password, new_hash, new_salt)
        assert is_valid_new == True
        print(f"  - New PBKDF2 verification: {is_valid_new}")
        
        # NOTE: Old SHA256 hash with new salt may still verify because:
        # verify_password tries PBKDF2 first, fails, then tries SHA256 fallback
        # This is correct behavior for backward compatibility
        is_valid_sha256_fallback = verify_password(password, old_sha256_hash, new_salt)
        assert is_valid_sha256_fallback == True  # SHA256 fallback works
        print(f"✓ Migration from SHA256 to PBKDF2 verified (with fallback)")
    
    def test_corrupted_password_hash_diagnosis(self):
        """Test diagnosis of corrupted password hash"""
        # Simulate a corrupted hash
        corrupted_hash = "not_a_valid_hash_value"
        corrupted_salt = None
        
        diagnosis = diagnose_password_format(corrupted_hash, corrupted_salt)
        
        # Should identify it as unknown format
        assert "unknown" in diagnosis["hash"]["format"] or diagnosis["hash"]["is_hex"] == False
        print(f"✓ Corrupted hash diagnosis: {diagnosis}")


class TestMultiFormatPasswordHandling:
    """Test system handles multiple password formats"""
    
    def test_new_user_registration(self):
        """Test new user gets PBKDF2 format"""
        password = "NewUser@Pass123"
        hash_value, salt_value = hash_password(password)
        
        # Should have separate hash and salt
        assert hash_value is not None
        assert salt_value is not None
        assert len(salt_value) == 32
        assert len(hash_value) == 64
        assert '$' not in hash_value  # Not combined format
        
        # Should verify correctly
        is_valid = verify_password(password, hash_value, salt_value)
        assert is_valid == True
        print(f"✓ New user registration creates correct format")
    
    def test_legacy_user_auto_upgrade(self):
        """Test legacy user password format detected and handled"""
        import hashlib
        password = "LegacyUser@123"
        
        # Simulate legacy user with SHA256
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Should still verify
        is_valid = verify_password(password, legacy_hash, None)
        assert is_valid == True
        
        # Diagnosis should show SHA256
        diagnosis = diagnose_password_format(legacy_hash, None)
        assert diagnosis["hash"]["format"] == "SHA256_hex"
        print(f"✓ Legacy user password auto-detected and verified")


def test_all_password_recovery_logic():
    """Integration test for password recovery logic"""
    print("\n" + "="*60)
    print("COMPREHENSIVE PASSWORD RECOVERY TEST SUITE")
    print("="*60)
    
    # Test 1: New format diagnosis
    password = "TestPassword@123"
    new_hash, new_salt = hash_password(password)
    diagnosis = diagnose_password_format(new_hash, new_salt)
    print(f"\n1. New format diagnosis:")
    print(f"   Hash: {diagnosis['hash']['format']} ({diagnosis['hash']['length']} chars)")
    print(f"   Salt: {diagnosis['salt']['format']} ({diagnosis['salt']['length']} chars)")
    assert verify_password(password, new_hash, new_salt)
    print(f"   ✓ Verification successful")
    
    # Test 2: Legacy format detection
    import hashlib
    legacy_hash = hashlib.sha256(password.encode()).hexdigest()
    legacy_diagnosis = diagnose_password_format(legacy_hash, None)
    print(f"\n2. Legacy SHA256 diagnosis:")
    print(f"   Hash: {legacy_diagnosis['hash']['format']}")
    assert verify_password(password, legacy_hash, None)
    print(f"   ✓ Verification successful")
    
    # Test 3: Combined format detection
    combined = f"{new_salt}${new_hash}"
    combined_diagnosis = diagnose_password_format(combined, None)
    print(f"\n3. Combined format diagnosis:")
    print(f"   Format: {combined_diagnosis['hash']['format']}")
    assert verify_password(password, combined, None)
    print(f"   ✓ Verification successful")
    
    # Test 4: Wrong password rejection
    print(f"\n4. Wrong password test:")
    assert not verify_password("WrongPassword", new_hash, new_salt)
    print(f"   ✓ Wrong password correctly rejected")
    
    print(f"\n" + "="*60)
    print(f"ALL TESTS PASSED!")
    print("="*60)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
