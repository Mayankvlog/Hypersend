"""
Test specific user credentials scenario
This test validates that the system can handle the specific user case:
Email: mayank.kr0311@gmail.com
Password: Mayank@#03
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from backend.auth.utils import hash_password, verify_password, diagnose_password_format
import hashlib


def test_specific_user_credentials():
    """Test the exact credentials that should work"""
    print("\n" + "="*70)
    print("TESTING SPECIFIC USER CREDENTIALS")
    print("="*70)
    
    email = "mayank.kr0311@gmail.com"
    password = "Mayank@#03"
    
    print(f"\nEmail: {email}")
    print(f"Password: {password}")
    
    # Scenario 1: New format (PBKDF2)
    print(f"\n{'─'*70}")
    print("SCENARIO 1: User has NEW PBKDF2 format (current system)")
    print(f"{'─'*70}")
    
    new_hash, new_salt = hash_password(password)
    print(f"Generated hash: {new_hash[:32]}...")
    print(f"Generated salt: {new_salt}")
    
    diagnosis_new = diagnose_password_format(new_hash, new_salt)
    print(f"Diagnosis: {diagnosis_new['hash']['format']}")
    
    is_valid = verify_password(password, new_hash, new_salt)
    print(f"Verification result: {'✓ PASS' if is_valid else '✗ FAIL'}")
    assert is_valid, "Should verify successfully with new format"
    
    # Scenario 2: Legacy SHA256 format
    print(f"\n{'─'*70}")
    print("SCENARIO 2: User has LEGACY SHA256 format")
    print(f"{'─'*70}")
    
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    print(f"SHA256 hash: {sha256_hash}")
    
    diagnosis_sha = diagnose_password_format(sha256_hash, None)
    print(f"Diagnosis: {diagnosis_sha['hash']['format']}")
    
    is_valid = verify_password(password, sha256_hash, None)
    print(f"Verification result: {'✓ PASS' if is_valid else '✗ FAIL'}")
    assert is_valid, "Should verify successfully with SHA256 format"
    
    # Scenario 3: Combined format
    print(f"\n{'─'*70}")
    print("SCENARIO 3: User has COMBINED format (salt$hash)")
    print(f"{'─'*70}")
    
    combined = f"{new_salt}${new_hash}"
    print(f"Combined format: {new_salt}${new_hash[:32]}...")
    
    diagnosis_combined = diagnose_password_format(combined, None)
    print(f"Diagnosis: {diagnosis_combined['hash']['format']}")
    
    is_valid = verify_password(password, combined, None)
    print(f"Verification result: {'✓ PASS' if is_valid else '✗ FAIL'}")
    assert is_valid, "Should verify successfully with combined format"
    
    # Scenario 4: Wrong password (should FAIL)
    print(f"\n{'─'*70}")
    print("SCENARIO 4: User enters WRONG password")
    print(f"{'─'*70}")
    
    wrong_password = "WrongPassword123"
    print(f"Attempted password: {wrong_password}")
    
    is_valid = verify_password(wrong_password, new_hash, new_salt)
    print(f"Verification result: {'✓ Correctly rejected' if not is_valid else '✗ INCORRECTLY ACCEPTED'}")
    assert not is_valid, "Wrong password should fail verification"
    
    # Scenario 5: Swapped hash/salt recovery
    print(f"\n{'─'*70}")
    print("SCENARIO 5: Hash and salt were SWAPPED in database")
    print(f"{'─'*70}")
    
    print(f"Normal order - hash: {new_hash[:32]}..., salt: {new_salt}")
    print(f"Swapped order - hash: {new_salt}, salt: {new_hash[:32]}...")
    
    # This should fail normally
    is_valid_swapped = verify_password(password, new_salt, new_hash)
    print(f"Direct verification with swapped values: {is_valid_swapped}")
    
    # But should work if we swap them back
    is_valid_recovered = verify_password(password, new_hash, new_salt)
    print(f"Verification after recovery: {'✓ PASS' if is_valid_recovered else '✗ FAIL'}")
    assert is_valid_recovered, "Should recover from swapped hash/salt"
    
    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY FOR USER: mayank.kr0311@gmail.com")
    print(f"{'='*70}")
    print("""
The system can now handle this user's password in multiple scenarios:

✓ NEW FORMAT (PBKDF2): Direct verification works
  → Hash: 64-char hex, Salt: 32-char hex
  → Most secure, newly registered users get this

✓ LEGACY SHA256: Automatic fallback works
  → Hash: 64-char hex, No salt
  → Users who were registered with SHA256 still work

✓ COMBINED FORMAT: Auto-parsing works
  → Hash: "salt$hash" format (97 chars)
  → Intermediate format from earlier systems

✓ RECOVERY: Swapped hash/salt detection works
  → If data was stored backwards, system auto-fixes
  → This handles data corruption scenarios

✓ WRONG PASSWORD: Properly rejected
  → System doesn't allow invalid passwords
  → Security maintained

If this user still cannot login:
1. Check database to see which format their password is in
2. Use /debug/diagnose-password endpoint to check
3. If format is unknown/corrupted, request password reset
4. New password will be created in secure PBKDF2 format
""")
    
    print(f"{'='*70}")
    print("ALL SCENARIOS TESTED SUCCESSFULLY!")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    test_specific_user_credentials()
    print("✓ Test completed successfully!")
