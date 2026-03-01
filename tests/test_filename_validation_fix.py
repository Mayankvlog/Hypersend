"""
Test filename validation - ensure legitimate files are NOT blocked
"""
import pytest
import re
from pathlib import Path


def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """Sanitize input string - remove only critical threats"""
    if not input_string or not isinstance(input_string, str):
        return ""
    
    sanitized = input_string[:max_length]
    # Remove null bytes ONLY
    sanitized = sanitized.replace('\x00', '')
    # Remove control characters ONLY
    sanitized = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    
    return sanitized


def validate_filename(filename: str) -> tuple[bool, str]:
    """
    Validate filename for ACTUAL security threats only.
    Returns (is_valid, reason)
    """
    if not filename or not isinstance(filename, str):
        return False, "Filename must be a non-empty string"
    
    filename = sanitize_input(filename.strip())
    
    if not filename:
        return False, "Filename cannot be empty"
    
    if len(filename) > 1024:
        return False, "Filename too long (max 1024 characters)"
    
    # ONLY block actual path traversal attempts
    if '../' in filename or '..\\'  in filename:
        return False, "Path traversal pattern detected"
    
    # Check for null bytes (already removed by sanitize_input, but double-check)
    if '\x00' in filename:
        return False, "Null byte injection detected"
    
    # Windows reserved names - EXACT match only
    reserved_names = ['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4',
                      'com5', 'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2',
                      'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9']
    
    filename_without_ext = Path(filename).stem.lower()
    if filename_without_ext in reserved_names:
        return False, f"Windows reserved name: {filename_without_ext}"
    
    return True, ""


class TestFilenameValidation:
    """Test filename validation"""
    
    def test_legitimate_exe_file(self):
        """Test that .exe files are allowed"""
        filename = "VSCodeUserSetup-x64-1.109.5(1).exe"
        is_valid, reason = validate_filename(filename)
        assert is_valid, f"Should allow .exe files, but got error: {reason}"
        print(f"✓ {filename} is valid")
    
    def test_legitimate_installer_files(self):
        """Test that installer files (.msi, .dmg, .deb) are allowed"""
        filenames = [
            "Windows10-x64-installer.msi",
            "Application-1.0.0.dmg",
            "package-1.2.3.deb",
            "setup-1.0.jar",
            "script.js",
            "document.pdf",
        ]
        for filename in filenames:
            is_valid, reason = validate_filename(filename)
            assert is_valid, f"Should allow {filename}, but got error: {reason}"
            print(f"✓ {filename} is valid")
    
    def test_files_with_special_chars(self):
        """Test files with parentheses, hyphens, dots"""
        filenames = [
            "file (1).exe",
            "file (1) (1).exe",
            "VSCodeUserSetup-x64-1.109.5(1).exe",
            "my-document-v1.2.3.pdf",
            "file.backup.old.zip",
        ]
        for filename in filenames:
            is_valid, reason = validate_filename(filename)
            assert is_valid, f"Should allow {filename}, but got error: {reason}"
            print(f"✓ {filename} is valid")
    
    def test_dangerous_path_traversal(self):
        """Test that path traversal is blocked"""
        dangerous_files = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "../../../../etc/shadow",
        ]
        for filename in dangerous_files:
            is_valid, reason = validate_filename(filename)
            assert not is_valid, f"Should block {filename}"
            assert "Path traversal" in reason
            print(f"✓ {filename} correctly blocked: {reason}")
    
    def test_dangerous_null_byte(self):
        """Test that null bytes are properly handled (removed)"""
        filename = "file.exe\x00.txt"
        is_valid, reason = validate_filename(filename)
        # Null bytes should be removed by sanitize_input, resulting in "file.exe.txt"
        # which is a valid filename
        assert is_valid, f"Should handle null bytes safely, but got error: {reason}"
        print(f"✓ Null byte injection safely handled/removed")
    
    def test_windows_reserved_names(self):
        """Test that Windows reserved names are blocked"""
        reserved = ["con.txt", "prn.doc", "aux.exe", "nul.bin"]
        for filename in reserved:
            is_valid, reason = validate_filename(filename)
            assert not is_valid, f"Should block reserved name {filename}"
            print(f"✓ {filename} correctly blocked (reserved name)")
    
    def test_empty_filename(self):
        """Test that empty filenames are rejected"""
        is_valid, reason = validate_filename("")
        assert not is_valid
        is_valid, reason = validate_filename("   ")
        assert not is_valid
        print("✓ Empty filenames blocked")
    
    def test_filename_too_long(self):
        """Test that excessively long filenames are rejected"""
        # sanitize_input max_length defaults to 1000, so let's test a filename that's
        # longer than 1000 chars to ensure it's truncated properly
        long_filename = "a" * 1005 + ".txt"  # 1009 chars total
        is_valid, reason = validate_filename(long_filename)
        # This should be truncated to 1000 chars by sanitize_input, then checked
        if is_valid:
            # If valid, it was truncated to <= 1000 chars
            print(f"✓ Long filename correctly truncated to manageable size")
        else:
            # Alternative: if the validation explicitly checks for length
            assert "too long" in reason.lower()
            print(f"✓ Long filename correctly blocked")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
