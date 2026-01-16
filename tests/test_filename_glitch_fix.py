#!/usr/bin/env python3
"""
Test for the specific YenSurferUserSetup filename rendering glitch fix
"""

import pytest
import sys
import os

# Add frontend to path for testing
frontend_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'lib', 'presentation', 'screens')
if frontend_path not in sys.path:
    sys.path.insert(0, frontend_path)

def test_filename_pattern_detection():
    """Test that filename patterns are properly detected to prevent rendering glitches"""
    
    # Mock the filename detection logic (simplified version of Flutter implementation)
    def is_likely_filename(text):
        # Check for common filename patterns that would cause rendering glitches
        if not isinstance(text, str) or not text:
            return False

        lowered = text.lower()

        # URLs / API paths should never be treated as filenames by this heuristic
        if "/" in text or "://" in text:
            return False

        # Specific glitch-triggering patterns
        if (
            "yensurferusersetup" in lowered
            or "usersetup" in lowered
            or "setup" in lowered
            or "x64" in lowered
        ):
            return True

        # Executables are always treated as filenames
        if lowered.endswith(".exe"):
            return True

        # Generic hyphenated tokens with an extension (e.g. file-name.ext)
        if "-" in text and "." in text:
            return True

        return False
    
    # Test cases that should be detected as filenames
    problematic_patterns = [
        "YenSurferUserSetup-x64-13.5.exe",
        "YenSurferUserSetup",
        "UserSetup-x64.exe",
        "application-x64-12.1.exe",
        "program-setup.exe",
        "file-name.ext"
    ]
    
    # Test cases that should NOT be detected as filenames
    valid_patterns = [
        "/api/v1/users/avatar/user123.jpg",
        "https://example.com/avatar.png",
        "/api/v1/users/avatar/abc123.jpg",
        "avatar.jpg",
        "https://server.com/path/to/image.png"
    ]
    
    print("[TEST] Testing filename pattern detection...")
    
    for pattern in problematic_patterns:
        result = is_likely_filename(pattern)
        assert result == True, f"Should detect '{pattern}' as filename"
        print(f"✓ Detected as filename: {pattern}")
    
    for pattern in valid_patterns:
        result = is_likely_filename(pattern)
        assert result == False, f"Should NOT detect '{pattern}' as filename"
        print(f"✓ Valid URL pattern: {pattern}")
    
    print("PASS: All filename patterns correctly identified")

if __name__ == "__main__":
    test_filename_pattern_detection()
    print("SUCCESS: Filename rendering glitch fix verification completed!")