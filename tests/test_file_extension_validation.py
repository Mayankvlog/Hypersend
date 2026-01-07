#!/usr/bin/env python3
"""Direct validation of file extension blocking"""

import pytest

from backend.security import SecurityConfig
from backend.validators import validate_command_injection, validate_path_injection


def _ext(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()


@pytest.mark.parametrize(
    "filename,expected_safe",
    [
        ("document.pdf", True),
        ("script.js", True),  # User requested JavaScript files
        ("virus.exe", True),  # User requested .exe files
        ("image.JPG", True),
        ("program.EXE", True),  # User requested .exe files
        ("movie.mp4", True),
        ("setup.msi", True),  # User requested .msi files
    ],
)
def test_file_extension_blocking(filename: str, expected_safe: bool):
    ext = _ext(filename)
    is_blocked = ext in SecurityConfig.BLOCKED_FILE_EXTENSIONS
    assert (not is_blocked) == expected_safe


@pytest.mark.parametrize(
    "value,expected",
    [
        ("test.txt", True),
        ("rm -rf /", False),
        ("test; whoami", False),
        ("test | cat", False),
    ],
)
def test_command_injection_validation(value: str, expected: bool):
    assert validate_command_injection(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("document.txt", True),
        ("../../../etc/passwd", False),
        ("safe/path/file.txt", True),
        ("test\x00null.txt", False),
    ],
)
def test_path_injection_validation(value: str, expected: bool):
    assert validate_path_injection(value) is expected
