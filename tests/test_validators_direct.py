#!/usr/bin/env python3
"""Direct test of security validators - command injection and path traversal"""

import pytest

from backend.validators import validate_command_injection, validate_path_injection


@pytest.mark.parametrize(
    "value,expected",
    [
        ("hello world", True),
        ("test;ls", False),
        ("test|cat", False),
        ("eval(x)", False),
        ("subprocess.run", False),
        ("file.txt", True),
        ("test<script>alert(1)</script>", False),
        ("data\x00null", False),
        ("test&rm", False),
        ("normal_input", True),
    ],
)
def test_validate_command_injection_direct(value: str, expected: bool):
    assert validate_command_injection(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("file.txt", True),
        ("../../../etc/passwd", False),
        ("data/file.txt", True),
        ("file\x00name", False),
        ("/etc/passwd", False),
        ("document.pdf", True),
        ("..\\..\\windows\\system32", False),
    ],
)
def test_validate_path_injection_direct(value: str, expected: bool):
    assert validate_path_injection(value) is expected
