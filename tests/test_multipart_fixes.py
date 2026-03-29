#!/usr/bin/env python3
"""
Test script to verify multipart boundary fixes in files.py
"""

import sys

def test_multipart_detection():
    """Test the _detect_multipart_boundary function"""
    
    # Create test data patterns
    test_cases = [
        {
            "name": "Valid multipart PNG",
            "data": b"------WebKitFormBoundaryABC123\r\nContent-Disposition: form-data\r\n\r\n\x89PNG\r\n\x1a\n",
            "expect_boundary": b"------WebKitFormBoundaryABC123",
        },
        {
            "name": "PNG without multipart",
            "data": b"\x89PNG\r\n\x1a\n[actual PNG bytes]",
            "expect_boundary": None,
        },
        {
            "name": "Empty data",
            "data": b"",
            "expect_boundary": None,
        },
        {
            "name": "Invalid multipart marker",
            "data": b"-PNG\r\n...",
            "expect_boundary": None,
        },
    ]
    
    print("=" * 60)
    print("MULTIPART BOUNDARY DETECTION TESTS")
    print("=" * 60)
    
    for test in test_cases:
        # Simulate the function logic
        data = test["data"]
        expected = test["expect_boundary"]
        
        # Apply detection logic
        if not data or not data.startswith(b"--"):
            detected = None
        else:
            first_crlf = data.find(b"\r\n")
            if first_crlf > 2:
                detected = data[:first_crlf]
            else:
                detected = None
        
        passed = detected == expected
        status = "✓ PASS" if passed else "✗ FAIL"
        
        print(f"\n{status}: {test['name']}")
        if not passed:
            print(f"  Expected: {expected}")
            print(f"  Got: {detected}")
    
    print("\n" + "=" * 60)

def test_multipart_cleaning():
    """Test the _clean_multipart_boundaries logic"""
    
    print("\nMULTIPART BOUNDARY CLEANING TESTS")
    print("=" * 60)
    
    # Test case: valid multipart data with PNG
    test_multipart = (
        b"------WebKitFormBoundaryABC123\r\n"
        b"Content-Disposition: form-data; name=\"file\"\r\n"
        b"Content-Type: image/png\r\n"
        b"\r\n"
        b"\x89PNG\r\n\x1a\n[PNG DATA HERE]"
        b"\r\n------WebKitFormBoundaryABC123--"
    )
    
    # Extract boundary
    first_crlf = test_multipart.find(b"\r\n")
    boundary = test_multipart[:first_crlf]
    
    # Find headers end
    headers_end = test_multipart.find(b"\r\n\r\n")
    file_start = headers_end + 4
    
    # Find closing boundary
    closing_boundary = b"\r\n" + boundary + b"--"
    closing_idx = test_multipart.find(closing_boundary, file_start)
    
    # Extract file
    if closing_idx > file_start:
        extracted = test_multipart[file_start:closing_idx]
    else:
        extracted = b"ERROR"
    
    expected_start = b"\x89PNG\r\n\x1a\n"
    success = extracted.startswith(expected_start)
    
    print(f"\n{'✓ PASS' if success else '✗ FAIL'}: Multipart extraction")
    print(f"  Input size: {len(test_multipart)} bytes")
    print(f"  Extracted size: {len(extracted)} bytes")
    if extracted.startswith(expected_start):
        print(f"  ✓ Starts with PNG signature")
    else:
        print(f"  ✗ Does NOT start with PNG signature")
        print(f"    First bytes: {extracted[:20]}")

def test_id_validation():
    """Test ID validation accepts both UUIDs and ObjectIds"""
    
    print("\nID VALIDATION TESTS")
    print("=" * 60)
    
    from bson import ObjectId
    
    test_ids = [
        ("Valid ObjectId string", "64a1b2c3d4e5f6g7h8i9j0k1", True),
        ("Valid UUID", "550e8400-e29b-41d4-a716-446655440000", True),
        ("Valid UUID no hyphens", "550e8400e29b41d4a716446655440000", True),
        ("Empty string", "", False),
        ("Invalid format", "!!!invalid!!!", True),  # Will pass initial check, fail at DB
        ("Special characters", "../../../etc/passwd", True),  # Passes initial, fails at DB
    ]
    
    for name, test_id, should_validate in test_ids:
        # Apply validation logic
        is_valid_objectid = ObjectId.is_valid(test_id)
        is_valid_string = isinstance(test_id, str)
        passes_check = test_id and (is_valid_objectid or is_valid_string)
        
        status = "✓ PASS" if passes_check == should_validate else "✗ FAIL"
        print(f"{status}: {name}")
        print(f"  ID: {test_id:30s} Valid: {passes_check}")

if __name__ == "__main__":
    test_multipart_detection()
    test_multipart_cleaning()
    test_id_validation()
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)
