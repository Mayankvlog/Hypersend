#!/usr/bin/env python3
"""
FINAL TEST: Verify 400 error fix for file upload
Tests the original issue: application/octet-stream MIME type was causing 400 errors
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import asyncio
import json
from pathlib import Path

# Set up mock database for testing
os.environ['USE_MOCK_DB'] = 'true'

from fastapi.testclient import TestClient
from backend.main import app
from backend.auth.utils import create_access_token

client = TestClient(app)

def test_octet_stream_fix():
    """Test that application/octet-stream now works (was causing 400 errors)"""
    
    print("[TEST] Testing application/octet-stream MIME type fix...")
    
    # Create a test token
    test_payload = {
        "sub": "695b468f9f0b4122e16d740d",
        "email": "test@example.com",
        "token_type": "access"
    }
    
    token = create_access_token(test_payload)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test cases that previously caused 400 errors
    test_cases = [
        {
            "name": "Application/octet-stream (original issue)",
            "payload": {
                "filename": "unknown_file.bin",
                "size": 1024,
                "chat_id": "test_chat_123",
                "mime_type": "application/octet-stream"  # This was causing 400
            }
        },
        {
            "name": "Empty MIME type (should use default)",
            "payload": {
                "filename": "no_mime_file",
                "size": 1024,
                "chat_id": "test_chat_123",
                "mime_type": ""
            }
        },
        {
            "name": "Whitespace MIME type (should be normalized)",
            "payload": {
                "filename": "whitespace_mime.bin",
                "size": 1024,
                "chat_id": "test_chat_123",
                "mime_type": "  application/octet-stream  "
            }
        },
        {
            "name": "Uppercase MIME type (should be normalized)",
            "payload": {
                "filename": "uppercase_mime.JPG",
                "size": 1024,
                "chat_id": "test_chat_123",
                "mime_type": "IMAGE/JPEG"
            }
        }
    ]
    
    all_passed = True
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n[TEST {i}] {test_case['name']}")
        print(f"[TEST {i}] Payload: {json.dumps(test_case['payload'], indent=2)}")
        
        response = client.post("/api/v1/files/init", 
                           json=test_case['payload'], 
                           headers=headers)
        
        print(f"[TEST {i}] Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            upload_id = data.get('upload_id')
            print(f"[TEST {i}] SUCCESS - Upload ID: {upload_id}")
        else:
            print(f"[TEST {i}] FAILED - {response.status_code}")
            print(f"[TEST {i}] Response: {response.text}")
            all_passed = False
    
    # Test that truly invalid MIME types still fail
    print(f"\n[TEST 5] Invalid MIME type (should still fail)")
    invalid_payload = {
        "filename": "malicious.exe",
        "size": 1024,
        "chat_id": "test_chat_123",
        "mime_type": "application/x-executable"
    }
    
    response = client.post("/api/v1/files/init", 
                       json=invalid_payload, 
                       headers=headers)
    
    if response.status_code == 400:
        print("[TEST 5] SUCCESS - Invalid MIME type correctly rejected")
    else:
        print(f"[TEST 5] FAILED - Should reject but got {response.status_code}")
        all_passed = False
    
    return all_passed

def test_other_400_scenarios():
    """Test other scenarios that should still return 400"""
    
    print(f"\n[OTHER] Testing other 400 scenarios...")
    
    test_payload = {
        "sub": "695b468f9f0b4122e16d740d",
        "email": "test@example.com",
        "token_type": "access"
    }
    
    token = create_access_token(test_payload)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test missing required fields
    invalid_cases = [
        {
            "name": "Missing filename",
            "payload": {
                "size": 1024,
                "chat_id": "test_chat_123",
                "mime_type": "application/pdf"
            }
        },
        {
            "name": "Missing size",
            "payload": {
                "filename": "test.pdf",
                "chat_id": "test_chat_123",
                "mime_type": "application/pdf"
            }
        },
        {
            "name": "Missing chat_id",
            "payload": {
                "filename": "test.pdf",
                "size": 1024,
                "mime_type": "application/pdf"
            }
        },
        {
            "name": "Invalid file size (0)",
            "payload": {
                "filename": "test.pdf",
                "size": 0,
                "chat_id": "test_chat_123",
                "mime_type": "application/pdf"
            }
        },
        {
            "name": "Negative file size",
            "payload": {
                "filename": "test.pdf",
                "size": -100,
                "chat_id": "test_chat_123",
                "mime_type": "application/pdf"
            }
        }
    ]
    
    all_passed = True
    
    for i, test_case in enumerate(invalid_cases, 1):
        print(f"\n[OTHER {i}] {test_case['name']}")
        
        response = client.post("/api/v1/files/init", 
                           json=test_case['payload'], 
                           headers=headers)
        
        if response.status_code == 400:
            print(f"[OTHER {i}] SUCCESS - Correctly rejected with 400")
        else:
            print(f"[OTHER {i}] FAILED - Expected 400, got {response.status_code}")
            all_passed = False
    
    return all_passed

if __name__ == "__main__":
    print("=" * 80)
    print("FINAL 400 ERROR FIX VALIDATION")
    print("=" * 80)
    
    # Test the main fix
    main_fix_passed = test_octet_stream_fix()
    
    # Test other 400 scenarios still work
    other_400_passed = test_other_400_scenarios()
    
    print("\n" + "=" * 80)
    print("FINAL RESULTS:")
    print(f"Octet-stream fix: {'PASSED' if main_fix_passed else 'FAILED'}")
    print(f"Other 400 validation: {'PASSED' if other_400_passed else 'FAILED'}")
    
    if main_fix_passed and other_400_passed:
        print("ALL TESTS PASSED - 400 error is FIXED!")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED")
        sys.exit(1)