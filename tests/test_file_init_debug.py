#!/usr/bin/env python3
"""
Debug test for /files/init endpoint to identify the 500 error
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

def test_files_init_endpoint():
    """Test the /files/init endpoint to see what error occurs"""
    
    # First, we need to authenticate
    print("[TEST] Starting file initialization test...")
    
    # Create a test token with proper payload
    print("[TEST] Creating test access token...")
    # Use a valid MongoDB ObjectId format (24 hex chars)
    test_payload = {
        "sub": "695b468f9f0b4122e16d740d",  # Valid 24-char hex ObjectId
        "email": "test@example.com",
        "token_type": "access"
    }
    
    # Use the actual create_access_token function
    token = create_access_token(test_payload)
    print(f"[TEST] Token created: {token[:30]}...")
    
    # Test with valid request
    payload = {
        "filename": "unknown_file.bin",
        "size": 1024 * 1024 * 100,  # 100MB
        "chat_id": "test_chat_123",
        "checksum": "abc123def456",
        "mime_type": "application/octet-stream"  # Test the problematic MIME type
    }
    
    print(f"[TEST] Request payload: {json.dumps(payload, indent=2)}")
    
    # Use token in Authorization header
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    response = client.post("/api/v1/files/init", json=payload, headers=headers)
    
    print(f"[TEST] Response status: {response.status_code}")
    print(f"[TEST] Response body: {response.text}")
    
    if response.status_code not in [200, 400]:
        print(f"[ERROR] Expected 200 or 400, got {response.status_code}")
        # Try to parse as JSON
        try:
            data = response.json()
            print(f"[ERROR] Error details: {json.dumps(data, indent=2)}")
        except:
            print(f"[ERROR] Could not parse response as JSON")
        assert False, f"Expected 200/400, got {response.status_code}"
    
    if response.status_code == 200:
        print("[TEST] File initialization successful!")
        data = response.json()
        print(f"[TEST] Response data: {json.dumps(data, indent=2)}")
    else:
        print("[TEST] File initialization returned validation error (acceptable)")
        try:
            data = response.json()
            print(f"[TEST] Validation error: {json.dumps(data, indent=2)}")
        except:
            print(f"[TEST] Validation response: {response.text}")
    
    assert True

if __name__ == "__main__":
    print("=" * 80)
    print("FILE INIT ENDPOINT DEBUG TEST")
    print("=" * 80)
    
    success = test_files_init_endpoint()
    
    print("=" * 80)
    if success:
        print("TEST PASSED")
        sys.exit(0)
    else:
        print("TEST FAILED")
        sys.exit(1)
