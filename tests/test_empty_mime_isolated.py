#!/usr/bin/env python3
"""
Isolated test for empty MIME type
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import asyncio
import json

# Set up mock database for testing
os.environ['USE_MOCK_DB'] = 'true'

from fastapi.testclient import TestClient
from backend.main import app
from backend.auth.utils import create_access_token

client = TestClient(app)

def test_empty_mime_only():
    """Test ONLY empty MIME type"""
    
    print("[TEST] Testing empty MIME type in isolation...")
    
    # Create a test token
    test_payload = {
        "sub": "695b468f9f0b4122e16d740d",
        "email": "test@example.com",
        "token_type": "access"
    }
    
    token = create_access_token(test_payload)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test empty MIME type
    payload = {
        "filename": "no_mime_file",
        "size": 1024,
        "chat_id": "test_chat_123",
        "mime_type": ""
    }
    
    print(f"[TEST] Payload: {json.dumps(payload, indent=2)}")
    
    response = client.post("/api/v1/files/init", 
                       json=payload, 
                       headers=headers)
    
    print(f"[TEST] Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        upload_id = data.get('upload_id')
        print(f"[TEST] SUCCESS - Upload ID: {upload_id}")
        return True
    else:
        print(f"[TEST] FAILED - {response.status_code}")
        print(f"[TEST] Response: {response.text}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("EMPTY MIME TYPE TEST")
    print("=" * 60)
    
    success = test_empty_mime_only()
    
    print("=" * 60)
    if success:
        print("TEST PASSED")
        sys.exit(0)
    else:
        print("TEST FAILED")
        sys.exit(1)