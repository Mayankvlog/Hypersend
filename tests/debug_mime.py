#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.environ['USE_MOCK_DB'] = 'true'

from fastapi.testclient import TestClient
from backend.main import app
from backend.auth.utils import create_access_token

client = TestClient(app)

def get_token():
    return create_access_token({"sub": "695b468f9f0b4122e16d740d", "token_type": "access"})

# Test 1: Invalid MIME type
print("TEST 1: Invalid MIME type (application/x-exe)")
response = client.post("/api/v1/files/init",
    json={"filename": "script.exe", "size": 1024, "chat_id": "chat_123", "checksum": "abc123", "mime_type": "application/x-exe"},
    headers={"Authorization": f"Bearer {get_token()}"}
)
print(f"Status: {response.status_code}")
print(f"Response: {response.json()}\n")

# Test 2: Large file
print("TEST 2: Large 40GB file")
response = client.post("/api/v1/files/init",
    json={"filename": "large.iso", "size": 40 * 1024 * 1024 * 1024, "chat_id": "chat_123", "checksum": "abc123", "mime_type": "application/octet-stream"},
    headers={"Authorization": f"Bearer {get_token()}"}
)
print(f"Status: {response.status_code}")
print(f"Response: {response.json()}\n")
