#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Set mock database
os.environ['USE_MOCK_DB'] = 'True'
os.environ['DEBUG'] = 'True'

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def check_endpoints():
    """Check all available endpoints"""
    print("🔍 Checking available endpoints...\n")
    
    # Test common endpoints
    endpoints = [
        "/api/v1/files/init",
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/messages/send",
        "/api/v1/messages",
        "/api/v1/chats",
        "/api/v1/users/profile",
        "/api/v1/health",
        "/docs",
        "/",
        "/api/v1"
    ]
    
    for endpoint in endpoints:
        try:
            response = client.get(endpoint)
            status = "✅" if 200 <= response.status_code < 300 else "❌"
            print(f"{status} GET {endpoint} - {response.status_code}")
        except Exception as e:
            print(f"❌ GET {endpoint} - Error: {e}")
    
    # Check POST endpoints
    post_endpoints = [
        ("/api/v1/files/init", {"filename": "test.txt", "size": 1024, "chat_id": "test", "mime_type": "text/plain"}),
        ("/api/v1/messages/send", {"chat_id": "test", "message": "Hello", "message_type": "text"}),
        ("/api/v1/auth/login", {"email": "test@test.com", "password": "test123"}),
    ]
    
    print("\n📤 Testing POST endpoints:")
    for endpoint, payload in post_endpoints:
        try:
            response = client.post(endpoint, json=payload)
            status = "✅" if 200 <= response.status_code < 300 else "❌"
            print(f"{status} POST {endpoint} - {response.status_code}")
        except Exception as e:
            print(f"❌ POST {endpoint} - Error: {e}")

if __name__ == "__main__":
    check_endpoints()
