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
    
    # Map endpoints to expected HTTP methods and acceptable status codes
    # This allows testing both GET and POST routes with appropriate methods
    endpoints_map = {
        "/api/v1/files/init": {"method": "POST", "expected": [200, 201, 400, 401]},
        "/api/v1/auth/login": {"method": "POST", "expected": [200, 201, 400, 401]},
        "/api/v1/auth/register": {"method": "POST", "expected": [200, 201, 400, 409]},
        "/api/v1/messages/send": {"method": "POST", "expected": [200, 201, 400, 401, 404]},
        "/api/v1/messages": {"method": "GET", "expected": [200, 401, 404]},
        "/api/v1/chats": {"method": "GET", "expected": [200, 401]},
        "/api/v1/users/profile": {"method": "GET", "expected": [200, 401]},
        "/api/v1/health": {"method": "GET", "expected": [200]},
        "/docs": {"method": "GET", "expected": [200, 404]},
        "/": {"method": "GET", "expected": [200, 404]},
        "/api/v1": {"method": "GET", "expected": [200, 404]},
    }
    
    for endpoint, config in endpoints_map.items():
        method = config["method"]
        expected_codes = config["expected"]
        try:
            if method == "GET":
                response = client.get(endpoint)
            else:  # POST
                # Provide appropriate JSON payload for each POST endpoint
                if endpoint == "/api/v1/files/init":
                    payload = {
                        "filename": "test.txt",
                        "size": 1024,
                        "chat_id": "test",
                        "mime_type": "text/plain"
                    }
                elif endpoint == "/api/v1/auth/login":
                    payload = {"username": "testuser", "password": "testpass"}
                elif endpoint == "/api/v1/auth/register":
                    payload = {"username": "testuser", "email": "test@example.com", "password": "testpass"}
                elif endpoint == "/api/v1/messages/send":
                    payload = {"chat_id": "test", "content": "hello", "recipient_id": "recipient"}
                else:
                    payload = None
                response = client.request(method, endpoint, json=payload)
            
            status = "✅" if response.status_code in expected_codes else "❌"
            print(f"{status} {method:4} {endpoint:30} - {response.status_code} (expected {expected_codes})")
        except Exception as e:
            print(f"❌ {method:4} {endpoint:30} - Error: {e}")

if __name__ == "__main__":
    check_endpoints()
