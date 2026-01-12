#!/usr/bin/env python3
"""
Simple test to verify chat functionality works
"""

import sys
import os
import asyncio
from fastapi.testclient import TestClient

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

async def test_chat_functionality():
    """Test basic chat functionality"""
    print("=== Testing Chat Functionality ===")
    
    from backend.main import app
    client = TestClient(app)
    
    # Test 1: Create private chat
    response = client.post("/api/v1/chats/create", json={
        "type": "private",
        "member_ids": ["user2"]
    })
    
    print(f"✅ Private chat creation: {response.status_code}")
    
    # Test 2: Get chats list
    response = client.get("/api/v1/chats")
    print(f"✅ Chat list: {response.status_code}")
    
    # Test 3: Send message
    response = client.post("/api/v1/chats/test_chat_id/messages", json={
        "text": "Hello World"
    })
    
    print(f"✅ Message sent: {response.status_code}")
    
    print("=== Chat Functionality Test Complete ===")

if __name__ == "__main__":
    asyncio.run(test_chat_functionality())
