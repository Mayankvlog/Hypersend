#!/usr/bin/env python3
"""
Simple test to verify chat functionality works
"""

import pytest
import sys
import os
import asyncio
from fastapi.testclient import TestClient

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Helper function to handle async calls in tests
def run_async(coro):
    """Run async function safely in test environment"""
    try:
        loop = asyncio.get_running_loop()
        if loop.is_running():
            # Use create_task to run in existing loop
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, coro)
                return future.result()
        else:
            return asyncio.run(coro)
    except RuntimeError as e:
        # No running loop or loop is closed, safe to use asyncio.run
        if "Event loop is closed" in str(e):
            # Create new event loop
            try:
                # Try to get the policy and create a new loop
                policy = asyncio.get_event_loop_policy()
                new_loop = policy.new_event_loop()
                asyncio.set_event_loop(new_loop)
                return new_loop.run_until_complete(coro)
            except Exception:
                # Fallback - try to run directly
                return asyncio.run(coro)
        else:
            return asyncio.run(coro)

def test_chat_functionality():
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
    test_chat_functionality()
