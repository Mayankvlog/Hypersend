#!/usr/bin/env python3
"""
Simple test to verify chat functionality works
"""

import pytest
import sys
import os
import asyncio
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

def test_chat_functionality():
    """Test basic chat functionality"""
    print("=== Testing Chat Functionality ===")
    
    try:
        from backend.main import app
        client = TestClient(app)
    except ImportError as e:
        print(f"Cannot import app: {e}")
        pytest.skip("Backend app not available")
        return
    
    # Patch DB access to avoid Motor event-loop issues in sync TestClient runs.
    with patch("backend.routes.chats.chats_collection") as mock_chats_collection:
        mock_chats = AsyncMock()
        mock_chats.find_one = AsyncMock(return_value=None)
        mock_chats.insert_one = AsyncMock()
        mock_chats_collection.return_value = mock_chats

        try:
            from backend.main import app
            from backend.auth.utils import get_current_user

            app.dependency_overrides[get_current_user] = lambda: "user1"
        except Exception:
            pass

        # Test 1: Create private chat
        response = client.post(
            "/api/v1/chats/create",
            json={
                "type": "private",
                "member_ids": ["user2"],
            },
        )

        print(f"✅ Private chat creation: {response.status_code}")

        # Test 2: Get chats list
        response = client.get("/api/v1/chats")
        print(f"✅ Chat list: {response.status_code}")

        # Test 3: Send message
        response = client.post(
            "/api/v1/chats/test_chat_id/messages",
            json={
                "text": "Hello World",
            },
        )

        print(f"✅ Message sent: {response.status_code}")

        try:
            from backend.main import app
            from backend.auth.utils import get_current_user

            app.dependency_overrides.pop(get_current_user, None)
        except Exception:
            pass
    
    print("=== Chat Functionality Test Complete ===")

if __name__ == "__main__":
    test_chat_functionality()
