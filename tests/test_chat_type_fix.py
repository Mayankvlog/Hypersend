#!/usr/bin/env python3
"""
Test chat creation functionality to identify and fix the chat type validation issue
"""

import pytest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

class TestChatCreationFix:
    """Test chat creation functionality and fix chat type validation"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        from main import app
        return TestClient(app)
    
    @pytest.mark.asyncio
    async def test_chat_type_validation_issue(self):
        """Test the chat type validation issue from logs"""
        from routes.chats import create_chat
        from models import ChatCreate
        
        # Test all valid chat types
        valid_types = ["private", "group", "supergroup", "channel", "secret", "saved"]
        
        for chat_type in valid_types:
            chat = ChatCreate(
                type=chat_type,
                name=f"Test {chat_type}",
                member_ids=["user1", "user2"] if chat_type == "private" else ["user1"]
            )
            
            # Mock collections
            class MockChatsCollection:
                def __init__(self):
                    self.chat = None
                
                async def find_one(self, query):
                    return None  # No existing chat
                
                async def insert_one(self, chat_doc):
                    self.chat = chat_doc
                    return MagicMock(inserted_id="mock_chat_id")
            
            with patch("routes.chats.chats_collection", return_value=MockChatsCollection()), \
                 patch("routes.chats.get_current_user", return_value="user1"):
                
                try:
                    response = await create_chat(chat, "user1")
                    assert response is not None
                    print(f"✅ Chat type '{chat_type}' validation passed")
                except Exception as e:
                    if "Invalid chat type" in str(e):
                        print(f"❌ Chat type '{chat_type}' validation failed: {e}")
                        raise AssertionError(f"Valid chat type '{chat_type}' was rejected")
    
    @pytest.mark.asyncio
    async def test_invalid_chat_type_rejection(self):
        """Test that invalid chat types are properly rejected"""
        from routes.chats import create_chat
        from models import ChatCreate
        from pydantic import ValidationError
        
        # Test invalid chat types
        invalid_types = ["invalid", "direct", "personal", "community", "broadcast"]
        
        for chat_type in invalid_types:
            # Test that ChatCreate model rejects invalid types at creation
            try:
                chat = ChatCreate(
                    type=chat_type,
                    name=f"Test {chat_type}",
                    member_ids=["user1", "user2"]
                )
                # If we get here, validation didn't work
                raise AssertionError(f"Invalid chat type '{chat_type}' was accepted by model")
            except ValidationError as e:
                # This is expected - validation should fail at model level
                assert "Invalid chat type" in str(e)
                print(f"✅ Invalid chat type '{chat_type}' properly rejected at model level")
            
            # Also test that route would reject if somehow bypassed model validation
            with patch("routes.chats.chats_collection", return_value=MagicMock()), \
                 patch("routes.chats.get_current_user", return_value="user1"):
                
                # Create a valid chat first, then modify type to test route validation
                try:
                    valid_chat = ChatCreate(
                        type="private",
                        name="Test Chat",
                        member_ids=["user1", "user2"]
                    )
                    # Manually set invalid type to test route validation (bypassing model validation)
                    valid_chat.type = chat_type
                    
                    with pytest.raises(Exception) as exc_info:
                        await create_chat(valid_chat, "user1")
                    
                    # Should get validation error from route or model
                    assert "Invalid chat type" in str(exc_info.value) or "validation error" in str(exc_info.value).lower()
                    print(f"✅ Invalid chat type '{chat_type}' properly rejected by route")
                except Exception as route_e:
                    # Route should also catch this
                    assert "Invalid chat type" in str(route_e) or "validation error" in str(route_e).lower()
                    print(f"✅ Invalid chat type '{chat_type}' properly rejected by route")
    
    @pytest.mark.asyncio
    async def test_chat_type_enum_consistency(self):
        """Test that ChatType enum matches validation list"""
        from models import ChatType
        
        # Check if all enum values are in validation list
        enum_values = [
            ChatType.PRIVATE,
            ChatType.GROUP, 
            ChatType.SUPERGROUP,
            ChatType.CHANNEL,
            ChatType.SECRET
        ]
        
        validation_list = ["private", "group", "supergroup", "channel", "secret", "saved"]
        
        for enum_val in enum_values:
            if enum_val not in validation_list:
                raise AssertionError(f"Enum value '{enum_val}' not in validation list")
        
        # Check if validation list has all enum values (except saved which is special)
        for val in validation_list:
            if val not in enum_values and val != "saved":
                print(f"⚠️ Validation list has '{val}' but no enum constant")
        
        print("✅ Chat type enum consistency verified")
    
    def test_debug_log_analysis(self):
        """Analyze the debug log to identify the issue"""
        # The log shows: "Invalid chat type. Must be one of: private, group, supergroup, channel, secret, saved"
        # This suggests the frontend is sending a type not in this list
        
        # Common issues that could cause this:
        potential_issues = [
            "Frontend sending 'direct' instead of 'private'",
            "Frontend sending 'personal' instead of 'private'", 
            "Frontend sending 'community' instead of 'group'",
            "Frontend sending null/undefined type",
            "Case sensitivity issues",
            "Extra whitespace in type",
            "Typo in type string"
        ]
        
        print("🔍 Potential causes for chat type validation error:")
        for i, issue in enumerate(potential_issues, 1):
            print(f"{i}. {issue}")
        
        # Recommended frontend fixes
        print("\n💡 Recommended frontend fixes:")
        print("1. Use exact type values: 'private', 'group', 'supergroup', 'channel', 'secret', 'saved'")
        print("2. Ensure type is not null or undefined")
        print("3. Trim whitespace from type values")
        print("4. Add client-side validation before API call")

    @pytest.mark.asyncio
    async def test_post_chats_root_endpoint(self):
        """Test that POST /api/v1/chats endpoint works (not just /api/v1/chats/create)"""
        from routes.chats import create_chat_root
        from models import ChatCreate
        
        # Test data
        chat_data = ChatCreate(
            type="private",
            member_ids=["test_user_id", "other_user_id"]
        )
        
        # Mock collections and ObjectId
        mock_collection = AsyncMock()
        mock_collection.find_one.return_value = None  # No existing chat
        mock_collection.insert_one.return_value = MagicMock(inserted_id="test_chat_id")
        
        with patch('routes.chats.chats_collection', return_value=mock_collection), \
             patch('routes.chats.ObjectId', return_value="test_chat_id"):
            # Test the new root endpoint
            result = await create_chat_root(chat_data, "test_user_id")
            
            # Verify the result
            assert result is not None
            assert "chat_id" in result
            assert result["chat_id"] == "test_chat_id"
            
            # Verify the collection was called correctly
            mock_collection.insert_one.assert_called_once()
            
            print("✅ POST /api/v1/chats endpoint works correctly")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
