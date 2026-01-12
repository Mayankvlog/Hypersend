#!/usr/bin/env python3
"""
Test member suggestions endpoint specifically
"""

import pytest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

class TestMemberSuggestionsFix:
    """Test member suggestions functionality"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        from backend.main import app
        return TestClient(app)
    
    @pytest.mark.asyncio
    async def test_member_suggestions_returns_list(self, client):
        """Test that member suggestions returns a list, not dict"""
        from fastapi.security import HTTPAuthorizationCredentials
        
        # Mock user with contacts
        mock_user = {
            "_id": "current_user",
            "contacts": ["user1", "user2", "user3"]
        }
        
        mock_contacts = [
            {
                "_id": "user1",
                "name": "User One",
                "email": "user1@example.com",
                "username": "user1",
                "avatar_url": None,
                "is_online": True,
                "last_seen": None,
                "status": "active"
            },
            {
                "_id": "user2", 
                "name": "User Two",
                "email": "user2@example.com",
                "username": "user2",
                "avatar_url": None,
                "is_online": False,
                "last_seen": None,
                "status": "active"
            }
        ]
        
        mock_group = {
            "_id": "test_group",
            "type": "group",
            "members": ["current_user"]  # User is member
        }
        
        # Mock all the dependencies
        fake_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="fake_token")
        
        with patch('backend.routes.groups.get_current_user', return_value="current_user"):
            with patch('backend.routes.groups.UserCacheService.get_user_contacts', return_value=["user1", "user2", "user3"]):
                with patch('backend.routes.groups.users_collection') as mock_users_collection:
                    # Mock the cursor
                    mock_cursor = AsyncMock()
                    mock_cursor.__aiter__ = AsyncMock(return_value=iter(mock_contacts))
                    mock_users_collection.return_value.find.return_value = mock_cursor
                    
                    with patch('backend.routes.groups.chats_collection') as mock_chats_collection:
                        mock_chats_collection.return_value.find_one.return_value = mock_group
                        
                        with patch('backend.routes.groups.SearchCacheService') as mock_search_cache:
                            mock_search_cache.get_user_search.return_value = None  # No cache hit
                            mock_search_cache.set_user_search = AsyncMock()
                            
                            # Make the request
                            response = client.get(
                                "/api/v1/groups/test_group/member-suggestions",
                                headers={"Authorization": "Bearer fake_token"}
                            )
                            
                            # Verify response
                            assert response.status_code == 200
                            suggestions = response.json()
                            
                            # CRITICAL: Verify it returns a list, not a dict
                            assert isinstance(suggestions, list), f"Expected list, got {type(suggestions)}"
                            assert len(suggestions) == 2, f"Expected 2 suggestions, got {len(suggestions)}"
                            
                            # Verify structure of first suggestion
                            assert "id" in suggestions[0]
                            assert "name" in suggestions[0]
                            assert suggestions[0]["id"] == "user1"
                            assert suggestions[0]["name"] == "User One"
                            
                            # Verify cache was called properly
                            mock_search_cache.set_user_search.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_member_suggestions_with_search_filter(self, client):
        """Test member suggestions with search query"""
        from fastapi.security import HTTPAuthorizationCredentials
        
        mock_user = {
            "_id": "current_user",
            "contacts": ["user1", "user2"]
        }
        
        mock_contacts = [
            {
                "_id": "user1",
                "name": "John Doe",
                "email": "john@example.com",
                "username": "johndoe",
                "avatar_url": None,
                "is_online": True,
                "last_seen": None,
                "status": "active"
            }
        ]
        
        mock_group = {
            "_id": "test_group",
            "type": "group", 
            "members": ["current_user"]
        }
        
        fake_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="fake_token")
        
        with patch('backend.routes.groups.get_current_user', return_value="current_user"):
            with patch('backend.routes.groups.UserCacheService.get_user_contacts', return_value=["user1", "user2"]):
                with patch('backend.routes.groups.users_collection') as mock_users_collection:
                    mock_cursor = AsyncMock()
                    mock_cursor.__aiter__ = AsyncMock(return_value=iter(mock_contacts))
                    mock_users_collection.return_value.find.return_value = mock_cursor
                    
                    with patch('backend.routes.groups.chats_collection') as mock_chats_collection:
                        mock_chats_collection.return_value.find_one.return_value = mock_group
                        
                        with patch('backend.routes.groups.cache') as mock_cache:
                            mock_cache.get.return_value = None
                            mock_cache.set_group_suggestions = AsyncMock()
                            
                            # Test with search query that matches
                            response = client.get(
                                "/api/v1/groups/test_group/member-suggestions?q=john",
                                headers={"Authorization": "Bearer fake_token"}
                            )
                            
                            assert response.status_code == 200
                            suggestions = response.json()
                            assert isinstance(suggestions, list)
                            assert len(suggestions) == 1
                            assert suggestions[0]["name"] == "John Doe"
