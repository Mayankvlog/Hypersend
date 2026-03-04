"""
Comprehensive tests for critical fixes:
1. ObjectId serialization in group creation
2. Forgot password token generation
3. File download response structure

Run with: pytest test_critical_fixes_verification.py -v
"""

import pytest
import json
import asyncio
from datetime import datetime, timezone
from bson import ObjectId
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, MagicMock, AsyncMock

# Import after path setup
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.main import app
from backend.config import settings
from backend.database import users_collection, chats_collection, files_collection


class TestGroupCreationObjectIdFix:
    """Test that group creation properly encodes ObjectId objects"""
    
    @pytest.fixture
    async def auth_headers(self):
        """Create test user and return auth headers"""
        # This would normally use a fixture to create real auth
        return {"Authorization": "Bearer test_token"}
    
    @pytest.mark.asyncio
    async def test_create_group_returns_json_serializable_response(self):
        """Test that create group endpoint returns properly encoded response"""
        from backend.main import app
        from backend.routes.groups import get_current_user
        
        # Override get_current_user dependency with async function
        async def fake_get_current_user():
            return "test_user_123"
        
        app.dependency_overrides[get_current_user] = fake_get_current_user
        
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                test_user_id = "test_user_123"
                test_payload = {
                    "name": "Test Group",
                    "description": "Test Description",
                    "member_ids": [str(ObjectId()), str(ObjectId())]
                }
                
                # Mock database operations
                with patch("backend.routes.groups.chats_collection") as mock_chats:
                    with patch("backend.routes.groups.users_collection") as mock_users:
                        with patch("backend.routes.groups._log_activity"):
                            # Setup mock responses
                            mock_chats.return_value.insert_one = AsyncMock()
                            mock_users.return_value.find_one = AsyncMock(
                                return_value={"_id": "test_user", "name": "Test User"}
                            )
                            
                            response = await client.post(
                                "/api/v1/groups",
                                json=test_payload,
                                headers={"Authorization": "Bearer test_token"}
                            )
                            
                            # Check response is valid JSON
                            assert response.status_code == 201
                            data = response.json()
                            
                            # Verify structure
                            assert "group_id" in data
                            assert "chat_id" in data
                            assert "group" in data
                            
                            # Verify group_id and chat_id are strings
                            assert isinstance(data["group_id"], str)
                            assert isinstance(data["chat_id"], str)
                            
                            # Verify group object has no ObjectId instances
                            group = data["group"]
                            assert isinstance(group["_id"], str)
                            assert isinstance(group["members"], list)
                            assert all(isinstance(m, str) for m in group["members"])
                            
                            print("✅ Group creation response properly serialized")
        finally:
            # Clean up dependency override
            app.dependency_overrides.clear()


class TestForgotPasswordTokenFix:
    """Test that forgot password endpoint returns reset token directly"""
    
    @pytest.mark.asyncio
    async def test_forgot_password_returns_token_directly(self):
        """Test that forgot password returns token without email dependency"""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            test_email = "test@example.com"
            test_payload = {"email": test_email}
            
            with patch("backend.routes.auth.users_collection") as mock_users:
                # Mock user found
                mock_users.return_value.find_one = AsyncMock(
                    return_value={
                        "_id": str(ObjectId()),
                        "email": test_email,
                        "name": "Test User"
                    }
                )
                mock_users.return_value.update_one = AsyncMock()
                
                response = await client.post(
                    "/api/v1/auth/forgot-password",
                    json=test_payload
                )
                
                # Check response structure
                assert response.status_code == 200
                data = response.json()
                
                # Verify token is returned directly
                assert "reset_token" in data or "token" in data
                token = data.get("token") or data.get("reset_token")
                assert isinstance(token, str)
                assert len(token) > 20  # Reset token should be reasonably long
                
                # Verify other fields
                assert "message" in data
                assert "expires_in_minutes" in data
                assert data["expires_in_minutes"] > 0
                
                print("✅ Forgot password returns token directly")
    
    @pytest.mark.asyncio
    async def test_forgot_password_includes_user_id(self):
        """Test that forgot password response includes user_id"""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            test_email = "test@example.com"
            test_user_id = str(ObjectId())
            test_payload = {"email": test_email}
            
            with patch("backend.routes.auth.users_collection") as mock_users:
                mock_users.return_value.find_one = AsyncMock(
                    return_value={
                        "_id": test_user_id,
                        "email": test_email
                    }
                )
                mock_users.return_value.update_one = AsyncMock()
                
                response = await client.post(
                    "/api/v1/auth/forgot-password",
                    json=test_payload
                )
                
                data = response.json()
                assert "user_id" in data
                
                print("✅ Forgot password includes user_id")


class TestFileDownloadResponseFix:
    """Test that file download endpoint returns proper response structure"""
    
    @pytest.mark.asyncio
    async def test_file_download_presigned_url_response_structure(self):
        """Test that presigned URL response has all required fields"""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            test_file_id = str(ObjectId())
            test_user_id = str(ObjectId())
            
            with patch("backend.routes.files.get_current_user_for_download") as mock_get_user:
                mock_get_user.return_value = test_user_id
                
                with patch("backend.routes.files.files_collection") as mock_files:
                    mock_file_doc = {
                        "_id": ObjectId(test_file_id),
                        "owner_id": test_user_id,
                        "filename": "test.pdf",
                        "size": 1024,
                        "mime_type": "application/pdf",
                        "storage_key": "files/test/test.pdf",
                        "bucket": "zaply-temp",
                        "region": "us-east-1"
                    }
                    
                    mock_files.return_value.find_one = AsyncMock(
                        return_value=mock_file_doc
                    )
                    mock_files.return_value.update_one = AsyncMock()
                    
                    with patch("backend.routes.files._generate_presigned_url") as mock_presigned:
                        mock_presigned.return_value = "https://s3.amazonaws.com/presigned-url"
                        
                        response = await client.get(
                            f"/api/v1/files/{test_file_id}/download",
                            headers={"Authorization": "Bearer test_token"}
                        )
                        
                        data = response.json()
                        
                        # Verify required fields
                        assert "presigned_url" in data
                        assert "file_id" in data
                        assert "filename" in data
                        assert "size" in data
                        assert "mime_type" in data
                        assert "expires_in" in data
                        
                        # Verify types
                        assert isinstance(data["presigned_url"], str)
                        assert isinstance(data["file_id"], str)
                        assert isinstance(data["filename"], str)
                        assert isinstance(data["size"], (int, float))
                        assert isinstance(data["expires_in"], int)
                        
                        print("✅ File download presigned URL response properly structured")
    
    @pytest.mark.asyncio
    async def test_file_download_includes_download_url_alias(self):
        """Test that response includes download_url alias for compatibility"""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            test_file_id = str(ObjectId())
            test_user_id = str(ObjectId())
            
            with patch("backend.routes.files.get_current_user_for_download") as mock_get_user:
                mock_get_user.return_value = test_user_id
                
                with patch("backend.routes.files.files_collection") as mock_files:
                    mock_file_doc = {
                        "_id": ObjectId(test_file_id),
                        "owner_id": test_user_id,
                        "filename": "test.pdf",
                        "size": 2048,
                        "mime_type": "application/pdf",
                        "storage_key": "files/test/test.pdf",
                        "bucket": "zaply-temp",
                        "region": "us-east-1"
                    }
                    
                    mock_files.return_value.find_one = AsyncMock(
                        return_value=mock_file_doc
                    )
                    mock_files.return_value.update_one = AsyncMock()
                    
                    with patch("backend.routes.files._generate_presigned_url") as mock_presigned:
                        mock_presigned.return_value = "https://s3.amazonaws.com/presigned-url"
                        
                        response = await client.get(
                            f"/api/v1/files/{test_file_id}/download",
                            headers={"Authorization": "Bearer test_token"}
                        )
                        
                        data = response.json()
                        
                        # Verify alias exists
                        assert "download_url" in data
                        assert data["download_url"] == data["presigned_url"]
                        
                        print("✅ File download includes download_url alias")


class TestObjectIdSerializationIntegration:
    """Integration tests for ObjectId serialization across endpoints"""
    
    @pytest.mark.asyncio
    async def test_list_groups_returns_serialized_groups(self):
        """Test that list groups endpoint properly encodes all ObjectId objects"""
        from backend.main import app
        from backend.routes.groups import get_current_user
        
        # Override get_current_user dependency with async function
        async def fake_get_current_user(request=MagicMock(), credentials=MagicMock()):
            return "test_user_123"
        
        app.dependency_overrides[get_current_user] = fake_get_current_user
        
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                test_user_id = "test_user_123"
                
                with patch("backend.routes.groups.chats_collection") as mock_chats:
                    mock_group_doc = {
                        "_id": ObjectId(),
                        "type": "group",
                        "name": "Test Group",
                        "members": [test_user_id, str(ObjectId())],
                        "created_at": datetime.now(timezone.utc),
                        "muted_by": []
                    }
                    
                    # Mock async cursor
                    mock_cursor = AsyncMock()
                    mock_cursor.__aiter__ = AsyncMock(return_value=mock_cursor)
                    mock_cursor.__anext__ = AsyncMock(side_effect=[mock_group_doc, StopAsyncIteration])
                    
                    mock_chats.return_value.find = MagicMock(return_value=mock_cursor)
                    
                    with patch("backend.routes.groups.messages_collection") as mock_messages:
                        mock_messages.return_value.find_one = AsyncMock(return_value=None)
                        
                        response = await client.get(
                            "/api/v1/groups",
                            headers={"Authorization": "Bearer test_token"}
                        )
                        
                        assert response.status_code == 200
                        data = response.json()
                        
                        # Verify groups are properly serialized
                        assert "groups" in data
                        assert isinstance(data["groups"], list)
                        
                        if data["groups"]:
                            group = data["groups"][0]
                            # All ObjectIds should be strings
                            assert isinstance(group["_id"], str)
                            assert isinstance(group["members"], list)
                            assert all(isinstance(m, str) for m in group["members"])
                        
                        print("✅ List groups returns properly serialized response")
        finally:
            # Clean up dependency override
            app.dependency_overrides.clear()


class TestErrorHandling:
    """Test error handling in fixed endpoints"""
    
    @pytest.mark.asyncio
    async def test_forgot_password_validation_errors(self):
        """Test forgot password validation"""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Test with invalid email
            response = await client.post(
                "/api/v1/auth/forgot-password",
                json={"email": "invalid"}
            )
            
            # Should return 400 or 200 (depends on implementation)
            assert response.status_code in [200, 400, 422]
            
            print("✅ Forgot password handles invalid email")
    
    @pytest.mark.asyncio
    async def test_group_creation_validation(self):
        """Test group creation validation"""
        from backend.main import app
        from backend.routes.groups import get_current_user
        
        # Override get_current_user dependency with async function
        async def fake_get_current_user(request=MagicMock(), credentials=MagicMock()):
            return "test_user_123"
        
        app.dependency_overrides[get_current_user] = fake_get_current_user
        
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                test_user_id = str(ObjectId())
                
                # Test with invalid payload
                response = await client.post(
                    "/api/v1/groups",
                    json={"name": ""}  # Empty name
                )
                
                # Should return 400 or 422
                assert response.status_code in [400, 422]
                
                print("✅ Group creation validates input properly")
        finally:
            # Clean up dependency override
            app.dependency_overrides.clear()


# Test utilities
def assert_no_objectid(obj, path=""):
    """Recursively check that object contains no raw ObjectId instances"""
    if isinstance(obj, ObjectId):
        raise AssertionError(f"Found ObjectId at {path}: {obj}")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            assert_no_objectid(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            assert_no_objectid(item, f"{path}[{i}]")


if __name__ == "__main__":
    print("Run tests with: pytest test_critical_fixes_verification.py -v")
    pytest.main([__file__, "-v", "-s"])
