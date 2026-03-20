import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch
from fastapi.testclient import TestClient
from fastapi import status as http_status
import json
import io

from backend.main import app
from backend.models import StatusCreate, StatusInDB
from backend.routes.status import get_status_collection


class TestStatusAPI:
    """Test suite for Status API endpoints"""

    @pytest.fixture
    def mock_current_user(self):
        """Mock authenticated user"""
        return {
            "_id": "507f1f77bcf86cd799439011",
            "email": "testuser@example.com",
            "name": "Test User"
        }

    @pytest.fixture
    def mock_status_collection(self):
        """Mock status collection"""
        return Mock()

    @pytest.fixture
    def mock_database(self, mock_status_collection):
        """Mock database with status collection"""
        mock_db = Mock()
        mock_db.__getitem__.return_value = mock_status_collection
        return mock_db

    @pytest.fixture
    def client(self, mock_database, mock_current_user):
        """Test client fixture with mock database injected"""
        # Override the database dependency for testing
        async def override_get_database():
            return mock_database
        
        # Also override get_status_collection to use mock database
        async def override_get_status_collection():
            return mock_database["statuses"]
        
        from backend.routes import status as status_module
        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[status_module.get_status_collection] = override_get_status_collection
        
        client = TestClient(app)
        
        # Clean up after tests
        yield client
        app.dependency_overrides.clear()

    def test_create_text_status_success(self, client, mock_current_user, mock_database):
        """Test successful text status creation"""
        # Mock authentication
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            # Mock database operations
            mock_database["statuses"].insert_one.return_value = Mock(inserted_id="507f1f77bcf86cd799439012")
            
            # Test data
            status_data = {
                "text": "Hello World! 🌍"
            }
            
            response = client.post(
                "/api/v1/status/",
                json=status_data,
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 201
            data = response.json()
            assert data["text"] == "Hello World! 🌍"
            assert data["user_id"] == mock_current_user["_id"]
            assert "created_at" in data
            assert "expires_at" in data

    def test_create_status_missing_content(self, client, mock_current_user):
        """Test status creation with missing content"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            status_data = {}  # Missing both text and file_key
            
            response = client.post(
                "/api/v1/status/",
                json=status_data,
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 422
            assert "Either text or file must be provided" in response.json()["detail"][0]

    def test_create_status_with_file_key(self, client, mock_current_user, mock_database):
        """Test status creation with file key"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            mock_database["statuses"].insert_one.return_value = Mock(inserted_id="507f1f77bcf86cd799439013")
            
            status_data = {
                "file_key": "status/user123/image.jpg"
            }
            
            response = client.post(
                "/api/v1/status/",
                json=status_data,
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 201
            data = response.json()
            assert data["user_id"] == mock_current_user["_id"]

    def test_upload_status_media_success(self, client, mock_current_user):
        """Test successful status media upload"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            # Mock file upload
            mock_file_content = b"fake_image_content"
            mock_file = io.BytesIO(mock_file_content)
            
            response = client.post(
                "/api/v1/status/upload",
                files={"file": ("test.jpg", mock_file, "image/jpeg")},
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert "upload_id" in data
            assert "upload_url" in data

    def test_upload_status_media_invalid_type(self, client, mock_current_user):
        """Test status media upload with invalid file type"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            mock_file_content = b"fake_file_content"
            mock_file = io.BytesIO(mock_file_content)
            
            response = client.post(
                "/api/v1/status/upload",
                files={"file": ("test.txt", mock_file, "text/plain")},
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 400
            assert "File type text/plain not supported" in response.json()["detail"]

    def test_upload_status_media_too_large(self, client, mock_current_user):
        """Test status media upload with file too large"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            # Create a file larger than 16MB
            mock_file_content = b"x" * (17 * 1024 * 1024)  # 17MB
            mock_file = io.BytesIO(mock_file_content)
            
            response = client.post(
                "/api/v1/status/upload",
                files={"file": ("large.jpg", mock_file, "image/jpeg")},
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 413
            assert "File too large" in response.json()["detail"]

    def test_get_all_statuses_success(self, client, mock_current_user, mock_database):
        """Test successful retrieval of all statuses"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            # Mock database response with AsyncMock for async iteration
            mock_statuses = [
                {
                    "_id": "507f1f77bcf86cd799439014",
                    "user_id": "507f1f77bcf86cd799439015",
                    "text": "Test status 1",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                    "views": 5
                }
            ]
            
            # Use AsyncMock for proper async iteration
            async def async_iterator():
                for item in mock_statuses:
                    yield item
            
            mock_cursor = AsyncMock()
            mock_cursor.__aiter__.return_value = async_iterator()
            mock_database["statuses"].find.return_value.sort.return_value.skip.return_value.limit.return_value = mock_cursor
            mock_database["statuses"].count_documents = AsyncMock(return_value=1)
            
            response = client.get(
                "/api/v1/status/",
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert "statuses" in data
            assert "total" in data
            assert "has_more" in data
            assert len(data["statuses"]) == 1

    def test_get_all_statuses_excludes_own(self, client, mock_current_user, mock_database):
        """Test that get all statuses excludes user's own statuses and verifies $ne filter"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            # Use AsyncMock for proper async iteration
            async def async_iterator():
                return
                yield  # Never reached, creates empty iterator
            
            mock_cursor = AsyncMock()
            mock_cursor.__aiter__.return_value = async_iterator()
            mock_database["statuses"].find.return_value.sort.return_value.skip.return_value.limit.return_value = mock_cursor
            mock_database["statuses"].count_documents = AsyncMock(return_value=0)
            
            response = client.get(
                "/api/v1/status/",
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert len(data["statuses"]) == 0
            
            # Verify that find() was called with $ne filter excluding current user
            mock_database["statuses"].find.assert_called()
            find_call_args = mock_database["statuses"].find.call_args
            query = find_call_args[0][0]
            assert "user_id" in query
            assert "$ne" in query["user_id"]
            assert query["user_id"]["$ne"] == mock_current_user["_id"]

    def test_get_user_statuses_success(self, client, mock_current_user, mock_database):
        """Test successful retrieval of user's statuses"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            target_user_id = "507f1f77bcf86cd799439015"
            mock_statuses = [
                {
                    "_id": "507f1f77bcf86cd799439014",
                    "user_id": target_user_id,
                    "text": "User's status",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                    "views": 3
                }
            ]
            
            # Use AsyncMock for proper async iteration
            async def async_iterator():
                for item in mock_statuses:
                    yield item
            
            mock_cursor = AsyncMock()
            mock_cursor.__aiter__.return_value = async_iterator()
            mock_database["statuses"].find.return_value.sort.return_value.skip.return_value.limit.return_value = mock_cursor
            mock_database["statuses"].count_documents = AsyncMock(return_value=1)
            mock_database["statuses"].update_many = AsyncMock()
            
            response = client.get(
                f"/api/v1/status/{target_user_id}",
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert len(data["statuses"]) == 1
            assert data["statuses"][0]["user_id"] == target_user_id

    def test_get_user_statuses_invalid_id(self, client, mock_current_user):
        """Test get user statuses with invalid user ID"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            response = client.get(
                "/api/v1/status/invalid_id",
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 400
            assert "Invalid user ID format" in response.json()["detail"]

    def test_delete_status_success(self, client, mock_current_user, mock_database):
        """Test successful status deletion"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            status_id = "507f1f77bcf86cd799439014"
            
            # Mock existing status
            mock_database["statuses"].find_one.return_value = {
                "_id": status_id,
                "user_id": mock_current_user["_id"],
                "text": "Status to delete"
            }
            
            response = client.delete(
                f"/api/v1/status/{status_id}",
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 200
            assert "Status deleted successfully" in response.json()["message"]

    def test_delete_status_not_found(self, client, mock_current_user, mock_database):
        """Test status deletion for non-existent status"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            status_id = "507f1f77bcf86cd799439014"
            
            # Mock non-existent status
            mock_database["statuses"].find_one.return_value = None
            
            response = client.delete(
                f"/api/v1/status/{status_id}",
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 404
            assert "Status not found" in response.json()["detail"]

    def test_delete_status_unauthorized(self, client, mock_database):
        """Test status deletion without authentication"""
        status_id = "507f1f77bcf86cd799439014"
        
        response = client.delete(f"/api/v1/status/{status_id}")
        
        assert response.status_code == 401

    def test_status_auto_expiry_filtering(self, client, mock_current_user, mock_database):
        """Test that expired statuses are filtered out by verifying expiry filter in query"""
        with patch('backend.routes.status.get_current_user', return_value=mock_current_user):
            # Use AsyncMock for proper async iteration
            async def async_iterator():
                return
                yield  # Never reached, creates empty iterator
            
            mock_cursor = AsyncMock()
            mock_cursor.__aiter__.return_value = async_iterator()
            mock_database["statuses"].find.return_value.sort.return_value.skip.return_value.limit.return_value = mock_cursor
            mock_database["statuses"].count_documents = AsyncMock(return_value=0)
            
            response = client.get(
                "/api/v1/status/",
                headers={"Authorization": "Bearer test_token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert len(data["statuses"]) == 0
            
            # Verify that find() was called with expiry filter
            mock_database["statuses"].find.assert_called()
            find_call_args = mock_database["statuses"].find.call_args
            query = find_call_args[0][0]
            assert "expires_at" in query
            assert "$gt" in query["expires_at"]


if __name__ == "__main__":
    pytest.main([__file__])
