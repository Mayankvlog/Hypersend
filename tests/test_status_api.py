"""
Test suite for Status API endpoints
Tests validation, authorization, and input handling
"""

import pytest
import os
import sys
import io
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch
from bson import ObjectId
from fastapi.testclient import TestClient
from fastapi import status

os.environ["PYTEST_CURRENT_TEST"] = "test_status_api"
os.environ["USE_MOCK_DB"] = "true"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestStatusAPIValidation:
    """Test Status API validation and authorization"""

    def test_post_status_upload_success(self):
        """Test POST /status/upload returns 200 and file_key exists"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils

        mock_user = "507f1f77bcf86cd799439011"  # Mock user ID
        mock_file_content = b"fake_image_content_for_testing"
        
        mock_status_collection = AsyncMock()
        mock_status_collection.insert_one = AsyncMock(return_value=Mock(inserted_id="507f1f77bcf86cd799439012"))
        
        async def override_get_database():
            return Mock()
        
        async def override_get_status_collection():
            return mock_status_collection
        
        def override_get_current_user():
            return mock_user
        
        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[status_module.get_status_collection] = override_get_status_collection
        app.dependency_overrides[auth_utils.get_current_user] = override_get_current_user
        
        with patch('backend.routes.status.upload_file_to_s3', return_value="status/test_user/12345.jpg"):
            client = TestClient(app)
            # Create a mock file
            file_content = io.BytesIO(mock_file_content)
            
            response = client.post(
                "/api/v1/status/upload",
                files={"file": ("test.jpg", file_content, "image/jpeg")},
                headers={"Authorization": "Bearer mock_token"}
            )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "uploadId" in response_data or "upload_id" in response_data
        assert "file_key" in response_data
        assert response_data.get("uploadId") or response_data.get("upload_id") == "status/test_user/12345.jpg"
        assert response_data.get("file_key") == "status/test_user/12345.jpg"
        print("✅ POST /status/upload test passed - file_key returned correctly")
    
    def test_post_status_upload_invalid_file_type(self):
        """Test POST /status/upload with invalid file type returns 400"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils
        
        mock_user = "507f1f77bcf86cd799439011"
        mock_status_collection = AsyncMock()
        
        async def override_get_database():
            return Mock()
        
        async def override_get_status_collection():
            return mock_status_collection
        
        def override_get_current_user():
            return mock_user
        
        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[status_module.get_status_collection] = override_get_status_collection
        app.dependency_overrides[auth_utils.get_current_user] = override_get_current_user
        
        client = TestClient(app)
        # Create a mock file with invalid type
        file_content = io.BytesIO(b"fake_file_content")
        
        response = client.post(
            "/api/v1/status/upload",
            files={"file": ("test.txt", file_content, "text/plain")},
            headers={"Authorization": "Bearer mock_token"}
        )
        
        assert response.status_code == 400
        assert "File type text/plain not supported" in response.json()["detail"]
        print("✅ POST /status/upload invalid file type test passed")
    
    def test_get_status_returns_uploaded_item(self):
        """Test GET /status returns uploaded items"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils
        
        mock_user = "507f1f77bcf86cd799439011"
        
        # Mock status documents
        mock_statuses = [
            {
                "_id": ObjectId("507f1f77bcf86cd799439015"),
                "user_id": "other_user_1",
                "text": "Status 1",
                "file_key": "status/other_user_1/abc123.jpg",
                "file_type": "image",
                "duration": None,
                "created_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
                "views": 5
            },
            {
                "_id": ObjectId("507f1f77bcf86cd799439016"), 
                "user_id": "other_user_2",
                "text": "Status 2",
                "file_key": None,
                "file_type": None,
                "duration": None,
                "created_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
                "views": 3
            }
        ]
        
        mock_cursor = AsyncMock()
        mock_cursor.sort = AsyncMock(return_value=mock_cursor)
        mock_cursor.skip = AsyncMock(return_value=mock_cursor)
        mock_cursor.limit = AsyncMock(return_value=mock_cursor)
        mock_cursor.to_list = AsyncMock(return_value=mock_statuses)
        
        mock_status_collection = AsyncMock()
        mock_status_collection.find = AsyncMock(return_value=mock_cursor)
        mock_status_collection.count_documents = AsyncMock(return_value=2)
        
        async def override_get_database():
            return Mock()
        
        async def override_get_status_collection():
            return mock_status_collection
        
        def override_get_current_user():
            return mock_user
        
        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[status_module.get_status_collection] = override_get_status_collection
        app.dependency_overrides[auth_utils.get_current_user] = override_get_current_user
        
        client = TestClient(app)
        response = client.get(
            "/api/v1/status",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "statuses" in response_data
        assert len(response_data["statuses"]) == 2
        assert response_data["total"] == 2
        assert response_data["has_more"] == False
        
        # Check that statuses have proper fields
        status1 = response_data["statuses"][0]
        assert "file_url" in status1
        assert status1["file_type"] == "image"
        assert status1["views"] == 5
        
        status2 = response_data["statuses"][1]
        assert status2["text"] == "Status 2"
        assert status2["file_type"] is None
        assert status2["views"] == 3
        
        print("✅ GET /status returns uploaded items test passed")


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"])
