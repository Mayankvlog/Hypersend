"""
Test suite for Status API endpoints
Tests validation, authorization, and input handling
"""

import pytest
import os
import sys
import io
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock
from bson import ObjectId

os.environ["PYTEST_CURRENT_TEST"] = "test_status_api"
os.environ["USE_MOCK_DB"] = "true"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestStatusAPIValidation:
    """Test Status API validation and authorization"""

    def test_create_status_missing_content(self):
        """Test status creation with missing content"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils

        mock_user = {
            "_id": ObjectId("507f1f77bcf86cd799439011"),
            "email": "testuser@example.com",
            "name": "Test User",
        }

        async def override_get_database():
            return MagicMock()

        async def override_get_status_collection():
            return MagicMock()

        def override_get_current_user():
            return mock_user

        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[
            status_module.get_status_collection
        ] = override_get_status_collection
        app.dependency_overrides[
            auth_utils.get_current_user
        ] = override_get_current_user

        try:
            client = TestClient(app)

            status_data = {}
            response = client.post(
                "/api/v1/status/",
                json=status_data,
                headers={"Authorization": "Bearer test_token"},
            )

            assert response.status_code in [
                400,
                422,
            ], f"Expected 400/422, got {response.status_code}: {response.text}"
        finally:
            app.dependency_overrides.clear()

    def test_upload_status_media_invalid_type(self):
        """Test status media upload with invalid file type"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils

        mock_user = {
            "_id": ObjectId("507f1f77bcf86cd799439011"),
            "email": "testuser@example.com",
            "name": "Test User",
        }

        async def override_get_database():
            return MagicMock()

        async def override_get_status_collection():
            return MagicMock()

        def override_get_current_user():
            return mock_user

        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[
            status_module.get_status_collection
        ] = override_get_status_collection
        app.dependency_overrides[
            auth_utils.get_current_user
        ] = override_get_current_user

        try:
            client = TestClient(app)

            mock_file = io.BytesIO(b"fake_file_content")
            response = client.post(
                "/api/v1/status/upload",
                files={"file": ("test.txt", mock_file, "text/plain")},
                headers={"Authorization": "Bearer test_token"},
            )

            assert (
                response.status_code == 400
            ), f"Expected 400, got {response.status_code}: {response.text}"
            assert "not supported" in response.json().get("detail", "").lower()
        finally:
            app.dependency_overrides.clear()

    def test_upload_status_media_too_large(self):
        """Test status media upload with file too large"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils

        mock_user = {
            "_id": ObjectId("507f1f77bcf86cd799439011"),
            "email": "testuser@example.com",
            "name": "Test User",
        }

        async def override_get_database():
            return MagicMock()

        async def override_get_status_collection():
            return MagicMock()

        def override_get_current_user():
            return mock_user

        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[
            status_module.get_status_collection
        ] = override_get_status_collection
        app.dependency_overrides[
            auth_utils.get_current_user
        ] = override_get_current_user

        try:
            client = TestClient(app)

            mock_file = io.BytesIO(b"x" * (17 * 1024 * 1024))
            response = client.post(
                "/api/v1/status/upload",
                files={"file": ("large.jpg", mock_file, "image/jpeg")},
                headers={"Authorization": "Bearer test_token"},
            )

            assert (
                response.status_code == 413
            ), f"Expected 413, got {response.status_code}: {response.text}"
            assert "too large" in response.json().get("detail", "").lower()
        finally:
            app.dependency_overrides.clear()

    def test_get_user_statuses_invalid_id(self):
        """Test get user statuses with invalid user ID"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils
        from unittest.mock import AsyncMock

        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "email": "testuser@example.com",
            "name": "Test User",
        }

        # Create proper mock database with __getitem__
        mock_db = MagicMock()
        mock_status_collection = AsyncMock()
        
        def getitem_side_effect(key):
            if key == "statuses":
                return mock_status_collection
            raise KeyError(f"Collection '{key}' not found in mock database")
        
        mock_db.__getitem__ = MagicMock(side_effect=getitem_side_effect)

        async def override_get_database():
            return mock_db

        async def override_get_status_collection():
            return mock_status_collection

        def override_get_current_user():
            return mock_user

        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[
            status_module.get_status_collection
        ] = override_get_status_collection
        app.dependency_overrides[
            auth_utils.get_current_user
        ] = override_get_current_user

        try:
            client = TestClient(app)

            response = client.get(
                "/api/v1/status/invalid_id",
                headers={"Authorization": "Bearer test_token"},
            )

            assert (
                response.status_code == 400
            ), f"Expected 400, got {response.status_code}: {response.text}"
            assert "Invalid user ID format" in response.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    def test_delete_status_unauthorized(self):
        """Test status deletion without authentication"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from unittest.mock import AsyncMock

        # Create proper mock database with __getitem__
        mock_db = MagicMock()
        mock_status_collection = AsyncMock()
        
        def getitem_side_effect(key):
            if key == "statuses":
                return mock_status_collection
            raise KeyError(f"Collection '{key}' not found in mock database")
        
        mock_db.__getitem__ = MagicMock(side_effect=getitem_side_effect)

        async def override_get_database():
            return mock_db

        async def override_get_status_collection():
            return mock_status_collection

        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[
            status_module.get_status_collection
        ] = override_get_status_collection

        try:
            client = TestClient(app)

            status_id = "507f1f77bcf86cd799439014"
            response = client.delete(f"/api/v1/status/{status_id}")

            assert (
                response.status_code == 401
            ), f"Expected 401, got {response.status_code}: {response.text}"
        finally:
            app.dependency_overrides.clear()


class TestStatusExpiryValidation:
    """Test Status expiry validation"""

    def test_status_requires_text_or_file(self):
        """Test that status must have either text or file_key"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils

        mock_user = {
            "_id": ObjectId("507f1f77bcf86cd799439011"),
            "username": "testuser",
            "email": "test@example.com",
        }

        async def override_get_database():
            return MagicMock()

        async def override_get_status_collection():
            return MagicMock()

        def override_get_current_user():
            return mock_user

        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[
            status_module.get_status_collection
        ] = override_get_status_collection
        app.dependency_overrides[
            auth_utils.get_current_user
        ] = override_get_current_user

        try:
            client = TestClient(app)

            response = client.post(
                "/api/v1/status/", json={"text": None, "file_key": None}
            )

            assert response.status_code in [
                400,
                422,
            ], f"Should reject empty status: {response.text}"
        finally:
            app.dependency_overrides.clear()

    def test_status_empty_text_rejected(self):
        """Test that empty/whitespace-only text is rejected"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils

        mock_user = {
            "_id": ObjectId("507f1f77bcf86cd799439011"),
            "username": "testuser",
            "email": "test@example.com",
        }

        async def override_get_database():
            return MagicMock()

        async def override_get_status_collection():
            return MagicMock()

        def override_get_current_user():
            return mock_user

        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[
            status_module.get_status_collection
        ] = override_get_status_collection
        app.dependency_overrides[
            auth_utils.get_current_user
        ] = override_get_current_user

        try:
            client = TestClient(app)

            response = client.post(
                "/api/v1/status/", json={"text": "   ", "file_key": None}
            )

            assert response.status_code in [
                400,
                422,
            ], f"Should reject empty text: {response.text}"
        finally:
            app.dependency_overrides.clear()

    def test_status_max_text_length(self):
        """Test status text max length validation"""
        from fastapi.testclient import TestClient
        from backend.main import app
        from backend.routes import status as status_module
        from backend.auth import utils as auth_utils

        mock_user = {
            "_id": ObjectId("507f1f77bcf86cd799439011"),
            "username": "testuser",
            "email": "test@example.com",
        }

        async def override_get_database():
            return MagicMock()

        async def override_get_status_collection():
            return MagicMock()

        def override_get_current_user():
            return mock_user

        app.dependency_overrides[status_module.get_database] = override_get_database
        app.dependency_overrides[
            status_module.get_status_collection
        ] = override_get_status_collection
        app.dependency_overrides[
            auth_utils.get_current_user
        ] = override_get_current_user

        try:
            client = TestClient(app)

            text_501 = "a" * 501
            response = client.post("/api/v1/status/", json={"text": text_501})
            assert response.status_code in [400, 422], "Should reject 501+ char text"
        finally:
            app.dependency_overrides.clear()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
