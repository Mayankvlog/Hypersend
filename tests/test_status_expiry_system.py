"""
Test suite for 24-hour status expiry system
Tests validation and input handling
"""

import os
import pytest
import io
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock
from bson import ObjectId

if os.getenv("SKIP_STATUS_EXPIRY_TESTS", "false").lower() == "true":
    pytest.skip("Informational/print-only module", allow_module_level=True)

os.environ["PYTEST_CURRENT_TEST"] = "test_status_expiry"
os.environ["USE_MOCK_DB"] = "true"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestStatusExpiryValidation:
    """Test status expiry validation"""

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
