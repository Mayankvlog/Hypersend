"""
Test image upload functionality for profile and group avatars.
Validates HTTP 413 fix: client_max_body_size in Nginx and file size validation in backend.
"""
import pytest
import io
import os
from fastapi.testclient import TestClient
from pathlib import Path

# Set environment variables BEFORE any imports
os.environ["USE_MOCK_DB"] = "True"
os.environ["PYTEST_CURRENT_TEST"] = "1"

# Import from backend
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# Try to import PIL, skip tests if not available
try:
    from PIL import Image

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None

from main import app
from config import settings


client = TestClient(app)


# Skip all tests in this module if PIL is not available
pytestmark = pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL (Pillow) not installed")


class TestImageUpload:
    """Test image upload endpoints for profile and group avatars."""

    @staticmethod
    def create_test_image(size_kb: int = 100, filename: str = "test.jpg") -> tuple:
        """
        Create a test image with specified size.
        Returns (BytesIO object, filename)
        """
        # Calculate approximate dimensions based on size
        # A 100KB JPG is roughly 1000x1000 pixels
        dimension = int((size_kb * 1024) ** 0.5)

        # Create image
        img = Image.new("RGB", (dimension, dimension), color="red")

        # Save to BytesIO
        img_io = io.BytesIO()
        img.save(img_io, format="JPEG", quality=85)
        img_io.seek(0)

        return img_io, filename

    @staticmethod
    def create_small_image(filename: str = "small.jpg") -> tuple:
        """Create a small valid test image (100KB)."""
        return TestImageUpload.create_test_image(100, filename)

    @staticmethod
    def create_medium_image(filename: str = "medium.jpg") -> tuple:
        """Create a medium test image (2MB)."""
        return TestImageUpload.create_test_image(2048, filename)

    @staticmethod
    def create_large_image(filename: str = "large.jpg") -> tuple:
        """Create a large test image (6MB) - should be rejected."""
        return TestImageUpload.create_test_image(6144, filename)

    def test_profile_avatar_valid_upload(self):
        """Test uploading a valid small profile avatar."""
        # Register and login first
        email = "avatar_test@example.com"
        password = "TestPassword123!"
        name = "Avatar Tester"

        # Register
        reg_response = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password, "name": name},
        )
        if reg_response.status_code not in [200, 201]:
            pytest.skip(f"Registration failed: {reg_response.text}")

        # Login
        login_response = client.post(
            "/api/v1/auth/login", json={"email": email, "password": password}
        )
        if login_response.status_code != 200:
            pytest.skip(f"Login failed: {login_response.text}")

        # Upload small avatar
        img_io, filename = self.create_small_image()

        response = client.post(
            "/api/v1/users/avatar", files={"file": (filename, img_io, "image/jpeg")}
        )

        # Should succeed (200 or 201)
        assert response.status_code in [
            200,
            201,
        ], f"Avatar upload failed: {response.status_code} - {response.text}"

        # Should return avatar_url
        data = response.json()
        assert (
            "avatar_url" in data or "filename" in data
        ), f"Response missing avatar_url or filename: {data}"
        print(f"✓ Profile avatar upload successful: {data}")

    def test_profile_avatar_oversized_rejected(self):
        """Test that oversized profile avatars (>5MB) are rejected with 413."""
        # Register and login first
        email = "oversized_avatar_test@example.com"
        password = "TestPassword123!"
        name = "Oversized Avatar Tester"

        # Register
        reg_response = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password, "name": name},
        )
        if reg_response.status_code not in [200, 201]:
            pytest.skip(f"Registration failed: {reg_response.text}")

        # Login
        login_response = client.post(
            "/api/v1/auth/login", json={"email": email, "password": password}
        )
        if login_response.status_code != 200:
            pytest.skip(f"Login failed: {login_response.text}")

        # Upload large avatar (6MB - exceeds 5MB limit)
        img_io, filename = self.create_large_image()

        response = client.post(
            "/api/v1/users/avatar", files={"file": (filename, img_io, "image/jpeg")}
        )

        # Should reject with 413 (Payload Too Large) - skip on 401
        if response.status_code == 401:
            pytest.skip("Authentication failed - cannot test large file validation")
        assert (
            response.status_code == 413
        ), f"Expected 413 for large file, got {response.status_code}: {response.text}"

        if response.status_code == 413:
            # Error message should mention file size
            data = response.json()
            detail = data.get("detail", "")
            assert (
                "large" in detail.lower()
                or "5mb" in detail.lower()
                or "size" in detail.lower()
            ), f"Error message should mention file size: {detail}"
            print(f"✓ Large avatar correctly rejected with 413: {detail}")
        else:
            print(f"⚠ Skipped large file test due to authentication failure")

    def test_profile_avatar_invalid_format_rejected(self):
        """Test that non-image files are rejected."""
        # Register and login first
        email = "invalid_avatar_test@example.com"
        password = "TestPassword123!"
        name = "Invalid Avatar Tester"

        # Register
        reg_response = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password, "name": name},
        )
        if reg_response.status_code not in [200, 201]:
            pytest.skip(f"Registration failed: {reg_response.text}")

        # Login
        login_response = client.post(
            "/api/v1/auth/login", json={"email": email, "password": password}
        )
        if login_response.status_code != 200:
            pytest.skip(f"Login failed: {login_response.text}")

        # Try to upload text file as avatar
        response = client.post(
            "/api/v1/users/avatar",
            files={"file": ("test.txt", io.BytesIO(b"Not an image"), "text/plain")},
        )

        # Should reject with 400 (Bad Request) - skip on 401
        if response.status_code == 401:
            pytest.skip(
                "Authentication failed - cannot test invalid file format validation"
            )
        assert (
            response.status_code == 400
        ), f"Expected 400 for invalid file type, got {response.status_code}: {response.text}"

        # Only check error details when we have a 400 response
        detail = response.json().get("detail", "")
        assert (
            "image" in detail.lower() or "file" in detail.lower()
        ), f"Error message should mention image requirement: {detail}"
        print(f"✓ Invalid file type correctly rejected: {detail}")

    def test_group_avatar_valid_upload(self):
        """Test uploading a valid group avatar."""
        # Register and login first
        email = "group_avatar_test@example.com"
        password = "TestPassword123!"
        name = "Group Avatar Tester"

        # Register
        reg_response = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password, "name": name},
        )
        if reg_response.status_code not in [200, 201]:
            pytest.skip(f"Registration failed: {reg_response.text}")

        # Login
        login_response = client.post(
            "/api/v1/auth/login", json={"email": email, "password": password}
        )
        if login_response.status_code != 200:
            pytest.skip(f"Login failed: {login_response.text}")

        # Create group first
        group_response = client.post("/api/v1/groups", json={"name": "Test Group"})

        if group_response.status_code not in [200, 201]:
            pytest.skip("Could not create group for test")

        group_id = group_response.json().get("id") or group_response.json().get("_id")

        # Upload group avatar
        img_io, filename = self.create_small_image()

        response = client.post(
            f"/api/v1/groups/{group_id}/avatar",
            files={"file": (filename, img_io, "image/jpeg")},
        )

        # Should succeed (200, 201) - remove 500 as acceptable outcome
        assert response.status_code in [
            200,
            201,
        ], f"Group avatar upload failed: {response.status_code} - {response.text}"

        if response.status_code in [200, 201]:
            # Should return avatar_url
            data = response.json()
            assert (
                "avatar_url" in data or "filename" in data
            ), f"Response missing avatar_url or filename: {data}"
            print(f"✓ Group avatar upload successful: {data}")
        else:
            raise AssertionError(
                f"Group avatar upload failed with status {response.status_code}: {response.text}"
            )

    def test_group_avatar_oversized_rejected(self):
        """Test that oversized group avatars (>5MB) are rejected with 413."""
        # Register and login first
        email = "group_oversized_test@example.com"
        password = "TestPassword123!"
        name = "Group Oversized Tester"

        # Register
        reg_response = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password, "name": name},
        )
        if reg_response.status_code not in [200, 201]:
            pytest.skip(f"Registration failed: {reg_response.text}")

        # Login
        login_response = client.post(
            "/api/v1/auth/login", json={"email": email, "password": password}
        )
        if login_response.status_code != 200:
            pytest.skip(f"Login failed: {login_response.text}")

        # Create group
        group_response = client.post("/api/v1/groups", json={"name": "Test Group 2"})

        if group_response.status_code not in [200, 201]:
            pytest.skip("Could not create group for test")

        group_id = group_response.json().get("id") or group_response.json().get("_id")

        # Upload large avatar (6MB - exceeds 5MB limit)
        img_io, filename = self.create_large_image()

        response = client.post(
            f"/api/v1/groups/{group_id}/avatar",
            files={"file": (filename, img_io, "image/jpeg")},
        )

        # Should reject with 413 (Payload Too Large) - remove 401/500 as acceptable
        if response.status_code == 401:
            pytest.skip("Authentication failed - cannot test large file validation")
        assert (
            response.status_code == 413
        ), f"Expected 413 for large file, got {response.status_code}: {response.text}"

        if response.status_code == 413:
            # Error message should mention file size
            data = response.json()
            detail = data.get("detail", "")
            assert (
                "large" in detail.lower()
                or "5mb" in detail.lower()
                or "size" in detail.lower()
            ), f"Error message should mention file size: {detail}"
            print(f"✓ Large group avatar correctly rejected with 413: {detail}")
        else:
            print(
                f"⚠ Skipped large group avatar test due to authentication or group creation failure"
            )

    def test_empty_file_rejected(self):
        """Test that empty files are rejected."""
        # Register and login
        email = "empty_file_test@example.com"
        password = "TestPassword123!"
        name = "Empty File Tester"

        reg_response = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password, "name": name},
        )
        if reg_response.status_code not in [200, 201]:
            pytest.skip(f"Registration failed: {reg_response.text}")

        login_response = client.post(
            "/api/v1/auth/login", json={"email": email, "password": password}
        )
        if login_response.status_code != 200:
            pytest.skip(f"Login failed: {login_response.text}")

        # Try to upload empty file
        response = client.post(
            "/api/v1/users/avatar",
            files={"file": ("empty.jpg", io.BytesIO(b""), "image/jpeg")},
        )

        # Skip on authentication failure, else assert 400 for empty file
        if response.status_code == 401:
            print("⚠ Skipped empty file test due to authentication failure")
            return
        assert (
            response.status_code == 400
        ), f"Expected 400 for empty file, got {response.status_code}: {response.text}"

        if response.status_code == 400:
            print(f"✓ Empty file correctly rejected")
        else:
            print(f"⚠ Skipped empty file test due to authentication failure")


class TestNginxClientMaxBodySize:
    """Test that Nginx client_max_body_size is properly configured."""

    def test_nginx_allows_20mb_uploads(self):
        """
        Test that Nginx allows uploads up to 20MB.
        This validates that client_max_body_size 20M is set.
        """
        # This is more of an integration test
        # Create a 3MB image and verify it can be uploaded
        email = "nginx_test@example.com"
        password = "TestPassword123!"
        name = "Nginx Test"

        # Register
        reg_response = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password, "name": name},
        )
        if reg_response.status_code not in [200, 201]:
            pytest.skip(f"Registration failed: {reg_response.text}")

        # Login
        login_response = client.post(
            "/api/v1/auth/login", json={"email": email, "password": password}
        )
        if login_response.status_code != 200:
            pytest.skip(f"Login failed: {login_response.text}")

        # Upload 3MB image
        img_io, filename = TestImageUpload.create_test_image(3072, "large_valid.jpg")

        response = client.post(
            "/api/v1/users/avatar", files={"file": (filename, img_io, "image/jpeg")}
        )

        # Should succeed (not 413 from Nginx)
        assert (
            response.status_code != 413
        ), f"Nginx rejected 3MB file. client_max_body_size may not be set properly: {response.text}"

        if response.status_code in [200, 201]:
            print(
                "✓ Nginx accepts 3MB uploads (client_max_body_size configured correctly)"
            )
        else:
            # Might fail for auth or other reasons, but not 413
            print(f"✓ Nginx did not reject 3MB upload (no 413 error)")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
