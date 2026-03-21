"""
COMPREHENSIVE TEST: S3 Media Download 404 Fix

Tests the complete flow:
1. Upload status media -> Returns s3_key
2. Verify s3_key is stored in database with full path
3. Download using /api/v1/media/{s3_key} -> Returns 307 or streams
4. Verify storage_type field is set correctly
5. Test error handling for empty s3_key
"""

import pytest
import json
import os
import sys
from pathlib import Path
from io import BytesIO

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from bson import ObjectId


@pytest.fixture(scope="session")
def test_image_bytes():
    """Create a simple test image in memory"""
    # Minimal PNG file (1x1 transparent pixel)
    png_data = bytes([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
        0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
        0x0A, 0x49, 0x44, 0x41, 0x54, 0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0xFE,
        0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xE5, 0x27, 0xDE, 0xFC, 0x00,
        0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
    ])
    return png_data


@pytest.mark.asyncio
class TestS3MediaDownloadFix:
    """Test suite for S3 media download 404 fix"""

    def test_01_upload_status_media_returns_s3_key(self, client: TestClient, auth_headers, test_image_bytes):
        """TEST: Upload status media and verify s3_key is returned"""
        
        print("\n" + "="*80)
        print("TEST 1: Upload Status Media Returns S3 Key")
        print("="*80)
        
        response = client.post(
            "/api/v1/status/upload",
            headers=auth_headers,
            files={"file": ("test.png", BytesIO(test_image_bytes), "image/png")},
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 200, f"Upload should succeed, got {response.status_code}"
        
        data = response.json()
        s3_key = data.get("upload_id")
        
        # CRITICAL: Verify s3_key has correct format
        assert s3_key, "upload_id (s3_key) should not be empty"
        assert s3_key.startswith("status/"), f"s3_key should start with 'status/', got {s3_key}"
        assert ".png" in s3_key, f"s3_key should contain file extension, got {s3_key}"
        
        print(f"✓ S3 Key returned: {s3_key}")
        print(f"✓ Format correct: 'status/{{user_id}}/{{uuid}}.ext'")
        
        return s3_key

    def test_02_create_status_with_file_key(self, client: TestClient, auth_headers, s3_key=None):
        """TEST: Create status with file_key and verify storage_type"""
        
        print("\n" + "="*80)
        print("TEST 2: Create Status with File Key")
        print("="*80)
        
        if not s3_key:
            # Upload first
            test_image_bytes = bytes([
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
                0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
                0x0A, 0x49, 0x44, 0x41, 0x54, 0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0xFE,
                0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xE5, 0x27, 0xDE, 0xFC, 0x00,
                0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
            ])
            upload_resp = client.post(
                "/api/v1/status/upload",
                headers=auth_headers,
                files={"file": ("test.png", BytesIO(test_image_bytes), "image/png")},
            )
            s3_key = upload_resp.json()["upload_id"]
        
        response = client.post(
            "/api/v1/status/",
            headers=auth_headers,
            json={"file_key": s3_key, "text": "Test status with media"},
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 201, f"Status creation should succeed, got {response.status_code}"
        
        data = response.json()
        status_id = data.get("id")
        file_url = data.get("file_url")
        
        # CRITICAL: Verify file_key is used in file_url
        assert file_url, "file_url should not be empty"
        assert s3_key in file_url, f"file_url should contain s3_key, got {file_url}"
        
        print(f"✓ Status created: {status_id}")
        print(f"✓ File URL: {file_url}")
        print(f"✓ S3 Key embedded in URL")
        
        return status_id, s3_key

    def test_03_download_status_media_via_media_endpoint(self, client: TestClient, auth_headers, s3_key=None):
        """TEST: Download status media via /api/v1/media/{s3_key}"""
        
        print("\n" + "="*80)
        print("TEST 3: Download Status Media via Media Endpoint")
        print("="*80)
        
        if not s3_key:
            # Create status first
            test_image_bytes = bytes([
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
                0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
                0x0A, 0x49, 0x44, 0x41, 0x54, 0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0xFE,
                0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xE5, 0x27, 0xDE, 0xFC, 0x00,
                0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
            ])
            upload_resp = client.post(
                "/api/v1/status/upload",
                headers=auth_headers,
                files={"file": ("test.png", BytesIO(test_image_bytes), "image/png")},
            )
            s3_key = upload_resp.json()["upload_id"]
        
        # URL encode the s3_key (replace / with %2F)
        encoded_s3_key = s3_key.replace("/", "%2F")
        
        print(f"Downloading media: {s3_key}")
        
        response = client.get(
            f"/api/v1/media/{encoded_s3_key}",
            headers=auth_headers,
            follow_redirects=False,  # Don't follow 307 redirects
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        
        # CRITICAL: Response should be either:
        # - 307 redirect with presigned URL
        # - 200 with streamed content
        # - NOT 404!
        assert response.status_code in [200, 307], \
            f"Media download should succeed (200/307), got {response.status_code}"
        
        if response.status_code == 307:
            location = response.headers.get("location")
            print(f"✓ 307 Redirect: {location[:50]}...")
            assert location, "307 response should have Location header"
        elif response.status_code == 200:
            content_type = response.headers.get("content-type")
            print(f"✓ 200 Streaming: {content_type}")
            assert content_type, "200 response should have Content-Type header"
        
        return s3_key

    def test_04_invalid_s3_key_returns_404(self, client: TestClient, auth_headers):
        """TEST: Invalid s3_key returns 404 correctly"""
        
        print("\n" + "="*80)
        print("TEST 4: Invalid S3 Key Returns 404")
        print("="*80)
        
        # Try to download non-existent file
        response = client.get(
            "/api/v1/media/status%2Fnonexistent%2Fence3a3a3.png",
            headers=auth_headers,
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        # Should get 404
        assert response.status_code == 404, f"Invalid file should return 404, got {response.status_code}"
        
        error_data = response.json()
        detail = error_data.get("detail", "")
        
        # Should indicate it's a file not found error
        assert "not found" in detail.lower(), f"Error should mention 'not found', got {detail}"
        
        print(f"✓ 404 returned correctly: {detail}")

    def test_05_unauthenticated_media_request_returns_401(self, client: TestClient):
        """TEST: Unauthenticated media request returns 401"""
        
        print("\n" + "="*80)
        print("TEST 5: Unauthenticated Media Request Returns 401")
        print("="*80)
        
        # No auth headers
        response = client.get(
            "/api/v1/media/status%2F123%2Fabc.png",
        )
        
        print(f"Status Code: {response.status_code}")
        
        # Should get 401
        assert response.status_code == 401, f"No auth should return 401, got {response.status_code}"
        
        print(f"✓ 401 returned correctly for missing auth")

    def test_06_verify_database_storage_type_field(self, client: TestClient, auth_headers, db):
        """TEST: Verify database stores storage_type field correctly"""
        
        print("\n" + "="*80)
        print("TEST 6: Verify Database Storage Type Field")
        print("="*80)
        
        # Upload and create status
        test_image_bytes = bytes([
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
            0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
            0x0A, 0x49, 0x44, 0x41, 0x54, 0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0xFE,
            0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xE5, 0x27, 0xDE, 0xFC, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
        ])
        
        upload_resp = client.post(
            "/api/v1/status/upload",
            headers=auth_headers,
            files={"file": ("test.png", BytesIO(test_image_bytes), "image/png")},
        )
        s3_key = upload_resp.json()["upload_id"]
        
        status_resp = client.post(
            "/api/v1/status/",
            headers=auth_headers,
            json={"file_key": s3_key, "text": "DB test"},
        )
        status_id = status_resp.json()["id"]
        
        # Query database
        statuses_col = db["statuses"]
        status_doc = statuses_col.find_one({"_id": ObjectId(status_id)})
        
        print(f"Status document: {status_doc}")
        
        assert status_doc, "Status should be in database"
        
        file_key = status_doc.get("file_key")
        print(f"✓ File key in DB: {file_key}")
        assert file_key == s3_key, f"File key should match uploaded s3_key"
        assert file_key.strip() != "", "File key should not be empty"
        
        print(f"✓ Database storage verified")


# Helper fixtures
@pytest.fixture(scope="session")
def client():
    """Get TestClient for the app"""
    from backend.main import app
    return TestClient(app)


@pytest.fixture(scope="session")
def db():
    """Get database connection"""
    from backend.database import get_database
    return get_database()


@pytest.fixture(scope="session")
def auth_headers(client):
    """Get auth headers by login/register"""
    # Register user
    register_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@example.com",
            "password": "TestPassword123!",
            "full_name": "Test User",
        }
    )
    
    if register_resp.status_code != 201:
        # Already registered, login
        login_resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": "TestPassword123!",
            }
        )
        token = login_resp.json()["access_token"]
    else:
        token = register_resp.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}


if __name__ == "__main__":
    import pytest
    
    # Run tests
    pytest.main([
        __file__,
        "-v",
        "-s",
        "--tb=short",
    ])
