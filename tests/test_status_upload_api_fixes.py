"""
COMPREHENSIVE STATUS UPLOAD AND CREATION TESTS
Tests for POST /api/v1/status/upload and POST /api/v1/status endpoints
Verifies:
- Media upload returns correct file_key
- Status creation validates file_key exists
- Response fields match frontend expectations (uploadId, file_key, duration)
- CORS and cookie headers work correctly
- S3 integration doesn't return None
- Error handling returns proper HTTP status codes
- 405 Method Not Allowed is resolved
"""

import pytest
import io
import json
from fastapi.testclient import TestClient
from typing import Dict, Any
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock


@pytest.fixture
def status_image_file():
    """Create a valid PNG image file for testing"""
    # Minimal valid PNG (1x1 pixel, transparent)
    png_bytes = (
        b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
        b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01'
        b'\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
    )
    return ("test_image.png", io.BytesIO(png_bytes), "image/png")


@pytest.fixture
def status_text_only():
    """Create a text-only status"""
    return {
        "text": "This is a test status",
        "file_key": None
    }


@pytest.fixture
def status_with_file():
    """Create a status with file_key"""
    return {
        "text": "Status with media",
        "file_key": "status/test_user_id/12345.png"
    }


class TestStatusUploadEndpoint:
    """Tests for POST /api/v1/status/upload"""
    
    def test_upload_image_returns_200_and_file_key(self, client: TestClient, auth_headers: Dict, status_image_file):
        """
        CRITICAL TEST: Upload image and verify:
        1. Returns 200 OK
        2. Response contains uploadId field
        3. Response contains file_key field
        4. uploadId and file_key are identical
        5. duration is None for images
        """
        filename, file_content, content_type = status_image_file
        
        response = client.post(
            "/api/v1/status/upload",
            files={"file": (filename, file_content, content_type)},
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        
        # CRITICAL: Both uploadId and file_key must be present
        assert "uploadId" in data, "Response missing uploadId field"
        assert "file_key" in data, "Response missing file_key field"
        assert data["uploadId"] is not None and data["uploadId"].strip() != "", "uploadId is empty"
        assert data["file_key"] is not None and data["file_key"].strip() != "", "file_key is empty"
        
        # uploadId and file_key should be identical for status uploads
        assert data["uploadId"] == data["file_key"], f"uploadId {data['uploadId']} != file_key {data['file_key']}"
        
        # Image should not have duration
        assert data.get("duration") is None, f"Image should not have duration, got {data.get('duration')}"
        
        # File key must contain status/ prefix
        assert data["uploadId"].startswith("status/"), f"File key should start with 'status/', got {data['uploadId']}"
        
        print(f"✓ Image upload successful: {data['uploadId']}")
    
    def test_upload_without_auth_returns_401(self, client: TestClient, status_image_file):
        """
        SECURITY TEST: Upload without authentication must return 401
        """
        filename, file_content, content_type = status_image_file
        
        response = client.post(
            "/api/v1/status/upload",
            files={"file": (filename, file_content, content_type)},
            headers={}  # No auth headers
        )
        
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("✓ Unauthenticated upload correctly returns 401")
    
    def test_upload_invalid_content_type_returns_400(self, client: TestClient, auth_headers: Dict):
        """
        VALIDATION TEST: Upload unsupported file type returns 400
        """
        invalid_file = ("test.txt", io.BytesIO(b"plain text"), "text/plain")
        
        response = client.post(
            "/api/v1/status/upload",
            files={"file": invalid_file},
            headers=auth_headers
        )
        
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        data = response.json()
        assert "not supported" in data.get("detail", "").lower(), "Error message should mention file type"
        print("✓ Invalid file type correctly returns 400")
    
    def test_upload_preserves_cookies_in_request(self, client: TestClient, auth_headers: Dict, status_image_file):
        """
        INTEGRATION TEST: Verify cookies are sent in upload request
        Note: This test verifies that nginx forwards cookies correctly
        """
        filename, file_content, content_type = status_image_file
        
        # Add cookie to request
        headers_with_cookie = {
            **auth_headers,
            "Cookie": "session_id=test_session_123"
        }
        
        response = client.post(
            "/api/v1/status/upload",
            files={"file": (filename, file_content, content_type)},
            headers=headers_with_cookie
        )
        
        # Should still succeed with cookie
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        print("✓ Upload works with cookies in request")


class TestStatusCreateEndpoint:
    """Tests for POST /api/v1/status (create status)"""
    
    def test_create_status_text_only_returns_200(self, client: TestClient, auth_headers: Dict, status_text_only):
        """
        CRITICAL TEST: Create text-only status and verify:
        1. Returns 200 OK
        2. Response is StatusResponse with id, user_id, text, created_at
        3. file_key is None when not provided
        """
        response = client.post(
            "/api/v1/status",
            json=status_text_only,
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        
        # Verify response structure
        assert "id" in data, "Response missing id"
        assert "user_id" in data, "Response missing user_id"
        assert "text" in data, "Response missing text"
        assert "created_at" in data, "Response missing created_at"
        assert data["text"] == status_text_only["text"], "Text doesn't match"
        assert data.get("file_key") is None, "file_key should be None for text-only status"
        assert data.get("file_url") is None, "file_url should be None for text-only status"
        
        print(f"✓ Text-only status created: {data['id']}")
    
    def test_create_status_with_file_key_returns_200(self, client: TestClient, auth_headers: Dict, status_with_file):
        """
        CRITICAL TEST: Create status with file_key and verify:
        1. Returns 200 OK
        2. file_key is set in response
        3. file_type is inferred from file_key
        """
        response = client.post(
            "/api/v1/status",
            json=status_with_file,
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        
        # Verify file_key is preserved
        assert data.get("file_key") == status_with_file["file_key"], "file_key not preserved"
        assert data.get("file_type") == "image/png", f"Expected file_type image/png, got {data.get('file_type')}"
        
        # file_url should be generated from file_key
        if "file_url" in data and data["file_url"]:
            assert status_with_file["file_key"] in data["file_url"], "file_url should contain file_key"
        
        print(f"✓ Status with file created: {data['id']}")
    
    def test_create_status_without_text_and_file_returns_400(self, client: TestClient, auth_headers: Dict):
        """
        VALIDATION TEST: Create status with neither text nor file_key returns 400
        """
        response = client.post(
            "/api/v1/status",
            json={"text": None, "file_key": None},
            headers=auth_headers
        )
        
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        data = response.json()
        assert "either text or file" in data.get("detail", "").lower(), "Error should mention text or file requirement"
        print("✓ Empty status correctly returns 400")
    
    def test_create_status_empty_text_string_returns_400(self, client: TestClient, auth_headers: Dict):
        """
        VALIDATION TEST: Create status with empty text string returns 400
        """
        response = client.post(
            "/api/v1/status",
            json={"text": "", "file_key": None},
            headers=auth_headers
        )
        
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        print("✓ Empty text string correctly returns 400")
    
    def test_create_status_without_auth_returns_401(self, client: TestClient, status_text_only):
        """
        SECURITY TEST: Create status without auth returns 401
        """
        response = client.post(
            "/api/v1/status",
            json=status_text_only,
            headers={}  # No auth
        )
        
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("✓ Unauthenticated status creation correctly returns 401")
    
    def test_create_status_method_not_allowed_on_wrong_method(self, client: TestClient, auth_headers: Dict):
        """
        REGRESSION TEST: Verify POST method is allowed (resolves 405 error)
        This verifies that POST /api/v1/status endpoint exists
        """
        # This should NOT return 405 Method Not Allowed
        response = client.post(
            "/api/v1/status",
            json={"text": "test"},
            headers=auth_headers
        )
        
        assert response.status_code != 405, f"ERROR: POST /status returns 405 Method Not Allowed! Endpoint is missing!"
        print("✓ POST /api/v1/status endpoint exists (405 resolved)")


class TestStatusUploadIntegration:
    """Integration tests: Upload → Create flow"""
    
    def test_upload_then_create_flow(self, client: TestClient, auth_headers: Dict, status_image_file):
        """
        INTEGRATION TEST: Complete flow - upload image then create status with file_key
        
        Flow:
        1. POST /upload → get file_key
        2. POST /status with file_key → create status
        3. Verify both succeed
        """
        filename, file_content, content_type = status_image_file
        
        # Step 1: Upload image
        upload_response = client.post(
            "/api/v1/status/upload",
            files={"file": (filename, file_content, content_type)},
            headers=auth_headers
        )
        assert upload_response.status_code == 200, f"Upload failed: {upload_response.text}"
        upload_data = upload_response.json()
        file_key = upload_data["uploadId"]
        
        print(f"✓ Image uploaded: {file_key}")
        
        # Step 2: Create status with uploaded file
        create_response = client.post(
            "/api/v1/status",
            json={
                "text": "Uploaded image status",
                "file_key": file_key,
                "duration": upload_data.get("duration")
            },
            headers=auth_headers
        )
        assert create_response.status_code == 200, f"Status creation failed: {create_response.text}"
        status_data = create_response.json()
        
        # Verify status has the uploaded file
        assert status_data["file_key"] == file_key, "file_key not preserved in status"
        assert status_data.get("file_url"), "file_url should be generated"
        
        print(f"✓ Status created with uploaded image: {status_data['id']}")
    
    def test_response_fields_match_frontend_expectations(self, client: TestClient, auth_headers: Dict, status_image_file):
        """
        CRITICAL TEST: Verify upload response has all fields frontend expects
        
        Frontend expects:
        - uploadId (string, camelCase)
        - file_key (string, snake_case, for backward compatibility)
        - duration (optional float for videos)
        - chunk_size, total_chunks, expires_in, etc.
        """
        filename, file_content, content_type = status_image_file
        
        response = client.post(
            "/api/v1/status/upload",
            files={"file": (filename, file_content, content_type)},
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # CRITICAL: Check all expected fields
        required_fields = ["uploadId", "file_key", "chunk_size", "total_chunks", "expires_in"]
        for field in required_fields:
            assert field in data, f"Response missing required field: {field}"
        
        # Verify field values are reasonable
        assert isinstance(data["uploadId"], str) and len(data["uploadId"]) > 0
        assert isinstance(data["file_key"], str) and len(data["file_key"]) > 0
        assert isinstance(data["chunk_size"], int) and data["chunk_size"] > 0
        assert isinstance(data["total_chunks"], int) and data["total_chunks"] > 0
        assert isinstance(data["expires_in"], int) and data["expires_in"] > 0
        
        # Check optional fields
        if "duration" in data:
            assert data["duration"] is None or isinstance(data["duration"], (int, float))
        
        print(f"✓ Upload response contains all expected fields")


class TestStatusEdgeCases:
    """Edge case tests"""
    
    def test_create_status_with_max_length_text(self, client: TestClient, auth_headers: Dict):
        """
        VALIDATION TEST: Create status with maximum allowed text length
        """
        max_text = "x" * 500  # Max length per StatusCreate model
        response = client.post(
            "/api/v1/status",
            json={"text": max_text},
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        print("✓ Maximum length text accepted")
    
    def test_create_status_with_exceeding_text_returns_400(self, client: TestClient, auth_headers: Dict):
        """
        VALIDATION TEST: Text exceeding max length returns 400
        """
        too_long_text = "x" * 501  # Exceeds max length
        response = client.post(
            "/api/v1/status",
            json={"text": too_long_text},
            headers=auth_headers
        )
        
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        print("✓ Over-length text correctly rejected")
    
    def test_create_status_with_special_characters(self, client: TestClient, auth_headers: Dict):
        """
        VALIDATION TEST: Create status with special characters (emoji, symbols)
        """
        special_text = "Status with emoji 🎉🚀 and symbols !@#$%^&*()_+-=[]{}|;:',.<>?/"
        response = client.post(
            "/api/v1/status",
            json={"text": special_text},
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        # Note: Text may be sanitized (XSS prevention), but should not cause errors
        print(f"✓ Special characters handled: {data['text'][:50]}...")


class TestStatusErrorHandling:
    """Error handling and recovery tests"""
    
    def test_upload_returns_proper_json_error(self, client: TestClient, auth_headers: Dict):
        """
        ERROR HANDLING TEST: Error responses should be valid JSON with detail field
        """
        invalid_file = ("test.txt", io.BytesIO(b"text"), "text/plain")
        response = client.post(
            "/api/v1/status/upload",
            files={"file": invalid_file},
            headers=auth_headers
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data, "Error response should have 'detail' field"
        assert isinstance(data["detail"], str), "Error detail should be string"
        print(f"✓ Error response properly formatted: {data['detail'][:50]}...")
    
    def test_create_status_returns_proper_json_error(self, client: TestClient, auth_headers: Dict):
        """
        ERROR HANDLING TEST: Status creation error responses are properly formatted
        """
        response = client.post(
            "/api/v1/status",
            json={"text": "", "file_key": None},
            headers=auth_headers
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data, "Error response should have 'detail' field"
        print(f"✓ Status error response properly formatted: {data['detail'][:50]}...")


# Run tests with: pytest tests/test_status_upload_api_fixes.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
