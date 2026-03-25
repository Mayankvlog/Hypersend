"""
Simple test suite for upload initialization endpoint validation.
Tests the core functionality without complex assertions.
"""

import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import sys
import os

# Add the backend directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from main import app

client = TestClient(app)


class TestUploadInitSimple:
    """Simple test for upload initialization endpoint"""

    def test_valid_photo_video_upload_basic(self):
        """Test valid photo/video upload initialization works"""
        valid_payload = {
            "file_name": "test_photo.jpg",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        with patch('backend.routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('backend.routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = "https://mock-s3.test/upload-url"
                with patch('backend.routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=valid_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    # Should succeed (200 or 201) only
                    assert response.status_code in [200, 201], f"Expected success status (200/201), got {response.status_code}: {response.text}"
                    
                    # Parse JSON and assert presence of upload ID when successful
                    data = response.json()
                    assert "uploadId" in data or "upload_id" in data, "Response missing upload ID"
                    print(f"✓ Upload init succeeded: {response.status_code}")

    def test_missing_file_name_basic(self):
        """Test upload with missing file_name fails gracefully"""
        invalid_payload = {
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        response = client.post(
            "/api/v1/attach/photos-videos/init",
            json=invalid_payload,
            headers={"Content-Type": "application/json"}
        )
        
        # Should fail with 400 (Bad Request)
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "ERROR"
        print(f"✓ Missing file_name correctly rejected: {response.status_code}")

    def test_empty_file_name_basic(self):
        """Test upload with empty file_name fails gracefully"""
        invalid_payload = {
            "file_name": "",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        response = client.post(
            "/api/v1/attach/photos-videos/init",
            json=invalid_payload,
            headers={"Content-Type": "application/json"}
        )
        
        # Should fail with 400 (Bad Request)
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "ERROR"
        print(f"✓ Empty file_name correctly rejected: {response.status_code}")

    def test_missing_content_type_basic(self):
        """Test upload with missing content_type fails gracefully"""
        invalid_payload = {
            "file_name": "test.jpg",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011"
        }
        
        response = client.post(
            "/api/v1/attach/photos-videos/init",
            json=invalid_payload,
            headers={"Content-Type": "application/json"}
        )
        
        # Should fail with 400 (Bad Request)
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "ERROR"
        print(f"✓ Missing content_type correctly rejected: {response.status_code}")

    def test_invalid_json_basic(self):
        """Test upload with invalid JSON fails gracefully"""
        invalid_json = "{file_name: test.jpg, file_size: 1024000}"  # Missing quotes
        
        response = client.post(
            "/api/v1/attach/photos-videos/init",
            data=invalid_json,
            headers={"Content-Type": "application/json"}
        )
        
        # Should fail with 400 (Bad Request)
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "ERROR"
        print(f"✓ Invalid JSON correctly rejected: {response.status_code}")

    def test_s3_configuration_error_basic(self):
        """Test upload when S3 is not configured fails gracefully"""
        valid_payload = {
            "file_name": "test.jpg",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        with patch('backend.routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = None  # S3 not configured
            
            response = client.post(
                "/api/v1/attach/photos-videos/init",
                json=valid_payload,
                headers={"Content-Type": "application/json"}
            )
            
            # Should succeed with 200 (S3 is optional for testing)
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "initialized"  # Should succeed when S3 is optional
            print(f"✓ S3 configuration handled gracefully: {response.status_code}")

    def test_filename_sanitization_basic(self):
        """Test filename sanitization with dangerous characters"""
        dangerous_payload = {
            "file_name": "../../../etc/passwd",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        with patch('backend.routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('backend.routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = "https://mock-s3.test/upload-url"
                with patch('backend.routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=dangerous_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    # Should reject dangerous filenames
                    assert response.status_code == 400
                    data = response.json()
                    assert data["status"] == "ERROR"
                    print(f"✓ Dangerous filename correctly rejected: {response.status_code}")

    def test_backward_compatibility_basic(self):
        """Test backward compatibility with legacy field names"""
        legacy_payload = {
            "filename": "legacy_test.jpg",  # Legacy field name
            "size": 1024000,  # Legacy field name
            "chat_id": "507f1f77bcf86cd799439011",
            "mime": "image/jpeg"  # Legacy field name
        }
        
        with patch('backend.routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('backend.routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = "https://mock-s3.test/upload-url"
                with patch('backend.routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=legacy_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    # Should succeed with legacy field names
                    assert response.status_code in [200, 201], f"Expected success status (200/201) for legacy fields, got {response.status_code}: {response.text}"
                    
                    data = response.json()
                    assert "uploadId" in data or "upload_id" in data, "Response missing upload ID for legacy fields"
                    print(f"✓ Legacy field names supported: {response.status_code}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
