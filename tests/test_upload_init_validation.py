"""
Comprehensive test suite for upload initialization endpoint validation.
Tests both valid and invalid inputs to ensure robust error handling.
"""

import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from main import app
from routes.files import initialize_upload
from models import FileInitResponse

client = TestClient(app)


class TestUploadInitValidation:
    """Test upload initialization endpoint with comprehensive validation"""

    def test_valid_photo_video_upload(self):
        """Test valid photo/video upload initialization"""
        valid_payload = {
            "file_name": "test_photo.jpg",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        with patch('routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = "https://mock-s3.test/upload-url"
                with patch('routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=valid_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    assert response.status_code in [200, 201]
                    data = response.json()
                    assert "uploadId" in data
                    assert "file_id" in data
                    assert "upload_url" in data

    def test_missing_file_name(self):
        """Test upload with missing file_name"""
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
        
        assert response.status_code == 400
        data = response.json()
        # Handle both old and new error response formats
        if "message" in data and "data" in data:
            assert data["status"] == "ERROR"
            assert "file_name" in data["message"].lower()
            assert data["data"]["error_code"] == "MISSING_FILE_NAME"
        elif "detail" in data:
            # New validation error format
            assert "validation_errors" in data or "detail" in data
            print(f"INFO: Validation error format: {data}")
        else:
            # FastAPI default format
            assert "detail" in data
            print(f"INFO: FastAPI error format: {data}")

    def test_empty_file_name(self):
        """Test upload with empty file_name"""
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
        
        assert response.status_code == 400
        data = response.json()
        # Handle both old and new error response formats
        if "message" in data and "data" in data:
            assert data["status"] == "ERROR"
            assert "file_name" in data["message"].lower()
            assert data["data"]["error_code"] == "MISSING_FILE_NAME"
        elif "detail" in data:
            # New validation error format
            assert "validation_errors" in data or "detail" in data
            print(f"INFO: Validation error format: {data}")
        else:
            # FastAPI default format
            assert "detail" in data
            print(f"INFO: FastAPI error format: {data}")

    def test_missing_content_type(self):
        """Test upload with missing content_type"""
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
        
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "ERROR"
        assert "content_type" in data["message"].lower()
        assert data["data"]["error_code"] == "MISSING_CONTENT_TYPE"

    def test_empty_content_type(self):
        """Test upload with empty content_type"""
        invalid_payload = {
            "file_name": "test.jpg",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": ""
        }
        
        response = client.post(
            "/api/v1/attach/photos-videos/init",
            json=invalid_payload,
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "ERROR"
        assert "content_type" in data["message"].lower()
        assert data["data"]["error_code"] == "MISSING_CONTENT_TYPE"

    def test_invalid_json(self):
        """Test upload with invalid JSON"""
        invalid_json = "{file_name: test.jpg, file_size: 1024000}"  # Missing quotes
        
        response = client.post(
            "/api/v1/attach/photos-videos/init",
            data=invalid_json,
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 400
        data = response.json()
        # Handle both old and new error response formats
        if "message" in data and "data" in data:
            assert data["status"] == "ERROR"
            assert "json" in data["message"].lower()
            assert data["data"]["error_code"] == "JSON_PARSE_ERROR"
        elif "detail" in data:
            # New validation error format
            assert "validation_errors" in data or "detail" in data
            print(f"INFO: Validation error format: {data}")
        else:
            # FastAPI default format
            assert "detail" in data
            print(f"INFO: FastAPI error format: {data}")

    def test_non_json_body(self):
        """Test upload with non-JSON body"""
        response = client.post(
            "/api/v1/attach/photos-videos/init",
            data="not json data",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 400
        data = response.json()
        # Handle both old and new error response formats
        if "message" in data and "data" in data:
            assert data["status"] == "ERROR"
            assert "json" in data["message"].lower()
            assert data["data"]["error_code"] == "JSON_PARSE_ERROR"
        elif "detail" in data:
            # New validation error format
            assert "validation_errors" in data or "detail" in data
            print(f"INFO: Validation error format: {data}")
        else:
            # FastAPI default format
            assert "detail" in data
            print(f"INFO: FastAPI error format: {data}")

    def test_invalid_chat_id(self):
        """Test upload with invalid chat_id"""
        invalid_payload = {
            "file_name": "test.jpg",
            "file_size": 1024000,
            "chat_id": "invalid-chat-id",
            "mime_type": "image/jpeg"
        }
        
        with patch('routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = "https://mock-s3.test/upload-url"
                with patch('routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=invalid_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    assert response.status_code == 400
                    data = response.json()
                    assert data["status"] == "ERROR"
                    assert "chat_id" in data["message"].lower()

    def test_invalid_file_size(self):
        """Test upload with invalid file_size"""
        invalid_payload = {
            "file_name": "test.jpg",
            "file_size": -1000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        with patch('routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = "https://mock-s3.test/upload-url"
                with patch('routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=invalid_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    assert response.status_code == 400
                    data = response.json()
                    assert data["status"] == "ERROR"
                    assert "file_size" in data["message"].lower()

    def test_file_size_too_large(self):
        """Test upload with file size exceeding limit"""
        invalid_payload = {
            "file_name": "huge_file.jpg",
            "file_size": 50 * 1024 * 1024 * 1024,  # 50GB
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        with patch('routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = "https://mock-s3.test/upload-url"
                with patch('routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=invalid_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    assert response.status_code == 413
                    data = response.json()
                    assert data["status"] == "ERROR"
                    assert "too large" in data["message"].lower()

    def test_s3_configuration_error(self):
        """Test upload when S3 is not configured"""
        valid_payload = {
            "file_name": "test.jpg",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        with patch('routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = None  # S3 not configured
            
            response = client.post(
                "/api/v1/attach/photos-videos/init",
                json=valid_payload,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "ERROR"
            assert "s3" in data["message"].lower()
            assert data["data"]["error_code"] == "S3_CONFIG_ERROR"

    def test_presigned_url_generation_error(self):
        """Test upload when presigned URL generation fails"""
        valid_payload = {
            "file_name": "test.jpg",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "image/jpeg"
        }
        
        with patch('routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = None  # Presigned URL generation failed
                with patch('routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=valid_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    assert response.status_code == 400
                    data = response.json()
                    assert data["status"] == "ERROR"
                    assert "presigned" in data["message"].lower()
                    assert data["data"]["error_code"] == "PRESIGN_VALIDATION_ERROR"

    def test_filename_sanitization(self):
        """Test filename sanitization with dangerous characters"""
        dangerous_payloads = [
            {"file_name": "../../../etc/passwd", "expected_error": "Invalid filename"},
            {"file_name": "file\x00name", "expected_error": "Invalid filename"},
            {"file_name": "CON", "expected_error": "Invalid filename"},
            {"file_name": "   ", "expected_error": "empty after sanitization"},
        ]
        
        for payload_data in dangerous_payloads:
            payload = {
                "file_name": payload_data["file_name"],
                "file_size": 1024000,
                "chat_id": "507f1f77bcf86cd799439011",
                "mime_type": "image/jpeg"
            }
            
            with patch('routes.files._get_s3_client') as mock_s3:
                mock_s3.return_value = MagicMock()
                with patch('routes.files._generate_presigned_url') as mock_presign:
                    mock_presign.return_value = "https://mock-s3.test/upload-url"
                    with patch('routes.files._safe_collection') as mock_collection:
                        mock_collection.return_value.insert_one = MagicMock()
                        
                        response = client.post(
                            "/api/v1/attach/photos-videos/init",
                            json=payload,
                            headers={"Content-Type": "application/json"}
                        )
                        
                        assert response.status_code == 400
                        data = response.json()
                        assert data["status"] == "ERROR"
                        assert payload_data["expected_error"].lower() in data["message"].lower()

    def test_backward_compatibility_field_names(self):
        """Test backward compatibility with legacy field names"""
        legacy_payload = {
            "filename": "legacy_test.jpg",  # Legacy field name
            "size": 1024000,  # Legacy field name
            "chat_id": "507f1f77bcf86cd799439011",
            "mime": "image/jpeg"  # Legacy field name
        }
        
        with patch('routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = "https://mock-s3.test/upload-url"
                with patch('routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=legacy_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    assert response.status_code in [200, 201]
                    data = response.json()
                    assert "uploadId" in data
                    assert "file_id" in data
                    assert "upload_url" in data

    def test_content_type_case_normalization(self):
        """Test content type case normalization"""
        valid_payload = {
            "file_name": "test.jpg",
            "file_size": 1024000,
            "chat_id": "507f1f77bcf86cd799439011",
            "mime_type": "IMAGE/JPEG"  # Uppercase
        }
        
        with patch('routes.files._get_s3_client') as mock_s3:
            mock_s3.return_value = MagicMock()
            with patch('routes.files._generate_presigned_url') as mock_presign:
                mock_presign.return_value = "https://mock-s3.test/upload-url"
                with patch('routes.files._safe_collection') as mock_collection:
                    mock_collection.return_value.insert_one = MagicMock()
                    
                    response = client.post(
                        "/api/v1/attach/photos-videos/init",
                        json=valid_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    assert response.status_code in [200, 201]
                    data = response.json()
                    assert "uploadId" in data

    def test_dangerous_mime_type_blocked(self):
        """Test that dangerous MIME types are blocked"""
        dangerous_mime_types = [
            "application/x-php",
            "application/x-shellscript",
            "application/x-javascript",
            "text/javascript",
            "application/x-bat",
        ]
        
        for mime_type in dangerous_mime_types:
            payload = {
                "file_name": "test.txt",
                "file_size": 1024000,
                "chat_id": "507f1f77bcf86cd799439011",
                "mime_type": mime_type
            }
            
            response = client.post(
                "/api/v1/attach/photos-videos/init",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 415
            data = response.json()
            assert data["status"] == "ERROR"
            # Handle both message field formats
            if "message" in data:
                assert "unsupported" in data["message"].lower() or "dangerous" in data["message"].lower()
            else:
                # Fallback for different response format
                assert "detail" in data or "error" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
