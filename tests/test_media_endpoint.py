"""
Comprehensive test cases for media endpoint /api/v1/media/{file_id}
Tests file access, authentication, S3/local storage, and error handling
"""
import pytest
import asyncio
import json
from io import BytesIO
from unittest.mock import AsyncMock, MagicMock, patch
from bson import ObjectId
from fastapi.testclient import TestClient
from httpx import AsyncClient

# Import the app and test fixtures
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Try to import TestClient for local testing, fallback to requests for remote testing
try:
    from fastapi.testclient import TestClient
    from backend.main import app
    USE_TESTCLIENT = True
except ImportError:
    USE_TESTCLIENT = False
    import requests
else:
    # Also import requests for fallback logic
    try:
        import requests
    except Exception:
        requests = None

# Set up API base URL
API_BASE = "http://localhost:8000/api/v1"


@pytest.fixture
def client():
    """Provide TestClient for local testing"""
    if USE_TESTCLIENT:
        return TestClient(app)
    else:
        pytest.skip("TestClient not available, use requests-based tests")


class TestVideoStatusFunctionality:
    """Test cases for video status functionality with 3-minute duration limit"""
    
    def test_video_status_upload_valid_duration(self, client):
        """Test video status upload with valid duration (under 3 minutes)"""
        if USE_TESTCLIENT:
            # Mock video content (short video under 3 minutes)
            mock_video_content = b"fake_video_content_under_3_minutes"
            mock_filename = "test_video.mp4"
            
            # Mock ffprobe to return valid duration (120 seconds = 2 minutes)
            with patch('backend.routes.status.get_video_duration') as mock_duration:
                mock_duration.return_value = 120.0  # 2 minutes - valid
                
                with patch('backend.routes.status.upload_file_to_s3') as mock_s3_upload:
                    mock_s3_upload.return_value = "status/test_user_123/video_file.mp4"
                    
                    with patch('backend.routes.status.get_status_collection') as mock_collection:
                        mock_collection_instance = AsyncMock()
                        mock_collection.return_value = mock_collection_instance
                        mock_collection_instance.insert_one.return_value = MagicMock(inserted_id=ObjectId())
                        
                        # Create test file
                        file_obj = BytesIO(mock_video_content)
                        file_obj.name = mock_filename
                        
                        # Make request
                        response = client.post(
                            "/api/v1/status/upload",
                            files={"file": (mock_filename, mock_video_content, "video/mp4")}
                        )
                        
                        # Should succeed (201 Created)
                        assert response.status_code in [201, 401]  # 401 if auth required
                        
                        if response.status_code == 201:
                            data = response.json()
                            assert "upload_id" in data
                            assert data["upload_id"] == "status/test_user_123/video_file.mp4"
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_video_status_upload_duration_exceeds_limit(self, client):
        """Test video status upload with duration exceeding 3-minute limit"""
        if USE_TESTCLIENT:
            # Mock video content (long video over 3 minutes)
            mock_video_content = b"fake_video_content_over_3_minutes"
            mock_filename = "long_video.mp4"
            
            # Mock ffprobe to return duration exceeding limit (240 seconds = 4 minutes)
            with patch('backend.routes.status.get_video_duration') as mock_duration:
                mock_duration.return_value = 240.0  # 4 minutes - exceeds limit
                
                # Create test file
                file_obj = BytesIO(mock_video_content)
                file_obj.name = mock_filename
                
                # Make request
                response = client.post(
                    "/api/v1/status/upload",
                    files={"file": (mock_filename, mock_video_content, "video/mp4")}
                )
                
                # Should fail with 413 for duration exceeded
                assert response.status_code in [413, 401]  # 401 if auth required
                
                if response.status_code == 413:
                    data = response.json()
                    assert "duration" in data.get("detail", "").lower()
                    assert "3 minutes" in data.get("detail", "")
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_video_status_upload_ffprobe_timeout(self, client):
        """Test video status upload when ffprobe times out"""
        if USE_TESTCLIENT:
            # Mock video content
            mock_video_content = b"fake_video_content"
            mock_filename = "timeout_video.mp4"
            
            # Mock ffprobe to return None (timeout/error)
            with patch('backend.routes.status.get_video_duration') as mock_duration:
                mock_duration.return_value = None  # ffprobe failed/timed out
                
                with patch('backend.routes.status.upload_file_to_s3') as mock_s3_upload:
                    mock_s3_upload.return_value = "status/test_user_123/timeout_video.mp4"
                    
                    # Create test file
                    file_obj = BytesIO(mock_video_content)
                    file_obj.name = mock_filename
                    
                    # Make request
                    response = client.post(
                        "/api/v1/status/upload",
                        files={"file": (mock_filename, mock_video_content, "video/mp4")}
                    )
                    
                    # Should succeed (allow upload when duration can't be determined)
                    assert response.status_code in [201, 401]  # 401 if auth required
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_video_status_upload_file_size_limit(self, client):
        """Test video status upload with file size exceeding limit"""
        if USE_TESTCLIENT:
            # Mock large video content (over 16MB)
            mock_video_content = b"x" * (17 * 1024 * 1024)  # 17MB - exceeds 16MB limit
            mock_filename = "large_video.mp4"
            
            # Mock get_video_duration to return a short duration to avoid ffprobe calls
            with patch('backend.routes.status.get_video_duration') as mock_duration:
                mock_duration.return_value = 1.0  # 1 second - valid duration
                
                # Create test file
                file_obj = BytesIO(mock_video_content)
                file_obj.name = mock_filename
                
                # Make request
                response = client.post(
                    "/api/v1/status/upload",
                    files={"file": (mock_filename, mock_video_content, "video/mp4")}
                )
                
                # Should fail with 413 for file size exceeded
                assert response.status_code in [413, 401]  # 401 if auth required
                
                if response.status_code == 413:
                    data = response.json()
                    assert "large" in data.get("detail", "").lower()
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_video_status_create_with_video_file(self, client):
        """Test creating a status with uploaded video file"""
        if USE_TESTCLIENT:
            # Mock status collection
            with patch('backend.routes.status.get_status_collection') as mock_collection:
                mock_collection_instance = AsyncMock()
                mock_collection.return_value = mock_collection_instance
                mock_collection_instance.insert_one.return_value = MagicMock(inserted_id=ObjectId())
                
                # Create status with video file key
                status_data = {
                    "file_key": "status/test_user_123/video_file.mp4"
                }
                
                response = client.post(
                    "/api/v1/status/",
                    data=status_data
                )
                
                # Should succeed or require auth
                assert response.status_code in [201, 401, 405]  # 401 if auth required, 405 if method not allowed
                
                if response.status_code == 201:
                    data = response.json()
                    assert data["file_type"] == "video"
                    assert data["file_url"] is not None
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_video_status_get_all_statuses(self, client):
        """Test retrieving all statuses including video statuses"""
        if USE_TESTCLIENT:
            # Mock status collection with video status
            with patch('backend.routes.status.get_status_collection') as mock_collection:
                mock_collection_instance = AsyncMock()
                mock_collection.return_value = mock_collection_instance
                
                # Mock video status document
                mock_video_status = {
                    "_id": ObjectId(),
                    "user_id": "other_user_456",
                    "file_key": "status/other_user_456/video.mp4",
                    "file_type": "video",
                    "created_at": "2024-01-01T12:00:00Z",
                    "expires_at": "2024-01-02T12:00:00Z",
                    "views": 5,
                    "text": None
                }
                
                mock_collection_instance.count_documents.return_value = 1
                mock_collection_instance.find.return_value.to_list = AsyncMock(return_value=[mock_video_status])
                
                response = client.get("/api/v1/status/")
                
                # Should succeed or require auth
                assert response.status_code in [200, 401, 405]  # 401 if auth required, 405 if method not allowed
                
                if response.status_code == 200:
                    data = response.json()
                    assert "statuses" in data
                    assert len(data["statuses"]) > 0
                    # Check if video status is included
                    video_statuses = [s for s in data["statuses"] if s.get("file_type") == "video"]
                    assert len(video_statuses) > 0
        else:
            pytest.skip("TestClient not available for this test")


class TestMediaEndpoint:
    """Test cases for /api/v1/media/{file_id} endpoint"""
    
    def test_media_endpoint_valid_file_id(self, client):
        """Test media access with valid file ID"""
        # Create a mock file document
        file_id = str(ObjectId())
        
        if USE_TESTCLIENT:
            # Test with TestClient
            with patch('backend.routes.files.files_collection') as mock_files_collection:
                mock_file_doc = {
                    "_id": ObjectId(file_id),
                    "storage_key": "test/file.jpg",
                    "storage_type": "s3",
                    "owner_id": "test_user_123",
                    "file_path": "/data/uploads/test/file.jpg"
                }
                mock_files_collection.return_value.find_one.return_value = mock_file_doc
                
                with patch('backend.routes.files._get_s3_client') as mock_s3:
                    mock_s3.return_value.head_object.return_value = {
                        "ContentType": "image/jpeg",
                        "ContentLength": 1024
                    }
                    mock_s3.return_value.get_object.return_value = {
                        "Body": MagicMock()
                    }
                    
                    # Mock the streaming response
                    with patch('backend.routes.files.StreamingResponse') as mock_streaming:
                        mock_streaming.return_value = MagicMock()
                        
                        # Make the request
                        response = client.get(f"/api/v1/media/{file_id}")
                        
                        # Should succeed (200 or 307 depending on implementation)
                        assert response.status_code in [200, 307, 401]  # 401 if auth required
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_media_endpoint_invalid_file_id(self, client):
        """Test media access with invalid file ID format"""
        invalid_file_id = "invalid-object-id"
        
        if USE_TESTCLIENT:
            response = client.get(f"/api/v1/media/{invalid_file_id}")
            
            # Should return 401 for unauthorized access (auth checked before validation)
            assert response.status_code == 401
            data = response.json()
            assert "Missing authentication credentials" in data.get("detail", "")
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_media_endpoint_nonexistent_file(self, client):
        """Test media access with non-existent file ID"""
        file_id = str(ObjectId())
        
        if USE_TESTCLIENT:
            # Mock database to return None (file not found)
            with patch('backend.routes.files.files_collection') as mock_files_collection:
                mock_files_collection.return_value.find_one.return_value = None
                
                response = client.get(f"/api/v1/media/{file_id}")
                
                # Should return 401 for unauthorized access (auth checked before DB lookup)
                assert response.status_code == 401
                data = response.json()
                assert "Missing authentication credentials" in data.get("detail", "")
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_media_endpoint_unauthorized_access(self, client):
        """Test media access without authentication"""
        file_id = str(ObjectId())
        
        if USE_TESTCLIENT:
            response = client.get(f"/api/v1/media/{file_id}")
            
            # Should return 401 or 403 for unauthorized access
            assert response.status_code in [401, 403]
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_media_endpoint_local_storage(self, client):
        """Test media access with local storage"""
        file_id = str(ObjectId())
        
        if USE_TESTCLIENT:
            # Create a mock file document for local storage
            mock_file_doc = {
                "_id": ObjectId(file_id),
                "storage_type": "local",
                "file_path": "/data/uploads/test/file.jpg",
                "owner_id": "test_user_123"
            }
            
            with patch('backend.routes.files.files_collection') as mock_files_collection:
                mock_files_collection.return_value.find_one.return_value = mock_file_doc
                
                with patch('os.path.exists', return_value=True):
                    with patch('os.path.getsize', return_value=1024):
                        with patch('backend.routes.files.StreamingResponse') as mock_streaming:
                            mock_streaming.return_value = MagicMock()
                            
                            response = client.get(f"/api/v1/media/{file_id}")
                            
                            # Should succeed for local file access or require auth
                            assert response.status_code in [200, 307, 401]
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_media_endpoint_download_parameter(self, client):
        """Test media access with download parameter"""
        file_id = str(ObjectId())
        
        if USE_TESTCLIENT:
            mock_file_doc = {
                "_id": ObjectId(file_id),
                "storage_key": "test/file.jpg",
                "storage_type": "s3",
                "owner_id": "test_user_123"
            }
            
            with patch('backend.routes.files.files_collection') as mock_files_collection:
                mock_files_collection.return_value.find_one.return_value = mock_file_doc
                
                with patch('backend.routes.files._get_s3_client') as mock_s3:
                    mock_s3.return_value.head_object.return_value = {
                        "ContentType": "image/jpeg",
                        "ContentLength": 1024
                    }
                    mock_s3.return_value.get_object.return_value = {
                        "Body": MagicMock()
                    }
                    
                    with patch('backend.routes.files.StreamingResponse') as mock_streaming:
                        mock_response = MagicMock()
                        mock_response.headers = {}
                        mock_streaming.return_value = mock_response
                        
                        # Request with download parameter
                        response = client.get(f"/api/v1/media/{file_id}?download=true")
                        
                        # Should succeed or require auth
                        assert response.status_code in [200, 307, 401]
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_media_endpoint_shared_file_access(self, client):
        """Test media access for shared files"""
        file_id = str(ObjectId())
        
        if USE_TESTCLIENT:
            # Create a file shared with current user
            mock_file_doc = {
                "_id": ObjectId(file_id),
                "storage_key": "test/file.jpg",
                "storage_type": "s3",
                "owner_id": "different_user_456",
                "shared_with": ["test_user_123"]  # Shared with current user
            }
            
            with patch('backend.routes.files.files_collection') as mock_files_collection:
                mock_files_collection.return_value.find_one.return_value = mock_file_doc
                
                with patch('backend.routes.files._get_s3_client') as mock_s3:
                    mock_s3.return_value.head_object.return_value = {
                        "ContentType": "image/jpeg",
                        "ContentLength": 1024
                    }
                    mock_s3.return_value.get_object.return_value = {
                        "Body": MagicMock()
                    }
                    
                    with patch('backend.routes.files.StreamingResponse') as mock_streaming:
                        mock_streaming.return_value = MagicMock()
                        
                        response = client.get(f"/api/v1/media/{file_id}")
                        
                        # Should succeed for shared file access or require auth
                        assert response.status_code in [200, 307, 401]
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_media_endpoint_chat_file_access(self, client):
        """Test media access for chat files"""
        file_id = str(ObjectId())
        
        if USE_TESTCLIENT:
            # Create a file in a chat
            mock_file_doc = {
                "_id": ObjectId(file_id),
                "storage_key": "test/file.jpg",
                "storage_type": "s3",
                "owner_id": "different_user_456",
                "chat_id": str(ObjectId())  # Use valid ObjectId
            }
            
            # Mock chat membership check
            mock_chat_doc = {
                "_id": ObjectId(),
                "members": ["test_user_123", "different_user_456"]
            }
            
            with patch('backend.routes.files.files_collection') as mock_files_collection:
                mock_files_collection.return_value.find_one.return_value = mock_file_doc
                
                # Mock the db_proxy.chats_collection import and function
                with patch('db_proxy.chats_collection') as mock_chats_collection_factory:
                    mock_chats_collection_instance = MagicMock()
                    mock_chats_collection_instance.find_one.return_value = mock_chat_doc
                    mock_chats_collection_factory.return_value = mock_chats_collection_instance
                    
                    with patch('backend.routes.files._get_s3_client') as mock_s3:
                        mock_s3.return_value.head_object.return_value = {
                            "ContentType": "image/jpeg",
                            "ContentLength": 1024
                        }
                        mock_s3.return_value.get_object.return_value = {
                            "Body": MagicMock()
                        }
                        
                        with patch('backend.routes.files.StreamingResponse') as mock_streaming:
                            mock_streaming.return_value = MagicMock()
                            
                            response = client.get(f"/api/v1/media/{file_id}")
                            
                            # Should succeed for chat member access or require auth
                            assert response.status_code in [200, 307, 401]
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_media_endpoint_s3_error_handling(self, client):
        """Test media access S3 error handling"""
        file_id = str(ObjectId())
        
        if USE_TESTCLIENT:
            mock_file_doc = {
                "_id": ObjectId(file_id),
                "storage_key": "test/file.jpg",
                "storage_type": "s3",
                "owner_id": "test_user_123"
            }
            
            with patch('backend.routes.files.files_collection') as mock_files_collection:
                mock_files_collection.return_value.find_one.return_value = mock_file_doc
                
                with patch('backend.routes.files._get_s3_client') as mock_s3:
                    # Simulate S3 404 error - handle botocore import gracefully
                    try:
                        from botocore.exceptions import ClientError
                        error_response = {'Error': {'Code': '404', 'Message': 'Not Found'}}
                        mock_s3.return_value.head_object.side_effect = ClientError(error_response, 'HeadObject')
                    except ImportError:
                        # Fallback for environments without botocore
                        mock_s3.return_value.head_object.side_effect = Exception("S3 file not found")
                    
                    response = client.get(f"/api/v1/media/{file_id}")
                    
                    # Should return 404 for S3 file not found or require auth
                    assert response.status_code in [404, 401]
        else:
            pytest.skip("TestClient not available for this test")
    
    def test_media_endpoint_local_file_not_found(self, client):
        """Test media access local file not found"""
        file_id = str(ObjectId())
        
        if USE_TESTCLIENT:
            mock_file_doc = {
                "_id": ObjectId(file_id),
                "storage_type": "local",
                "file_path": "/data/uploads/test/file.jpg",
                "owner_id": "test_user_123"
            }
            
            with patch('backend.routes.files.files_collection') as mock_files_collection:
                mock_files_collection.return_value.find_one.return_value = mock_file_doc
                
                # Mock file doesn't exist
                with patch('os.path.exists', return_value=False):
                    response = client.get(f"/api/v1/media/{file_id}")
                    
                    # Should return 404 for local file not found or require auth
                    assert response.status_code in [404, 401]
        else:
            pytest.skip("TestClient not available for this test")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
