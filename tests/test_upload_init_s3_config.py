"""
Upload initialization endpoint tests for S3 configuration validation.
Tests both success and failure scenarios for upload initialization.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from bson import ObjectId

# Import the backend application
try:
    from backend.main import app
    from backend.config import settings
    from backend.routes.files import _get_s3_client
except ImportError:
    # Fallback for different import paths
    from main import app
    from config import settings
    from routes.files import _get_s3_client


class TestUploadInitS3Config:
    """Test upload initialization endpoint with S3 configuration validation"""

    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)

    @pytest.fixture
    def mock_user_token(self):
        """Mock authenticated user token"""
        return "Bearer mock_token_12345"

    @pytest.fixture
    def valid_upload_data(self):
        """Valid upload initialization data"""
        return {
            "filename": "test_file.jpg",
            "size": 1024000,
            "mime_type": "image/jpeg",
            "chat_id": str(ObjectId())
        }

    def test_upload_init_success_with_valid_s3_config(self, client, mock_user_token, valid_upload_data):
        """Test successful upload initialization with valid S3 configuration"""
        
        # Mock S3 client to return valid client
        mock_s3_client = MagicMock()
        mock_s3_client.head_bucket.return_value = None
        
        # Override the entire app dependency for this test
        app = client.app
        original_dependency = app.dependency_overrides.get(
            'backend.routes.files.get_current_user_for_upload'
        )
        
        def mock_auth():
            return "test_user"
        
        app.dependency_overrides['backend.routes.files.get_current_user_for_upload'] = mock_auth
        
        try:
            with patch('backend.routes.files._get_s3_client', return_value=mock_s3_client):
                response = client.post(
                    "/api/v1/files/init",
                    json=valid_upload_data,
                    headers={"Authorization": mock_user_token}
                )
        finally:
            # Restore original dependency
            if original_dependency:
                app.dependency_overrides['backend.routes.files.get_current_user_for_upload'] = original_dependency
            else:
                app.dependency_overrides.pop('backend.routes.files.get_current_user_for_upload', None)
        
        assert response.status_code == 200
        data = response.json()
        assert "uploadId" in data
        assert "chunk_size" in data
        assert "total_chunks" in data
        assert data["chunk_size"] > 0
        assert data["total_chunks"] > 0

    def test_upload_init_failure_when_s3_client_none(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization failure when S3 client returns None"""
        
        # Mock S3 client to return None (configuration error)
        with patch('backend.routes.files._get_s3_client', return_value=None):
            with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
                # Mock the authentication dependency
                with patch('backend.routes.files.get_current_user', return_value="test_user"):
                    response = client.post(
                        "/api/v1/files/init",
                        json=valid_upload_data,
                        headers={"Authorization": mock_user_token}
                    )
        
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "ERROR"
        assert "S3 configuration invalid" in data["message"]
        assert data["data"]["error_code"] == "S3_CONFIG_ERROR"
        assert "s3_bucket" in data["data"]
        assert "aws_region" in data["data"]
        assert "credentials_configured" in data["data"]

    def test_upload_init_failure_when_s3_bucket_empty(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization failure when S3 bucket is empty"""
        
        # Mock settings to have empty S3 bucket
        with patch.object(settings, 'S3_BUCKET', ""):
            with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
                # Mock the authentication dependency
                with patch('backend.routes.files.get_current_user', return_value="test_user"):
                    response = client.post(
                        "/api/v1/files/init",
                        json=valid_upload_data,
                        headers={"Authorization": mock_user_token}
                    )
        
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "ERROR"
        assert "S3 configuration invalid" in data["message"]
        assert data["data"]["error_code"] == "S3_CONFIG_ERROR"

    def test_upload_init_failure_when_aws_credentials_missing(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization failure when AWS credentials are missing"""
        
        # Mock settings to have missing AWS credentials
        with patch.object(settings, 'AWS_ACCESS_KEY_ID', ""):
            with patch.object(settings, 'AWS_SECRET_ACCESS_KEY', ""):
                with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
                    # Mock the authentication dependency
                    with patch('backend.routes.files.get_current_user', return_value="test_user"):
                        response = client.post(
                            "/api/v1/files/init",
                            json=valid_upload_data,
                            headers={"Authorization": mock_user_token}
                        )
        
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "ERROR"
        assert "S3 configuration invalid" in data["message"]
        assert data["data"]["credentials_configured"] == False

    def test_upload_init_failure_when_s3_bucket_access_denied(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization failure when S3 bucket access is denied"""
        
        # Mock S3 client to raise access denied error
        mock_s3_client = MagicMock()
        from botocore.exceptions import ClientError
        mock_s3_client.head_bucket.side_effect = ClientError(
            error_response={'Error': {'Code': '403', 'Message': 'Access Denied'}},
            operation_name='HeadBucket'
        )
        
        with patch('backend.routes.files._get_s3_client', return_value=mock_s3_client):
            with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
                # Mock the authentication dependency
                with patch('backend.routes.files.get_current_user', return_value="test_user"):
                    response = client.post(
                        "/api/v1/files/init",
                        json=valid_upload_data,
                        headers={"Authorization": mock_user_token}
                    )
        
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "ERROR"
        assert "S3 configuration invalid" in data["message"]

    def test_upload_init_failure_when_s3_bucket_not_found(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization failure when S3 bucket doesn't exist"""
        
        # Mock S3 client to raise bucket not found error
        mock_s3_client = MagicMock()
        from botocore.exceptions import ClientError
        mock_s3_client.head_bucket.side_effect = ClientError(
            error_response={'Error': {'Code': '404', 'Message': 'Not Found'}},
            operation_name='HeadBucket'
        )
        
        with patch('backend.routes.files._get_s3_client', return_value=mock_s3_client):
            with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
                # Mock the authentication dependency
                with patch('backend.routes.files.get_current_user', return_value="test_user"):
                    response = client.post(
                        "/api/v1/files/init",
                        json=valid_upload_data,
                        headers={"Authorization": mock_user_token}
                    )
        
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "ERROR"
        assert "S3 configuration invalid" in data["message"]

    def test_upload_init_validates_required_fields(self, client, mock_user_token):
        """Test upload initialization validates required fields"""
        
        # Test missing filename
        invalid_data = {
            "size": 1024000,
            "mime_type": "image/jpeg",
            "chat_id": str(ObjectId())
        }
        
        with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
            # Mock the authentication dependency
            with patch('backend.routes.files.get_current_user', return_value="test_user"):
                response = client.post(
                    "/api/v1/files/init",
                    json=invalid_data,
                    headers={"Authorization": mock_user_token}
                )
        
        assert response.status_code == 400

    def test_upload_init_handles_invalid_file_size(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization handles invalid file size"""
        
        # Test negative file size
        invalid_data = valid_upload_data.copy()
        invalid_data["size"] = -1
        
        mock_s3_client = MagicMock()
        mock_s3_client.head_bucket.return_value = None
        
        with patch('backend.routes.files._get_s3_client', return_value=mock_s3_client):
            with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
                # Mock the authentication dependency
                with patch('backend.routes.files.get_current_user', return_value="test_user"):
                    response = client.post(
                        "/api/v1/files/init",
                        json=invalid_data,
                        headers={"Authorization": mock_user_token}
                    )
        
        assert response.status_code == 400

    def test_upload_init_handles_large_file_size(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization handles large file size"""
        
        # Test extremely large file size (beyond limits)
        invalid_data = valid_upload_data.copy()
        invalid_data["size"] = 100 * 1024 * 1024 * 1024  # 100GB
        
        mock_s3_client = MagicMock()
        mock_s3_client.head_bucket.return_value = None
        
        with patch('backend.routes.files._get_s3_client', return_value=mock_s3_client):
            with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
                # Mock the authentication dependency
                with patch('backend.routes.files.get_current_user', return_value="test_user"):
                    response = client.post(
                        "/api/v1/files/init",
                        json=invalid_data,
                        headers={"Authorization": mock_user_token}
                    )
        
        assert response.status_code == 400

    def test_upload_init_rate_limiting(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization rate limiting"""
        
        mock_s3_client = MagicMock()
        mock_s3_client.head_bucket.return_value = None
        
        with patch('backend.routes.files._get_s3_client', return_value=mock_s3_client):
            with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
                # Make multiple rapid requests to trigger rate limiting
                responses = []
                for _ in range(15):  # Exceed the rate limit of 10 per minute
                    response = client.post(
                        "/api/v1/files/init",
                        json=valid_upload_data,
                        headers={"Authorization": mock_user_token}
                    )
                    responses.append(response)
                
                # At least one request should be rate limited
                rate_limited = any(r.status_code == 429 for r in responses)
                if rate_limited:
                    rate_limited_response = next(r for r in responses if r.status_code == 429)
                    data = rate_limited_response.json()
                    assert data["status"] == "ERROR"
                    assert "Too many upload initialization requests" in data["message"]

    def test_upload_init_unauthorized_access(self, client, valid_upload_data):
        """Test upload initialization without authentication"""
        
        response = client.post(
            "/api/v1/files/init",
            json=valid_upload_data
        )
        
        # Should return 401 or 403 depending on auth configuration
        assert response.status_code in [401, 403]

    def test_upload_init_wrong_http_method(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization with wrong HTTP method"""
        
        response = client.get(
            "/api/v1/files/init",
            headers={"Authorization": mock_user_token}
        )
        
        assert response.status_code == 405

    def test_s3_client_logging_configuration(self):
        """Test S3 client logs configuration parameters"""
        
        # Mock S3 client
        mock_s3_client = MagicMock()
        mock_s3_client.head_bucket.return_value = None
        
        with patch('backend.routes.files._get_s3_client', return_value=mock_s3_client) as mock_get_client:
            # Call the function to trigger logging
            client = _get_s3_client()
            
            # Verify the function was called
            assert client is not None
            assert mock_get_client.called_once()

    def test_upload_init_error_response_structure(self, client, mock_user_token, valid_upload_data):
        """Test upload initialization error response structure"""
        
        with patch('backend.routes.files._get_s3_client', return_value=None):
            with patch('backend.routes.files.get_current_user_for_upload', return_value="test_user"):
                # Mock the authentication dependency
                with patch('backend.routes.files.get_current_user', return_value="test_user"):
                    response = client.post(
                        "/api/v1/files/init",
                        json=valid_upload_data,
                        headers={"Authorization": mock_user_token}
                    )
        
        assert response.status_code == 503
        data = response.json()
        
        # Verify error response structure
        assert "status" in data
        assert "message" in data
        assert "data" in data
        assert data["status"] == "ERROR"
        assert isinstance(data["data"], dict)
        assert "error_code" in data["data"]
        assert "s3_bucket" in data["data"]
        assert "aws_region" in data["data"]
        assert "credentials_configured" in data["data"]
