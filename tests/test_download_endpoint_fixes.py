"""
Test cases for download endpoint fixes - device_id handling and error separation
"""
import pytest
import asyncio
from fastapi.testclient import TestClient
from fastapi import status
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from backend.main import app
from backend.routes.files import download_file
from backend.models import UserLogin


class TestDownloadEndpointFixes:
    """Test download endpoint with device_id fixes and error handling"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user"""
        return "test_user@example.com"
    
    @pytest.fixture
    def mock_file_doc(self):
        """Mock file document"""
        return {
            "_id": "507f1f77bcf86cd799439011",
            "file_id": "507f1f77bcf86cd799439011",
            "filename": "test_file.pdf",
            "owner_id": "test_user@example.com",
            "storage_type": "s3",
            "storage_key": "test/file.pdf",
            "content_type": "application/pdf",
            "size": 1024,
            "uploaded_at": "2024-01-01T00:00:00Z"
        }
    
    def test_download_without_device_id_generates_temp_id(self, client, mock_user, mock_file_doc):
        """Test that missing device_id generates temporary device_id"""
        with patch('backend.routes.files.get_current_user_download_dependency', return_value=lambda: mock_user):
            with patch('backend.routes.files.files_collection') as mock_collection:
                mock_collection.return_value.find_one.return_value = mock_file_doc
                
                with patch('backend.routes.files._log') as mock_log:
                    # Make request without device_id
                    response = client.get("/api/v1/files/507f1f77bcf86cd799439011/download")
                    
                    # Should generate temporary device_id and not return 400 error
                    assert response.status_code != 400
                    
                    # Verify logging includes device_id generation
                    mock_log.assert_any_call(
                        "info",
                        "Generated temporary device_id for download request",
                        expect_any=True
                    )
    
    def test_download_with_device_id_works_normally(self, client, mock_user, mock_file_doc):
        """Test that providing device_id works normally"""
        with patch('backend.routes.files.get_current_user_download_dependency', return_value=lambda: mock_user):
            with patch('backend.routes.files.files_collection') as mock_collection:
                mock_collection.return_value.find_one.return_value = mock_file_doc
                
                # Make request with device_id
                response = client.get("/api/v1/files/507f1f77bcf86cd799439011/download?device_id=test_device_123")
                
                # Should not return device_id required error
                assert response.status_code != 400
    
    def test_download_error_separation_400_vs_500(self, client, mock_user):
        """Test proper separation between 400 and 500 errors"""
        with patch('backend.routes.files.get_current_user_download_dependency', return_value=lambda: mock_user):
            with patch('backend.routes.files.files_collection') as mock_collection:
                # Simulate database error that should return 500
                mock_collection.return_value.find_one.side_effect = Exception("Database connection failed")
                
                response = client.get("/api/v1/files/507f1f77bcf86cd799439011/download?device_id=test_device")
                
                # Should return 500 for server errors
                assert response.status_code == 500
    
    def test_download_client_error_returns_400(self, client, mock_user):
        """Test that client validation errors return 400"""
        with patch('backend.routes.files.get_current_user_download_dependency', return_value=lambda: mock_user):
            with patch('backend.routes.files.files_collection') as mock_collection:
                # Simulate validation error that should return 400
                mock_collection.return_value.find_one.side_effect = ValueError("Invalid file ID format")
                
                response = client.get("/api/v1/files/invalid_file_id/download?device_id=test_device")
                
                # Should return 400 for client errors
                assert response.status_code == 400
    
    def test_download_logging_includes_device_id(self, client, mock_user, mock_file_doc):
        """Test that all download logs include device_id"""
        with patch('backend.routes.files.get_current_user_download_dependency', return_value=lambda: mock_user):
            with patch('backend.routes.files.files_collection') as mock_collection:
                mock_collection.return_value.find_one.return_value = mock_file_doc
                
                with patch('backend.routes.files._log') as mock_log:
                    # Make request with device_id
                    response = client.get("/api/v1/files/507f1f77bcf86cd799439011/download?device_id=test_device_123")
                    
                    # Verify logging includes device_id
                    log_calls = [call.args for call in mock_log.call_args_list]
                    device_id_logged = any('device_id' in str(call) for call in log_calls)
                    assert device_id_logged, "device_id should be included in logs"
    
    def test_download_unauthenticated_returns_401(self, client):
        """Test that unauthenticated requests return 401"""
        with patch('backend.routes.files.get_current_user_download_dependency', return_value=lambda: None):
            response = client.get("/api/v1/files/507f1f77bcf86cd799439011/download")
            
            # Should return 401 for unauthenticated
            assert response.status_code == 401
    
    def test_download_web_client_user_agent_detection(self, client, mock_user, mock_file_doc):
        """Test that web clients are properly detected by User-Agent"""
        with patch('backend.routes.files.get_current_user_download_dependency', return_value=lambda: mock_user):
            with patch('backend.routes.files.files_collection') as mock_collection:
                mock_collection.return_value.find_one.return_value = mock_file_doc
                
                with patch('backend.routes.files._log') as mock_log:
                    # Make request with browser User-Agent
                    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                    response = client.get("/api/v1/files/507f1f77bcf86cd799439011/download", headers=headers)
                    
                    # Should detect as web client
                    assert response.status_code != 400
    
    def test_download_mobile_client_user_agent_detection(self, client, mock_user, mock_file_doc):
        """Test that mobile clients are properly detected by User-Agent"""
        with patch('backend.routes.files.get_current_user_download_dependency', return_value=lambda: mock_user):
            with patch('backend.routes.files.files_collection') as mock_collection:
                mock_collection.return_value.find_one.return_value = mock_file_doc
                
                with patch('backend.routes.files._log') as mock_log:
                    # Make request with mobile User-Agent
                    headers = {"User-Agent": "HypersendMobile/1.0"}
                    response = client.get("/api/v1/files/507f1f77bcf86cd799439011/download", headers=headers)
                    
                    # Should still work (generates temp device_id)
                    assert response.status_code != 400


class TestMediaDownloadFixes:
    """Test media download endpoint with device_id fixes"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    def test_media_download_without_device_id_generates_temp_id(self, client):
        """Test that media download generates temporary device_id when missing"""
        with patch('backend.routes.files.get_current_user', return_value="test_user@example.com"):
            with patch('backend.routes.files.cache') as mock_cache:
                # Mock token data
                mock_cache.get.return_value = {
                    "media_id": "test_media_123",
                    "user_id": "test_user@example.com",
                    "device_id": None,
                    "download_count": 0,
                    "max_downloads": 1
                }
                
                with patch('backend.routes.files._log') as mock_log:
                    # Make request without device_id
                    response = client.get("/api/v1/files/download/test_token_123")
                    
                    # Should generate temporary device_id and not return 400 error
                    assert response.status_code != 400
                    
                    # Verify logging includes device_id generation
                    mock_log.assert_any_call(
                        "info",
                        "Generated temporary device_id for media download",
                        expect_any=True
                    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
