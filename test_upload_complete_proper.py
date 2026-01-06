#!/usr/bin/env python3
"""
Proper pytest tests for upload complete endpoint with mocking and error isolation
"""

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status
import sys
import os
sys.path.append('backend')

# Import the app
from main import app

class TestUploadCompleteEndpoint:
    """Test upload complete endpoint with proper mocking and error isolation"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_user_token(self):
        """Mock valid user token"""
        return "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1MDdmMWY3N2JjZjg2Y2Q3OTk0MzAxMSIsInRva2VuX3R5cGUiOiJhY2Nlc3MiLCJleHAiOjk5OTk5OTk5OTl9.invalid"
    
    @pytest.fixture
    def mock_upload_doc(self):
        """Mock upload document"""
        return {
            "_id": "upload_3cd723f21a564b87",
            "user_id": "507f1f77bcf86cd799439011",
            "filename": "test_file.pdf",
            "size": 1024000,
            "mime_type": "application/pdf",
            "total_chunks": 3,
            "uploaded_chunks": [0, 1, 2],
            "checksum": "d41d8cd98f00b204e9800998ecf8427e",
            "chat_id": None,
            "created_at": "2026-01-06T19:41:00Z"
        }
    
    @pytest.mark.asyncio
    async def test_upload_complete_success(self, client, mock_user_token, mock_upload_doc):
        """Test successful upload completion"""
        with patch('auth.utils.decode_token') as mock_decode:
            # Mock token decode to return valid user
            mock_decode.return_value = MagicMock(
                user_id="507f1f77bcf86cd799439011",
                token_type="access",
                payload={}
            )
            
            with patch('db_proxy.uploads_collection') as mock_uploads:
                # Mock upload document retrieval
                mock_uploads.return_value.find_one = AsyncMock(return_value=mock_upload_doc)
                
                with patch('db_proxy.files_collection') as mock_files:
                    # Mock file insertion
                    mock_files.return_value.insert_one = AsyncMock(return_value=MagicMock(inserted_id="file_123"))
                    
                    with patch('pathlib.Path.exists', return_value=True):
                        with patch('pathlib.Path.mkdir'):
                            with patch('pathlib.Path.stat') as mock_stat:
                                # Mock file size
                                mock_stat.return_value.st_size = 1024000
                                
                                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                                    # Mock temp file creation
                                    mock_temp.return_value.__enter__ = MagicMock()
                                    mock_temp.return_value.__exit__ = MagicMock()
                                    
                                    with patch('shutil.move'):
                                        with patch('os.chmod'):
                                            # Make the request
                                            response = client.post(
                                                "/api/v1/files/upload_3cd723f21a564b87/complete",
                                                headers={"Authorization": mock_user_token}
                                            )
                                            
                                            # Assertions
                                            assert response.status_code == 200
                                            
                                            response_data = response.json()
                                            assert "file_id" in response_data
                                            assert "filename" in response_data
                                            assert "size" in response_data
                                            assert "checksum" in response_data
                                            assert "storage_path" in response_data
                                            
                                            assert response_data["filename"] == "test_file.pdf"
                                            assert response_data["size"] == 1024000
    
    @pytest.mark.asyncio
    async def test_upload_complete_invalid_upload_id(self, client, mock_user_token):
        """Test upload complete with invalid upload_id"""
        with patch('auth.utils.decode_token') as mock_decode:
            mock_decode.return_value = MagicMock(
                user_id="507f1f77bcf86cd799439011",
                token_type="access",
                payload={}
            )
            
            # Test various invalid upload IDs
            invalid_ids = ["", "null", "undefined", "   ", "invalid/id"]
            
            for invalid_id in invalid_ids:
                response = client.post(
                    f"/api/v1/files/{invalid_id}/complete",
                    headers={"Authorization": mock_user_token}
                )
                
                # Should return 400 for invalid upload_id
                assert response.status_code == 400
                assert "Invalid upload ID" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_upload_complete_upload_not_found(self, client, mock_user_token):
        """Test upload complete when upload not found"""
        with patch('auth.utils.decode_token') as mock_decode:
            mock_decode.return_value = MagicMock(
                user_id="507f1f77bcf86cd799439011",
                token_type="access",
                payload={}
            )
            
            with patch('db_proxy.uploads_collection') as mock_uploads:
                # Mock upload not found (returns None)
                mock_uploads.return_value.find_one = AsyncMock(return_value=None)
                
                response = client.post(
                    "/api/v1/files/upload_nonexistent/complete",
                    headers={"Authorization": mock_user_token}
                )
                
                # Should return 404
                assert response.status_code == 404
                assert "Upload not found or expired" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_upload_complete_missing_chunks(self, client, mock_user_token):
        """Test upload complete with missing chunks"""
        with patch('auth.utils.decode_token') as mock_decode:
            mock_decode.return_value = MagicMock(
                user_id="507f1f77bcf86cd799439011",
                token_type="access",
                payload={}
            )
            
            # Mock upload document with missing chunks
            incomplete_upload = {
                "_id": "upload_3cd723f21a564b87",
                "user_id": "507f1f77bcf86cd799439011",
                "filename": "test_file.pdf",
                "size": 1024000,
                "mime_type": "application/pdf",
                "total_chunks": 3,
                "uploaded_chunks": [0, 1],  # Missing chunk 2
                "checksum": "d41d8cd98f00b204e9800998ecf8427e",
                "chat_id": None
            }
            
            with patch('db_proxy.uploads_collection') as mock_uploads:
                mock_uploads.return_value.find_one = AsyncMock(return_value=incomplete_upload)
                
                response = client.post(
                    "/api/v1/files/upload_3cd723f21a564b87/complete",
                    headers={"Authorization": mock_user_token}
                )
                
                # Should return 400 for missing chunks
                assert response.status_code == 400
                assert "Missing chunks: [2]" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_upload_complete_unauthorized_user(self, client, mock_user_token):
        """Test upload complete with wrong user"""
        with patch('auth.utils.decode_token') as mock_decode:
            mock_decode.return_value = MagicMock(
                user_id="different_user_id",  # Different user
                token_type="access",
                payload={}
            )
            
            with patch('db_proxy.uploads_collection') as mock_uploads:
                # Mock upload belonging to different user
                upload_doc = {
                    "_id": "upload_3cd723f21a564b87",
                    "user_id": "507f1f77bcf86cd799439011",  # Original user
                    "filename": "test_file.pdf",
                    "size": 1024000,
                    "mime_type": "application/pdf",
                    "total_chunks": 1,
                    "uploaded_chunks": [0],
                    "checksum": "d41d8cd98f00b204e9800998ecf8427e",
                    "chat_id": None
                }
                
                mock_uploads.return_value.find_one = AsyncMock(return_value=upload_doc)
                
                response = client.post(
                    "/api/v1/files/upload_3cd723f21a564b87/complete",
                    headers={"Authorization": mock_user_token}
                )
                
                # Should return 403 for wrong user
                assert response.status_code == 403
                assert "You don't have permission" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_upload_complete_no_auth(self, client):
        """Test upload complete without authentication"""
        response = client.post(
            "/api/v1/files/upload_3cd723f21a564b87/complete"
        )
        
        # Should return 401 for no auth
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_upload_complete_invalid_token(self, client):
        """Test upload complete with invalid token"""
        response = client.post(
            "/api/v1/files/upload_3cd723f21a564b87/complete",
            headers={"Authorization": "Bearer invalid_token"}
        )
        
        # Should return 401 for invalid token
        assert response.status_code == 401

class TestTokenValidation:
    """Test token validation with proper error isolation"""
    
    @pytest.mark.asyncio
    async def test_upload_token_validation_strict(self):
        """Test that upload_scope must be explicitly True"""
        from auth.utils import get_current_user_for_upload
        from fastapi import Request
        import jwt
        from config import settings
        
        # Create token with upload_scope=False (should be rejected)
        payload_false = {
            "sub": "507f1f77bcf86cd799439011",
            "token_type": "access",
            "upload_scope": False,  # Explicitly False
            "exp": 9999999999,  # Future timestamp
            "iat": 1736205600
        }
        
        token_false = jwt.encode(payload_false, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        # Create mock request
        request = MagicMock()
        request.headers = {"authorization": f"Bearer {token_false}"}
        
        # Should raise HTTPException for upload_scope=False
        with pytest.raises(Exception) as exc_info:
            await get_current_user_for_upload(request)
        
        # Should not use upload token validation
        assert exc_info.value.status_code == 200  # Regular access token should work
        
        # Create token with upload_scope=True (should use upload validation)
        payload_true = {
            "sub": "507f1f77bcf86cd799439011",
            "token_type": "access",
            "upload_scope": True,  # Explicitly True
            "upload_id": "upload_3cd723f21a564b87",
            "exp": 9999999999,
            "iat": 1736205600
        }
        
        token_true = jwt.encode(payload_true, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        request.headers = {"authorization": f"Bearer {token_true}"}
        
        # Should call validate_upload_token for upload_scope=True
        with patch('auth.utils.validate_upload_token') as mock_validate:
            mock_validate.return_value = "507f1f77bcf86cd799439011"
            
            result = await get_current_user_for_upload(request)
            assert result == "507f1f77bcf86cd799439011"
            mock_validate.assert_called_once()

class TestSecurityValidation:
    """Test security validation in endpoint context"""
    
    @pytest.mark.asyncio
    async def test_path_traversal_in_upload_id(self):
        """Test path traversal in upload_id parameter"""
        from validators import validate_path_injection
        
        # Test various path traversal attempts
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "file\x00.txt",
            "normal/../../../etc/passwd"
        ]
        
        for path in malicious_paths:
            result = validate_path_injection(path)
            assert result is False, f"Path traversal not blocked: {path}"
    
    @pytest.mark.asyncio
    async def test_command_injection_in_filename(self):
        """Test command injection in filename"""
        from validators import validate_command_injection
        
        # Test various command injection attempts
        malicious_commands = [
            "file; rm -rf /",
            "file|cat /etc/passwd",
            "file`whoami`",
            "file$(id)",
            "file&& echo hacked",
            "file|| curl evil.com"
        ]
        
        for cmd in malicious_commands:
            result = validate_command_injection(cmd)
            assert result is False, f"Command injection not blocked: {cmd}"

if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v", "--tb=short"])
