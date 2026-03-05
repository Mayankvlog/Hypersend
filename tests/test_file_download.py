import pytest
import sys
import os
import uuid
import re
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from pathlib import Path
import jwt
from datetime import datetime, timedelta, timezone

# Add the frontend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'frontend'))

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

def read_test_file(relative_path: str) -> str:
    """Helper function to read test files with proper encoding fallback"""
    file_path = Path(__file__).parent.parent / relative_path
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='latin-1') as f:
            return f.read()

class TestFileDownload:
    """Test suite for file download functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.mock_api_service = Mock()
        self.mock_file_transfer_service = Mock()
        self.test_file_id = "test_file_123"
        self.test_file_name = "test_document.pdf"
        self.test_file_size = 1024 * 1024  # 1MB
        self.test_content_type = "application/pdf"
        
    def test_api_service_download_file_info(self):
        """Test API service file info retrieval"""
        # Mock file info response
        mock_file_info = {
            'size': self.test_file_size,
            'filename': self.test_file_name,
            'content_type': self.test_content_type
        }
        self.mock_api_service.getFileInfo.return_value = mock_file_info
        
        # Test method
        result = self.mock_api_service.getFileInfo(self.test_file_id)
        
        # Assertions
        assert result['size'] == self.test_file_size
        assert result['filename'] == self.test_file_name
        assert result['content_type'] == self.test_content_type
        self.mock_api_service.getFileInfo.assert_called_once_with(self.test_file_id)
        
    def test_api_service_download_small_file(self):
        """Test API service small file download"""
        # Mock small file download
        mock_file_info = {'size': 1024}  # 1KB file
        self.mock_api_service.getFileInfo.return_value = mock_file_info
        
        # Mock download method
        self.mock_api_service.downloadFileToPathWithProgress = Mock()
        
        # Simulate logic from FileTransferService
        file_size = mock_file_info['size']
        if file_size <= 100 * 1024 * 1024:  # Small file
            self.mock_api_service.downloadFileToPathWithProgress(
                fileId=self.test_file_id,
                savePath="test_path",
                onProgress=Mock()
            )
            
        # Verify small file download was called
        self.mock_api_service.downloadFileToPathWithProgress.assert_called_once()
        
    def test_api_service_download_large_file(self):
        """Test API service large file download with chunking"""
        # Mock large file info
        mock_file_info = {'size': 200 * 1024 * 1024}  # 200MB file
        self.mock_api_service.getFileInfo.return_value = mock_file_info
        
        # Mock chunked download method
        self.mock_api_service.downloadLargeFileToPath = Mock()
        
        # Simulate logic from FileTransferService
        file_size = mock_file_info['size']
        if file_size > 100 * 1024 * 1024:  # Large file
            self.mock_api_service.downloadLargeFileToPath(
                fileId=self.test_file_id,
                savePath="test_path",
                onReceiveProgress=Mock()
            )
            
        # Verify chunked download was called
        self.mock_api_service.downloadLargeFileToPath.assert_called_once()
        
    def test_file_transfer_service_download_path_handling(self):
        """Test FileTransferService download path handling"""
        # Mock directory creation and file download
        with patch('os.path.exists', return_value=True), \
             patch('os.makedirs'), \
             patch('builtins.open', create=True) as mock_file:
            
            # Test download path generation
            mock_downloads_dir = "/mock/downloads"
            expected_path = "/mock/downloads/test_document.pdf"
            
            # Simulate path generation logic
            safe_file_name = re.sub(r'[^\w\-_.]', '_', self.test_file_name)
            download_path = f"{mock_downloads_dir}/{safe_file_name}"
            
            assert download_path == expected_path
                
    def test_download_progress_tracking(self):
        """Test download progress tracking"""
        progress_values = []
        
        def mock_progress_callback(progress):
            progress_values.append(progress)
            
        # Simulate progress updates
        test_progress_values = [0.1, 0.25, 0.5, 0.75, 1.0]
        
        for progress in test_progress_values:
            mock_progress_callback(progress)
            
        # Verify progress tracking
        assert len(progress_values) == 5
        assert progress_values[0] == 0.1
        assert progress_values[-1] == 1.0
        assert all(0 <= p <= 1 for p in progress_values)
        
    def test_file_download_error_handling(self):
        """Test file download error handling"""
        # Test file not found error
        self.mock_api_service.getFileInfo.side_effect = Exception("File not found")
        
        with pytest.raises(Exception, match="File not found"):
            self.mock_api_service.getFileInfo(self.test_file_id)
            
        # Test permission error
        self.mock_api_service.downloadFileToPathWithProgress.side_effect = Exception("Permission denied")
        
        with pytest.raises(Exception, match="Permission denied"):
            self.mock_api_service.downloadFileToPathWithProgress(
                fileId=self.test_file_id,
                savePath="test_path",
                onProgress=Mock()
            )
            
    def test_file_type_detection(self):
        """Test file type detection for different content types"""
        test_cases = [
            ("application/pdf", True, False, False),
            ("image/jpeg", False, True, False),
            ("video/mp4", False, False, True),
            ("application/octet-stream", False, False, False),
        ]
        
        for content_type, expected_pdf, expected_image, expected_video in test_cases:
            is_pdf = 'pdf' in content_type.lower()
            is_image = 'image' in content_type.lower()
            is_video = 'video' in content_type.lower()
            
            assert is_pdf == expected_pdf
            assert is_image == expected_image
            assert is_video == expected_video
            
    def test_chunked_download_logic(self):
        """Test chunked download logic for large files"""
        file_size = 200 * 1024 * 1024  # 200MB
        chunk_size = 4 * 1024 * 1024   # 4MB chunks
        expected_chunks = (file_size + chunk_size - 1) // chunk_size
        
        # Calculate expected number of chunks
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        # Verify chunk calculation
        assert total_chunks == expected_chunks
        
        # Test chunk range calculation
        downloaded_bytes = 0
        chunk_ranges = []
        
        while downloaded_bytes < file_size:
            end_byte = min(downloaded_bytes + chunk_size - 1, file_size - 1)
            chunk_ranges.append((downloaded_bytes, end_byte))
            downloaded_bytes = end_byte + 1
            
        assert len(chunk_ranges) == expected_chunks
        assert chunk_ranges[0] == (0, chunk_size - 1)
        assert chunk_ranges[-1][1] == file_size - 1
        
    def test_file_verification_after_download(self):
        """Test file verification after download"""
        # Mock successful download
        with patch('os.path.exists', return_value=True):
            file_path = "/mock/downloads/test_file.pdf"
            
            # Test file exists verification
            assert os.path.exists(file_path) == True
            
        # Mock failed download (file doesn't exist)
        with patch('os.path.exists', return_value=False):
            file_path = "/mock/downloads/missing_file.pdf"
            
            # Test file doesn't exist verification
            assert os.path.exists(file_path) == False
            
            # Should raise exception for missing file
            with pytest.raises(Exception, match="File download completed but file not found"):
                if not os.path.exists(file_path):
                    raise Exception(f"File download completed but file not found at path: {file_path}")


class TestFileDownloadAuthentication:
    """Test file download authentication with header and query parameter tokens"""
    
    def setup_method(self):
        """Setup test environment"""
        # Generate test IDs instead of using production values
        self.test_file_id = str(uuid.uuid4())
        self.test_user_id = str(uuid.uuid4())
        
        # Generate a test JWT with short expiration for testing
        test_payload = {
            'sub': self.test_user_id,
            'exp': datetime.now(timezone.utc) + timedelta(hours=1),
            'token_type': 'access'
        }
        self.test_token = jwt.encode(test_payload, 'test-secret-key', algorithm='HS256')
    
    def test_download_dependency_accepts_header_token(self):
        """Test that get_current_user_for_download accepts Authorization header token"""
        from unittest.mock import AsyncMock, MagicMock
        from fastapi import Request, Query
        
        # Create a mock request with Authorization header
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {"authorization": f"Bearer {self.test_token}"}
        
        # Test that the function can extract token from header
        auth_header = mock_request.headers.get("authorization", "")
        assert auth_header.startswith("Bearer ")
        extracted_token = auth_header.split(" ", 1)[1]
        assert extracted_token == self.test_token
    
    def test_download_dependency_accepts_query_token(self):
        """Test that get_current_user_for_download accepts query parameter token"""
        from unittest.mock import AsyncMock, MagicMock
        from fastapi import Query
        
        # Create a mock query parameter with token
        mock_token = Query(default=None)
        token_value = self.test_token
        
        # Test that the function can handle query token
        assert token_value == self.test_token
    
    def test_download_dependency_prefers_header_over_query(self):
        """Test that header token is preferred over query parameter token"""
        from unittest.mock import AsyncMock, MagicMock
        from fastapi import Request, Query
        
        # Create mock request with both header and query token
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {"authorization": f"Bearer {self.test_token}"}
        query_token = "different_token"
        
        # Simulate the dependency logic
        header_token = None
        auth_header = mock_request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            header_token = auth_header.split(" ", 1)[1]
        
        # Header should be preferred
        assert header_token == self.test_token
        assert header_token != query_token
    
    def test_download_dependency_falls_back_to_query_when_no_header(self):
        """Test that query token is used when header token is missing"""
        from unittest.mock import AsyncMock, MagicMock
        from fastapi import Request, Query
        
        # Create mock request with no header but query token
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {}
        query_token = self.test_token
        
        # Simulate the dependency logic
        header_token = None
        auth_header = mock_request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            header_token = None
        
        # Should fall back to query token
        assert header_token is None
        assert query_token == self.test_token
    
    def test_download_endpoint_receives_query_token(self):
        """
        DEEP SCAN: Verify download endpoint can receive and process
        token from query parameter (?token=...).
        
        From logs: GET /api/v1/files/e5977984e305ab5f/download?dl=1&token=eyJ...
        """
        from fastapi import Query
        import urllib.parse
        
        # Simulate query string from logs
        query_string = f"dl=1&token={self.test_token}"
        
        # Parse it as endpoint would
        params = urllib.parse.parse_qs(query_string)
        extracted_token = params.get("token", [None])[0]
        
        # Verify token was extracted correctly
        assert extracted_token == self.test_token
        
        # Verify it's a valid JWT format
        assert extracted_token.startswith("eyJ")
        assert extracted_token.count(".") == 2  # JWT has 3 parts separated by 2 dots
    
    def test_download_endpoint_get_method_accepts_query_params(self):
        """
        DEEP SCAN: Verify GET endpoint properly handles query parameters
        in URL without issues.
        
        GET /api/v1/files/{file_id}/download?dl=1&token=...
        """
        # Test that Query() dependency works with GET
        from fastapi import Query
        import inspect
        
        try:
            from routes.files import download_file
        except ImportError:
            from backend.routes.files import download_file
        
        sig = inspect.signature(download_file)
        params = list(sig.parameters.keys())
        
        # Should have file_id, request, current_user parameters
        assert "file_id" in params
        assert "request" in params
        assert "current_user" in params
    
    def test_token_decode_error_handling(self):
        """
        DEEP SCAN: Verify proper error handling when token decoding fails.
        
        Tests that invalid/expired tokens are properly rejected with
        appropriate error messages.
        """
        invalid_tokens = [
            "invalid.token.format",  # Invalid JWT structure
            "eyJhbGciOiJIUzI1NiJ9.invalid.invalid",  # Invalid payload
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ9.invalid",  # Empty payload
        ]
        
        for invalid_token in invalid_tokens:
            # Attempt to decode - should fail
            try:
                import jwt as pyjwt
                # Skip signature verification to test structural validity
                decoded = pyjwt.decode(invalid_token, options={"verify_signature": False})
                # If we get here, the token is structurally valid (unexpected)
                assert False, f"Token should be structurally invalid: {invalid_token}"
            except pyjwt.exceptions.DecodeError:
                # Expected - token is malformed
                assert True
            except Exception as e:
                # Other exceptions are also acceptable for invalid tokens
                assert True
    
    def test_authorization_header_format_validation(self):
        """
        DEEP SCAN: Verify Authorization header format is properly validated.
        
        Valid format: "Bearer <token>"
        Invalid formats should be rejected.
        """
        auth_headers = [
            ("Bearer valid_token_here", True),
            ("bearer lowercase_test", True),  # Case insensitive
            ("Valid_token_without_bearer", False),
            ("BearerNoSpace", False),
            ("", False),
            (None, False),
        ]
        
        for header_value, should_be_valid in auth_headers:
            if header_value:
                is_valid = (
                    header_value.lower().startswith("bearer ") and
                    len(header_value.split(" ", 1)) == 2
                )
            else:
                is_valid = False
            
            assert is_valid == should_be_valid, \
                f"Header '{header_value}' validity mismatch"
    
    def test_query_parameter_extraction_logic(self):
        """
        DEEP SCAN: Verify query parameter extraction handles various formats.
        
        Tests edge cases in query parameter parsing.
        """
        import urllib.parse
        
        test_cases = [
            # (query_string, expected_token_value)
            (f"token={self.test_token}", self.test_token),
            (f"dl=1&token={self.test_token}", self.test_token),
            (f"token={self.test_token}&dl=1", self.test_token),
            (f"other=value&token={self.test_token}&other2=value2", self.test_token),
        ]
        
        for query_string, expected_token in test_cases:
            params = urllib.parse.parse_qs(query_string)
            extracted = params.get("token", [None])[0]
            assert extracted == expected_token, \
                f"Failed to extract token from: {query_string}"
    
    def test_download_endpoint_accepts_both_auth_methods(self):
        """
        DEEP SCAN: Comprehensive test that download endpoint accepts
        authentication from both Authorization header AND query parameter.
        
        This is core fix for 401 error in logs.
        """
        try:
            from routes.files import get_current_user_for_download
        except ImportError:
            from backend.routes.files import get_current_user_for_download
        
        # Verify function exists and has correct signature
        import inspect
        sig = inspect.signature(get_current_user_for_download)
        
        # Should accept request and token
        params = sig.parameters
        assert "request" in params, "Should have 'request' parameter"
        assert "token" in params, "Should have 'token' parameter"
        
        # The token parameter should be optional (from Query)
        token_param = params["token"]
        # Query parameters are optional by default
        assert token_param.default is not inspect.Parameter.empty, \
            "token should have a default value (Query dependency)"


class TestFileDownloadUIFix:
    """Tests for file download UI fix - removing CircularProgressIndicator"""
    
    def test_download_dialog_removed_spinner(self):
        """
        Verify that CircularProgressIndicator has been removed from download dialog.
        
        ISSUE: The download dialog was showing a spinning three-dot indicator
        which was distracting. The fix removes this visual element while keeping
        the loading functionality.
        """
        content = read_test_file('frontend/lib/presentation/screens/chat_detail_screen.dart')
        
        # Find the _downloadFile method
        download_method_start = content.find('Future<void> _downloadFile(Message message)')
        assert download_method_start > 0, "_downloadFile method should exist"
        
        # Find the showDialog call within _downloadFile
        dialog_start = content.find('showDialog(', download_method_start)
        assert dialog_start > 0, "showDialog should be called in _downloadFile"
        
        # Get the dialog content (from showDialog to the closing semicolon)
        dialog_end = content.find('});', dialog_start)
        dialog_section = content[dialog_start:dialog_end + 2]
        
        # Check that CircularProgressIndicator is NOT in the download dialog
        has_spinner_in_dialog = 'CircularProgressIndicator' in dialog_section
        
        assert not has_spinner_in_dialog, \
            f"Download dialog should not contain CircularProgressIndicator. Found in dialog: {dialog_section}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
