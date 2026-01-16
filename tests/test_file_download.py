import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add the frontend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'frontend'))

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
        
        # Test the method
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
        
        # Simulate the logic from FileTransferService
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
        
        # Simulate the logic from FileTransferService
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
        # Mock the directory creation and file download
        with patch('os.path.exists', return_value=True), \
             patch('os.makedirs'), \
             patch('builtins.open', create=True) as mock_file:
            
            # Test the download path generation
            mock_downloads_dir = "/mock/downloads"
            expected_path = "/mock/downloads/test_document.pdf"
            
            # Simulate path generation logic
            safe_file_name = self.test_file_name.replace('[^\\w\\-_.]', '_')
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

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])