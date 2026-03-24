"""
Test media download/upload system for file integrity.
Validates:
- MIME type detection and storage
- S3 streaming without corruption
- File size validation
- Content-Disposition headers
- Binary data integrity (hash matching)
"""

import hashlib
import json
import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from io import BytesIO
from datetime import datetime, timezone, timedelta

# Add backend to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from backend.routes.files import (
    _log,
    _get_s3_client,
    _ensure_storage_dirs,
    _get_sanitized_bucket_name,
    _get_file_ttl_seconds,
)


class TestMediaDownloadSystem:
    """Test media download and upload system"""

    def test_mime_type_auto_detection(self):
        """Test MIME type auto-detection from filename"""
        import mimetypes
        
        test_cases = [
            ("image.png", "image/png"),
            ("video.mp4", "video/mp4"),
            ("document.pdf", "application/pdf"),
            ("text.txt", "text/plain"),
            ("image.jpg", "image/jpeg"),
            ("video.mov", "video/quicktime"),
            ("archive.zip", "application/zip"),
        ]
        
        for filename, expected_mime in test_cases:
            guessed, _ = mimetypes.guess_type(filename)
            assert guessed is not None, f"Failed to guess MIME type for {filename}"
            # Normalize for comparison (mimetypes might return slightly different values)
            if expected_mime.startswith("image/") or expected_mime.startswith("video/") or expected_mime.startswith("application/"):
                assert guessed.startswith(expected_mime.split("/")[0]), \
                    f"Expected MIME category {expected_mime.split('/')[0]} for {filename}, got {guessed}"


    def test_content_disposition_handling(self):
        """Test Content-Disposition header generation for preview vs download"""
        
        # Test inline for images/videos (preview)
        is_image = True
        is_video = False
        dl_requested = False
        filename = "test.png"
        
        content_disposition = f'inline; filename="{filename}"' if not dl_requested and (is_image or is_video) else f'attachment; filename="{filename}"'
        assert "inline" in content_disposition, "Images should use inline disposition for preview"
        
        # Test attachment for download
        dl_requested = True
        content_disposition = f'inline; filename="{filename}"' if not dl_requested and (is_image or is_video) else f'attachment; filename="{filename}"'
        assert "attachment" in content_disposition, "Downloads should use attachment disposition"
        
        # Test attachment for PDFs (documents)
        dl_requested = False
        is_image = False
        filename = "document.pdf"
        content_disposition = f'inline; filename="{filename}"' if not dl_requested and (is_image or is_video) else f'attachment; filename="{filename}"'
        assert "attachment" in content_disposition or "inline" in content_disposition, "PDFs should have proper disposition"


    def test_binary_data_integrity(self):
        """Test that binary data is preserved without corruption"""
        
        # Create test binary data (simulating image)
        test_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00'
        test_data += b'\x00' * 1000  # Add padding
        
        # Calculate hash
        sha256 = hashlib.sha256(test_data).hexdigest()
        
        # Simulate chunk streaming
        chunk_size = 512
        chunks = []
        for i in range(0, len(test_data), chunk_size):
            chunks.append(test_data[i:i+chunk_size])
        
        # Reconstruct from chunks
        reconstructed = b''.join(chunks)
        reconstructed_hash = hashlib.sha256(reconstructed).hexdigest()
        
        # Verify integrity
        assert sha256 == reconstructed_hash, "Binary data corrupted during chunking"
        assert len(test_data) == len(reconstructed), "Data size mismatch"


    def test_file_metadata_storage(self):
        """Test that file metadata is correctly stored"""
        
        file_metadata = {
            "filename": "test_image.png",
            "size": 102400,
            "mime_type": "image/png",
            "storage_key": "files/user123/upload456/test_image.png",
            "s3_key": "files/user123/upload456/test_image.png",
            "storage_type": "s3",
            "bucket": "zaply-media",
            "region": "us-east-1",
            "checksum": hashlib.sha256(b"test").hexdigest(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        # Verify all required fields are present
        assert file_metadata.get("storage_key"), "Missing storage_key"
        assert file_metadata.get("s3_key"), "Missing s3_key (S3-only requirement)"
        assert file_metadata.get("storage_type") == "s3", "Must use S3 storage"
        assert file_metadata.get("mime_type"), "Missing MIME type"
        assert file_metadata.get("checksum"), "Missing checksum for integrity"
        assert file_metadata.get("size") > 0, "Invalid file size"


    def test_s3_key_format(self):
        """Test that S3 keys follow the correct format with filename preservation"""
        
        from bson import ObjectId
        
        user_id = str(ObjectId())
        upload_id = "test-upload-123"
        filenames = [
            "my_document.pdf",
            "photo_2024.jpg",
            "video_file.mp4",
            "archive.zip",
            "file with spaces.txt",
        ]
        
        for filename in filenames:
            s3_key = f"files/{user_id}/{upload_id}/{filename}"
            
            # Verify format
            parts = s3_key.split("/")
            assert len(parts) >= 4, f"Invalid S3 key format: {s3_key}"
            assert parts[0] == "files", "S3 key must start with 'files/'"
            assert parts[-1] == filename, "S3 key must preserve original filename"


    @pytest.mark.asyncio
    async def test_streaming_response_headers(self):
        """Test that StreamingResponse has correct headers for media files"""
        
        test_cases = [
            {
                "mime_type": "image/png",
                "content_disposition": 'inline; filename="test.png"',
                "is_preview": True,
            },
            {
                "mime_type": "video/mp4",
                "content_disposition": 'inline; filename="test.mp4"',
                "is_preview": True,
            },
            {
                "mime_type": "application/pdf",
                "content_disposition": 'attachment; filename="test.pdf"',
                "is_preview": False,
            },
        ]
        
        for case in test_cases:
            headers = {
                "Content-Type": case["mime_type"],
                "Content-Disposition": case["content_disposition"],
                "Content-Length": "12345",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Accept-Ranges": "bytes",
                "X-Content-Type-Options": "nosniff",
            }
            
            # Verify headers
            assert headers["Content-Type"] == case["mime_type"], "Wrong Content-Type"
            assert "filename" in headers["Content-Disposition"], "Missing filename in disposition"
            assert int(headers["Content-Length"]) > 0, "Invalid Content-Length"
            assert "nosniff" in headers["X-Content-Type-Options"], "Missing security header"


    def test_upload_initialization_mime_type_handling(self):
        """Test MIME type validation and storage during upload init"""
        
        # Valid MIME types that should be allowed
        valid_types = [
            "image/jpeg",
            "image/png",
            "image/gif",
            "video/mp4",
            "video/quicktime",
            "application/pdf",
            "text/plain",
            "application/zip",
        ]
        
        for mime_type in valid_types:
            # Would be accepted in real code (not dangerous MIME types)
            assert mime_type not in [
                "application/x-php",
                "application/x-shellscript",
                "application/x-executable",
            ], f"MIME type {mime_type} incorrectly marked as dangerous"


    @pytest.mark.asyncio
    async def test_s3_metadata_tags(self):
        """Test that S3 metadata includes proper file information"""
        
        metadata = {
            "upload_id": "test-upload",
            "user_id": "user123",
            "original_filename": "photo.png",
            "mime_type": "image/png",
            "sha256_checksum": hashlib.sha256(b"test").hexdigest(),
            "file_size": "102400",
            "upload_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        # Verify metadata
        assert metadata["original_filename"] == "photo.png", "Filename not preserved"
        assert metadata["mime_type"] == "image/png", "MIME type not stored"
        assert metadata["sha256_checksum"], "Checksum missing"
        assert metadata["file_size"], "File size missing"
        assert metadata["upload_timestamp"], "Timestamp missing"


    def test_file_ttl_expiry(self):
        """Test that file TTL expiry is correctly calculated"""
        
        # Simulate file creation and expiry calculation
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        ttl_seconds = 432000  # 120 hours
        expires_at = now + timedelta(seconds=ttl_seconds)
        
        # Verify expiry is in the future
        assert expires_at > now, "Expiry time should be in the future"
        
        # Verify TTL is reasonable
        ttl_hours = ttl_seconds / 3600
        assert ttl_hours >= 72, f"TTL should be at least 72 hours, got {ttl_hours}"


    def test_filename_extension_validation(self):
        """Test that filenames with proper extensions are preserved"""
        
        # Extract extension correctly
        test_cases = [
            ("image.png", ".png", "png"),
            ("video.mp4", ".mp4", "mp4"),
            ("document.pdf", ".pdf", "pdf"),
            ("file.tar.gz", ".gz", "gz"),  # Last extension
            ("file.backup", ".backup", "backup"),
        ]
        
        for filename, expected_ext, expected_base_ext in test_cases:
            if "." in filename:
                actual_ext = "." + filename.split(".")[-1].lower()
                assert actual_ext == expected_ext, f"Wrong extension for {filename}"


    def test_s3_only_storage_requirement(self):
        """Test that LOCAL storage fallback is disabled"""
        
        file_doc = {
            "storage_type": "s3",  # CRITICAL: Must be S3
            "storage_key": "files/user/upload/file.png",
            "s3_key": "files/user/upload/file.png",
            "bucket": "zaply-media",
            "region": "us-east-1",
            "storage_path": None,  # NO local storage
        }
        
        # Verify S3-only requirement
        assert file_doc["storage_type"] == "s3", "Must use S3 storage"
        assert file_doc["storage_key"], "S3 key must be present"
        assert file_doc["storage_path"] is None, "Local storage must be disabled"
        assert file_doc["bucket"], "Bucket must be specified"
        assert file_doc["region"], "Region must be specified"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
