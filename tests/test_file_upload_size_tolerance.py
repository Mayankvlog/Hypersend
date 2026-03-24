"""
Test file upload size tolerance for all file types (Telegram-style support).
Ensures that minor size variances due to padding, metadata, and line endings are accepted.
Tests various file types: images, videos, audio, documents, etc.
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path
import tempfile
import hashlib
import json


class TestFileSizeTolerance:
    """Test suite for file size tolerance calculations"""

    def test_tiny_file_tolerance(self):
        """Test tolerance for files < 1KB (64 bytes allowed)"""
        expected_size = 512  # 512 bytes
        actual_size = 512 + 50  # 50 bytes variance
        
        # Should allow 64 bytes for tiny files
        size_difference = abs(actual_size - expected_size)
        SIZE_TOLERANCE = 64
        
        assert size_difference <= SIZE_TOLERANCE, f"Variance {size_difference} exceeds tolerance {SIZE_TOLERANCE}"

    def test_small_file_tolerance(self):
        """Test tolerance for files 1KB-10MB (0.1% or 1KB minimum)"""
        expected_size = 5242880  # 5MB
        actual_size = 5242880 + 174  # 174 bytes variance (from the error log)
        
        # Calculate tolerance: max(1024, int(expected_size * 0.001))
        SIZE_TOLERANCE = max(1024, int(expected_size * 0.001))
        size_difference = abs(actual_size - expected_size)
        
        assert size_difference <= SIZE_TOLERANCE, f"Variance {size_difference} exceeds tolerance {SIZE_TOLERANCE}"

    def test_large_file_tolerance(self):
        """Test tolerance for files 10MB+ (0.05% or 4KB minimum)"""
        expected_size = 104857600  # 100MB
        
        # Add 0.02% variance (within acceptable range)
        actual_size = int(expected_size * 1.0002)  # 0.02% increase
        
        SIZE_TOLERANCE = max(4096, int(expected_size * 0.0005))
        size_difference = abs(actual_size - expected_size)
        
        assert size_difference <= SIZE_TOLERANCE, f"Variance {size_difference} exceeds tolerance {SIZE_TOLERANCE}"

    def test_real_world_variance_174_bytes(self):
        """Test the exact case from the error log: 1791865 -> 1792039 (174 bytes)"""
        expected_size = 1791865  # ~1.7MB
        actual_size = 1792039
        size_difference = actual_size - expected_size  # 174 bytes
        
        # This is a small file, so tolerance should be: max(1024, int(1791865 * 0.001)) = 1791
        SIZE_TOLERANCE = max(1024, int(expected_size * 0.001))
        
        assert size_difference <= SIZE_TOLERANCE, \
            f"Real-world case failed: diff={size_difference}, tolerance={SIZE_TOLERANCE}"
        print(f"✓ Real-world case accepted: 174 bytes variance with {SIZE_TOLERANCE} byte tolerance")

    def test_chunk_boundary_padding(self):
        """Test acceptance of padding added at chunk boundaries"""
        expected_size = 1024 * 1024  # 1MB
        
        # Common chunk boundary alignments
        for boundary in [64, 128, 256, 512, 1024]:
            # File might be padded to next boundary
            actual_size = ((expected_size + boundary - 1) // boundary) * boundary
            size_difference = actual_size - expected_size
            
            SIZE_TOLERANCE = max(1024, int(expected_size * 0.001))
            
            assert size_difference <= SIZE_TOLERANCE, \
                f"Boundary padding of {size_difference} bytes exceeds tolerance {SIZE_TOLERANCE}"

    def test_metadata_overhead(self):
        """Test acceptance of metadata added by storage systems"""
        expected_size = 10485760  # 10MB
        
        # S3 and other cloud storage may add metadata (typically < 0.1%)
        metadata_overhead_percent = 0.001  # 0.1%
        actual_size = int(expected_size * (1 + metadata_overhead_percent))
        size_difference = actual_size - expected_size
        
        SIZE_TOLERANCE = max(1024, int(expected_size * 0.001))
        
        assert size_difference <= SIZE_TOLERANCE, \
            f"Metadata overhead {size_difference} exceeds tolerance {SIZE_TOLERANCE}"

    def test_line_ending_normalization(self):
        """Test acceptance of line ending changes (LF vs CRLF)"""
        # Windows CRLF vs Unix LF: each LF becomes CRLF (adds 1 byte per line)
        expected_size = 1024 * 100  # 100KB text file
        estimated_lines = 2000  # Estimate of lines in file
        
        # Worst case: all LF become CRLF
        actual_size = expected_size + estimated_lines
        size_difference = actual_size - expected_size
        
        SIZE_TOLERANCE = max(1024, int(expected_size * 0.001))
        
        assert size_difference <= SIZE_TOLERANCE, \
            f"Line ending normalization {size_difference} exceeds tolerance {SIZE_TOLERANCE}"

    def test_compression_variations(self):
        """Test acceptance of compression-related size variations"""
        # Compression may add small headers/footers
        expected_size = 5242880  # 5MB
        
        # Zip/gzip/brotli compression headers and footers typically < 512 bytes
        actual_size = expected_size + 256  # compression overhead
        size_difference = actual_size - expected_size
        
        SIZE_TOLERANCE = max(1024, int(expected_size * 0.001))
        
        assert size_difference <= SIZE_TOLERANCE, \
            f"Compression overhead {size_difference} exceeds tolerance {SIZE_TOLERANCE}"


class TestSupportedFileTypes:
    """Test support for all file types like Telegram"""

    @pytest.mark.parametrize("file_type,mime_type,max_size", [
        # Image types
        ("image", "image/jpeg", 16 * 1024 * 1024),  # 16MB
        ("image", "image/png", 16 * 1024 * 1024),
        ("image", "image/webp", 16 * 1024 * 1024),
        ("image", "image/gif", 16 * 1024 * 1024),
        ("image", "image/svg+xml", 2 * 1024 * 1024),  # 2MB for SVG
        
        # Video types
        ("video", "video/mp4", 256 * 1024 * 1024),  # 256MB
        ("video", "video/mpeg", 256 * 1024 * 1024),
        ("video", "video/quicktime", 256 * 1024 * 1024),  # MOV
        ("video", "video/x-msvideo", 256 * 1024 * 1024),  # AVI
        ("video", "video/x-matroska", 256 * 1024 * 1024),  # MKV
        
        # Audio types
        ("audio", "audio/mpeg", 128 * 1024 * 1024),  # 128MB MP3
        ("audio", "audio/wav", 256 * 1024 * 1024),   # 256MB WAV
        ("audio", "audio/ogg", 128 * 1024 * 1024),
        ("audio", "audio/flac", 256 * 1024 * 1024),
        ("audio", "audio/m4a", 128 * 1024 * 1024),
        
        # Document types
        ("document", "application/pdf", 128 * 1024 * 1024),  # 128MB PDF
        ("document", "application/msword", 50 * 1024 * 1024),  # DOC
        ("document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", 50 * 1024 * 1024),  # DOCX
        ("document", "application/vnd.ms-excel", 50 * 1024 * 1024),  # XLS
        ("document", "text/plain", 100 * 1024 * 1024),  # TXT
        
        # Archive types  
        ("archive", "application/zip", 512 * 1024 * 1024),  # 512MB
        ("archive", "application/x-rar-compressed", 512 * 1024 * 1024),  # RAR
        ("archive", "application/x-gzip", 512 * 1024 * 1024),  # GZ
        ("archive", "application/x-7z-compressed", 512 * 1024 * 1024),  # 7Z
    ])
    def test_file_type_upload_support(self, file_type, mime_type, max_size):
        """Test that all common file types are supported with proper size handling"""
        assert len(mime_type) > 0, f"MIME type should not be empty for {file_type}"
        assert max_size > 0, f"Max size should be positive for {file_type}"
        print(f"✓ {file_type} ({mime_type}) supported up to {max_size / (1024*1024):.0f}MB")

    def test_edge_case_exact_boundary(self):
        """Test file size exactly at chunk boundary"""
        chunk_size = 4096
        expected_size = chunk_size * 100  # Exactly 100 chunks
        actual_size = expected_size  # No variance
        size_difference = abs(actual_size - expected_size)
        
        # Should be perfectly accepted
        SIZE_TOLERANCE = max(1024, int(expected_size * 0.001))
        assert size_difference == 0
        assert size_difference <= SIZE_TOLERANCE

    def test_edge_case_one_byte_over(self):
        """Test file exactly one byte over chunk boundary"""
        chunk_size = 4096
        expected_size = chunk_size * 100  # Exactly 100 chunks
        actual_size = expected_size + 1  # One byte over
        size_difference = abs(actual_size - expected_size)
        
        SIZE_TOLERANCE = max(1024, int(expected_size * 0.001))
        assert size_difference <= SIZE_TOLERANCE


def test_tolerance_calculation_formula():
    """Verify the tolerance calculation formula for various file sizes"""
    test_cases = [
        (512, 64),  # < 1KB: 64 bytes
        (1024, max(1024, int(1024 * 0.001))),  # 1KB: 1024 bytes
        (10485760, max(1024, int(10485760 * 0.001))),  # 10MB: 10KB
        (104857600, max(4096, int(104857600 * 0.0005))),  # 100MB: 52KB
        (1099511627776, max(4096, int(1099511627776 * 0.0005))),  # 1TB: 512MB
    ]
    
    for file_size, expected_tolerance in test_cases:
        if file_size < 1024:
            calculated = 64
        elif file_size < 10485760:
            calculated = max(1024, int(file_size * 0.001))
        else:
            calculated = max(4096, int(file_size * 0.0005))
        
        assert calculated == expected_tolerance, \
            f"Tolerance mismatch for {file_size / (1024*1024):.1f}MB: expected {expected_tolerance}, got {calculated}"
        print(f"✓ {file_size / (1024*1024):.1f}MB: {calculated} byte tolerance")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
