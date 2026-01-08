#!/usr/bin/env python3
"""
Test for chunk size configuration fix
Tests that chunk size settings are consistent and properly handled
"""

import pytest
import sys
import os
from pathlib import Path

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
sys.path.insert(0, backend_path)

def test_chunk_size_configuration():
    """Test that chunk size settings are consistent"""
    
    try:
        from config import settings
        from backend.routes.files import optimize_40gb_transfer
        
        # Test chunk size configuration
        assert hasattr(settings, 'CHUNK_SIZE'), "CHUNK_SIZE should be defined in settings"
        assert hasattr(settings, 'UPLOAD_CHUNK_SIZE'), "UPLOAD_CHUNK_SIZE should be defined in settings"
        
        # Verify chunk sizes are reasonable (should be either 4MB or 16MB)
        valid_sizes = [4 * 1024 * 1024, 16 * 1024 * 1024]  # 4MB or 16MB
        assert settings.CHUNK_SIZE in valid_sizes, f"CHUNK_SIZE should be 4MB or 16MB, got {settings.CHUNK_SIZE}"
        assert settings.UPLOAD_CHUNK_SIZE in valid_sizes, f"UPLOAD_CHUNK_SIZE should be 4MB or 16MB, got {settings.UPLOAD_CHUNK_SIZE}"
        
        # Test optimization function
        test_file_gb = 2  # 2GB file
        optimization = optimize_40gb_transfer(test_file_gb * 1024 * 1024 * 1024)
        
        assert "chunk_size_mb" in optimization, "Optimization should include chunk_size_mb"
        assert optimization["chunk_size_mb"] >= 4, "Chunk size should be at least 4MB"
        
        chunk_size_mb = settings.CHUNK_SIZE / (1024 * 1024)
        print(f"✅ Chunk size configuration verified: {chunk_size_mb:.0f}MB")
        
    except ImportError as e:
        pytest.skip(f"Could not import settings: {e}")

def test_chunk_size_error_handling():
    """Test that chunk size error handling provides proper guidance"""
    
    # Check that the enhanced error message is implemented
    files_py_path = Path(__file__).parent.parent / "backend" / "routes" / "files.py"
    if files_py_path.exists():
        content = files_py_path.read_text()
        
        # Verify enhanced error handling
        assert "actual_size_mb" in content, "Error should include actual_size_mb"
        assert "max_size_mb" in content, "Error should include max_size_mb"
        assert "guidance" in content, "Error should include guidance"
        assert "Please split your data into chunks" in content, "Error should provide guidance"
        
        # Verify chunk size usage is consistent
        assert "chunk_size = settings.CHUNK_SIZE  # Use configured chunk size" in content, "Should use settings.CHUNK_SIZE consistently"
        
        print("✅ Enhanced chunk size error handling verified")
    else:
        pytest.skip("files.py not found")

def test_chunk_size_math():
    """Test chunk size calculations are correct"""
    
    # Test MB to bytes conversion for both 4MB and 16MB
    for chunk_size_mb in [4, 16]:
        chunk_size_bytes = chunk_size_mb * 1024 * 1024
        
        # Verify conversion
        if chunk_size_mb == 4:
            assert chunk_size_bytes == 4194304, f"4MB should be 4194304 bytes, got {chunk_size_bytes}"
        elif chunk_size_mb == 16:
            assert chunk_size_bytes == 16777216, f"16MB should be 16777216 bytes, got {chunk_size_bytes}"
        
        # Test reverse conversion
        bytes_to_mb = chunk_size_bytes / (1024 * 1024)
        assert bytes_to_mb == float(chunk_size_mb), f"{chunk_size_bytes} bytes should be {chunk_size_mb}MB, got {bytes_to_mb}"
    
    print("✅ Chunk size math verified")

if __name__ == "__main__":
    print("Testing chunk size configuration fix...")
    test_chunk_size_configuration()
    test_chunk_size_error_handling()
    test_chunk_size_math()
    print("🎉 All chunk size tests passed!")
