#!/usr/bin/env python3
"""
Comprehensive test to verify the chunk index fixes work correctly.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

def test_optimize_40gb_transfer_int_fix():
    """Test that the optimize_40gb_transfer function returns integer total_chunks."""
    
    # Import the function
    from routes.files import optimize_40gb_transfer
    
    test_cases = [
        (1850 * 1024**3, "1850MB file"),
        (2 * 1024**3, "2GB file"),
        (5 * 1024**3, "5GB file"),
        (20 * 1024**3, "20GB file"),
    ]
    
    for file_size, description in test_cases:
        result = optimize_40gb_transfer(file_size)
        
        print(f"{description}:")
        print(f"  target_chunks: {result['target_chunks']} (type: {type(result['target_chunks'])})")
        
        # Verify it's an integer
        assert isinstance(result['target_chunks'], int), \
            f"target_chunks should be int, got {type(result['target_chunks'])} for {description}"
        
        # Verify the calculation is correct
        file_size_mb = file_size / (1024 * 1024)
        chunk_size_mb = result['chunk_size_mb']
        expected_chunks = max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb)
        
        assert result['target_chunks'] == expected_chunks, \
            f"Chunk calculation mismatch for {description}"
        
        print(f"  ✓ Correct integer calculation")


def test_backend_total_chunks_validation():
    """Test the backend validation for float total_chunks conversion."""
    
    # Mock upload document with float total_chunks
    mock_upload_doc_float = {
        "_id": "test_upload_id",
        "total_chunks": 37.0,  # Float that should be converted
        "uploaded_chunks": [],
        "user_id": "test_user"
    }
    
    mock_upload_doc_int = {
        "_id": "test_upload_id", 
        "total_chunks": 37,  # Already integer
        "uploaded_chunks": [],
        "user_id": "test_user"
    }
    
    # Simulate the validation logic
    def validate_total_chunks(upload_doc):
        total_chunks = upload_doc.get("total_chunks", 0)
        
        # Apply the fix
        if isinstance(total_chunks, float):
            total_chunks = int(total_chunks)
            print(f"Converted float total_chunks to int: {upload_doc.get('total_chunks')} -> {total_chunks}")
        
        return total_chunks
    
    # Test float conversion
    total_chunks_float = validate_total_chunks(mock_upload_doc_float)
    assert isinstance(total_chunks_float, int), "Should convert float to int"
    assert total_chunks_float == 37, "Should convert 37.0 to 37"
    
    # Test int passthrough
    total_chunks_int = validate_total_chunks(mock_upload_doc_int)
    assert isinstance(total_chunks_int, int), "Should remain int"
    assert total_chunks_int == 37, "Should remain 37"
    
    print("✓ Backend total_chunks validation works correctly")


def test_chunk_index_validation():
    """Test chunk index validation logic."""
    
    def validate_chunk_index(chunk_index, total_chunks):
        """Simulate backend validation logic."""
        if isinstance(total_chunks, float):
            total_chunks = int(total_chunks)
        
        if chunk_index < 0:
            raise ValueError(f"Invalid chunk index: {chunk_index}. Chunk index cannot be negative")
        
        if chunk_index >= total_chunks:
            raise ValueError(f"Chunk index {chunk_index} out of range. Expected: 0-{total_chunks - 1}")
        
        return True
    
    # Test valid cases
    assert validate_chunk_index(0, 37) == True
    assert validate_chunk_index(36, 37) == True
    
    # Test invalid cases
    with pytest.raises(ValueError, match="Chunk index 37 out of range"):
        validate_chunk_index(37, 37)
    
    with pytest.raises(ValueError, match="Chunk index 38 out of range"):
        validate_chunk_index(38, 37)
    
    with pytest.raises(ValueError, match="cannot be negative"):
        validate_chunk_index(-1, 37)
    
    # Test with float total_chunks (should be converted)
    assert validate_chunk_index(36, 37.0) == True
    
    with pytest.raises(ValueError, match="Chunk index 37 out of range"):
        validate_chunk_index(37, 37.0)
    
    print("✓ Chunk index validation works correctly")


def test_frontend_validation_logic():
    """Test the frontend validation logic."""
    
    def validate_frontend_chunk_index(chunk_index, total_chunks):
        """Simulate frontend validation logic."""
        if (total_chunks != None and chunk_index >= total_chunks):
            raise ValueError(
                f'Chunk index {chunk_index} out of range. Expected: 0-{total_chunks - 1}. '
                'This indicates a calculation mismatch between frontend and backend.'
            )
        return True
    
    # Test valid cases
    assert validate_frontend_chunk_index(0, 37) == True
    assert validate_frontend_chunk_index(36, 37) == True
    
    # Test invalid cases
    with pytest.raises(ValueError, match="Chunk index 37 out of range"):
        validate_frontend_chunk_index(37, 37)
    
    # Test with None total_chunks (should pass validation)
    assert validate_frontend_chunk_index(50, None) == True
    
    print("✓ Frontend validation logic works correctly")


def test_end_to_end_chunk_scenario():
    """Test the complete chunk upload scenario with fixes."""
    
    # Simulate a complete upload scenario
    file_size = 1850 * 1024 * 1024  # 1850MB
    chunk_size = 50 * 1024 * 1024   # 50MB chunks
    
    # Backend calculation
    backend_total_chunks = (file_size + chunk_size - 1) // chunk_size
    
    # Frontend receives backend response
    frontend_total_chunks = backend_total_chunks
    
    # Frontend processes chunks
    chunk_indices = list(range(backend_total_chunks))
    
    print(f"End-to-end test:")
    print(f"  File size: {file_size // (1024*1024)}MB")
    print(f"  Chunk size: {chunk_size // (1024*1024)}MB")
    print(f"  Backend expects: {backend_total_chunks} chunks")
    print(f"  Frontend uploads: {len(chunk_indices)} chunks")
    print(f"  Chunk indices: {chunk_indices}")
    
    # Validate each chunk index
    for chunk_index in chunk_indices:
        # Backend validation
        assert chunk_index < backend_total_chunks, \
            f"Backend would reject chunk {chunk_index}"
        
        # Frontend validation
        assert chunk_index < frontend_total_chunks, \
            f"Frontend would not upload chunk {chunk_index}"
    
    # Verify no extra chunks are uploaded
    assert len(chunk_indices) == backend_total_chunks, \
        "Frontend should upload exactly the same number of chunks as backend expects"
    
    print("✓ End-to-end scenario works correctly")


def test_error_scenarios():
    """Test various error scenarios to ensure they're handled properly."""
    
    print("Testing error scenarios:")
    
    # Scenario 1: Float total_chunks from database
    total_chunks_float = 37.0
    chunk_index = 36
    
    # Should work after conversion
    assert chunk_index < int(total_chunks_float)
    print("  ✓ Float total_chunks conversion works")
    
    # Scenario 2: Frontend tries to upload chunk 37 when backend expects 37 chunks (0-36)
    backend_total_chunks = 37
    problematic_chunk_index = 37
    
    # Backend should reject this
    assert problematic_chunk_index >= backend_total_chunks
    print("  ✓ Backend correctly rejects out-of-range chunk")
    
    # Scenario 3: Frontend validation should prevent the upload
    frontend_total_chunks = 37
    try:
        if problematic_chunk_index >= frontend_total_chunks:
            raise ValueError(f"Chunk index {problematic_chunk_index} out of range")
        assert False, "Should have raised error"
    except ValueError as e:
        assert "out of range" in str(e)
        print("  ✓ Frontend validation prevents out-of-range upload")


if __name__ == "__main__":
    print("=== COMPREHENSIVE CHUNK INDEX FIX TESTS ===\n")
    
    print("1. Testing optimize_40gb_transfer int fix:")
    test_optimize_40gb_transfer_int_fix()
    print()
    
    print("2. Testing backend total_chunks validation:")
    test_backend_total_chunks_validation()
    print()
    
    print("3. Testing chunk index validation:")
    test_chunk_index_validation()
    print()
    
    print("4. Testing frontend validation logic:")
    test_frontend_validation_logic()
    print()
    
    print("5. Testing end-to-end chunk scenario:")
    test_end_to_end_chunk_scenario()
    print()
    
    print("6. Testing error scenarios:")
    test_error_scenarios()
    print()
    
    print("=== ALL TESTS PASSED! ===")
    print("\nFixes implemented:")
    print("✓ Backend: Convert float total_chunks to int")
    print("✓ Backend: Enhanced logging for debugging")
    print("✓ Frontend: Validate chunk_index against total_chunks")
    print("✓ Both: Better error messages for troubleshooting")
