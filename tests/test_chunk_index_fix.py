#!/usr/bin/env python3
"""
Test to reproduce the "Chunk index 37 out of range. Expected: 0-36" error.

This test simulates the exact scenario where the frontend calculates one more chunk
than the backend expects, causing the out-of-range error.
"""

import pytest
import asyncio
import math
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status
import json

# Import the functions we need to test
from backend.routes.files import optimize_40gb_transfer


class TestChunkIndexError:
    """Test cases for chunk index calculation mismatch between frontend and backend."""
    
    def test_chunk_calculation_exact_divisible_file(self):
        """Test chunk calculation when file size is exactly divisible by chunk size."""
        # Simulate the exact scenario from the error logs
        file_size = 50 * 1024 * 1024  # 50MB file
        chunk_size = 50 * 1024 * 1024  # 50MB chunk size
        
        # Backend calculation (ceiling division)
        backend_total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        # Simulate frontend chunk processing
        frontend_chunks = []
        remaining_size = file_size
        chunk_index = 0
        
        # Frontend processes full chunks
        while remaining_size >= chunk_size:
            frontend_chunks.append(chunk_index)
            chunk_index += 1
            remaining_size -= chunk_size
        
        # Frontend processes remaining tail (if any)
        if remaining_size > 0:
            frontend_chunks.append(chunk_index)
            chunk_index += 1
        
        print(f"File size: {file_size} bytes")
        print(f"Chunk size: {chunk_size} bytes") 
        print(f"Backend total_chunks: {backend_total_chunks}")
        print(f"Frontend chunks uploaded: {len(frontend_chunks)}")
        print(f"Frontend chunk indices: {frontend_chunks}")
        
        # This should pass for exact division
        assert len(frontend_chunks) == backend_total_chunks, \
            f"Frontend uploaded {len(frontend_chunks)} chunks, backend expected {backend_total_chunks}"
        
        # Verify no chunk exceeds backend limit
        for chunk_idx in frontend_chunks:
            assert chunk_idx < backend_total_chunks, \
                f"Chunk {chunk_idx} exceeds backend limit of {backend_total_chunks - 1}"
    
    def test_chunk_calculation_with_remainder(self):
        """Test chunk calculation when file size has remainder."""
        # File size that's not exactly divisible
        file_size = 51 * 1024 * 1024  # 51MB file
        chunk_size = 50 * 1024 * 1024  # 50MB chunk size
        
        # Backend calculation (ceiling division)
        backend_total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        # Simulate frontend chunk processing
        frontend_chunks = []
        remaining_size = file_size
        chunk_index = 0
        
        # Frontend processes full chunks
        while remaining_size >= chunk_size:
            frontend_chunks.append(chunk_index)
            chunk_index += 1
            remaining_size -= chunk_size
        
        # Frontend processes remaining tail (if any)
        if remaining_size > 0:
            frontend_chunks.append(chunk_index)
            chunk_index += 1
        
        print(f"File size: {file_size} bytes")
        print(f"Chunk size: {chunk_size} bytes") 
        print(f"Backend total_chunks: {backend_total_chunks}")
        print(f"Frontend chunks uploaded: {len(frontend_chunks)}")
        print(f"Frontend chunk indices: {frontend_chunks}")
        
        # This should also pass
        assert len(frontend_chunks) == backend_total_chunks, \
            f"Frontend uploaded {len(frontend_chunks)} chunks, backend expected {backend_total_chunks}"
        
        # Verify no chunk exceeds backend limit
        for chunk_idx in frontend_chunks:
            assert chunk_idx < backend_total_chunks, \
                f"Chunk {chunk_idx} exceeds backend limit of {backend_total_chunks - 1}"
    
    def test_reproduce_error_scenario(self):
        """Reproduce the exact error scenario from the logs."""
        # Based on the error: "Chunk index 37 out of range. Expected: 0-36"
        # This means backend expects 37 chunks (0-36), but frontend tries to upload chunk 37
        
        backend_total_chunks = 37  # Backend expects chunks 0-36
        file_size = 37 * 50 * 1024 * 1024  # 37 * 50MB = 1850MB
        chunk_size = 50 * 1024 * 1024  # 50MB chunks
        
        # Backend calculation verification
        calculated_backend_chunks = (file_size + chunk_size - 1) // chunk_size
        assert calculated_backend_chunks == backend_total_chunks
        
        # Simulate the buggy frontend logic that causes the error
        frontend_chunks = []
        remaining_size = file_size
        chunk_index = 0
        
        # Frontend processes full chunks
        while remaining_size >= chunk_size:
            frontend_chunks.append(chunk_index)
            chunk_index += 1
            remaining_size -= chunk_size
        
        # Frontend processes remaining tail (if any)
        if remaining_size > 0:
            frontend_chunks.append(chunk_index)
            chunk_index += 1
        
        # BUG: The frontend incorrectly increments chunk_index one extra time
        # This simulates the exact error from the logs
        buggy_extra_chunk = chunk_index  # This would be 37 in the error case
        frontend_chunks.append(buggy_extra_chunk)
        
        print(f"Backend expects chunks: 0-{backend_total_chunks - 1}")
        print(f"Frontend uploaded chunks: {frontend_chunks}")
        print(f"Problematic chunk: {buggy_extra_chunk}")
        
        # Verify this reproduces the error
        assert buggy_extra_chunk >= backend_total_chunks, \
            f"Should reproduce error: chunk {buggy_extra_chunk} >= {backend_total_chunks}"
        
        # The error message should match
        expected_error = f"Chunk index {buggy_extra_chunk} out of range. Expected: 0-{backend_total_chunks - 1}"
        print(f"Expected error message: {expected_error}")
    
    def test_optimize_40gb_transfer_chunk_calculation(self):
        """Test the optimize_40gb_transfer function for correct chunk calculation."""
        # Test various file sizes
        test_cases = [
            (2 * 1024**3, "2GB"),   # 2GB
            (5 * 1024**3, "5GB"),   # 5GB  
            (15 * 1024**3, "15GB"), # 15GB
            (30 * 1024**3, "30GB"), # 30GB
            (40 * 1024**3, "40GB"), # 40GB
        ]
        
        for file_size, description in test_cases:
            optimization = optimize_40gb_transfer(file_size)
            
            chunk_size_mb = optimization["chunk_size_mb"]
            target_chunks = optimization["target_chunks"]
            
            # Verify chunk calculation is correct
            file_size_mb = file_size / (1024 * 1024)
            expected_chunks = max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb)
            
            print(f"{description}: {target_chunks} chunks of {chunk_size_mb}MB each")
            print(f"  Expected chunks: {expected_chunks}")
            print(f"  File size: {file_size_mb:.0f}MB")
            
            assert target_chunks == expected_chunks, \
                f"Chunk calculation mismatch for {description}: got {target_chunks}, expected {expected_chunks}"
            
            # Verify optimization data is consistent
            assert optimization["file_size_bytes"] == file_size
            assert optimization["optimization_applied"] is True
            assert optimization["chunk_size_mb"] > 0
            assert optimization["target_chunks"] > 0
    
    def test_edge_case_single_chunk_file(self):
        """Test edge case where file fits in single chunk."""
        file_size = 25 * 1024 * 1024  # 25MB file
        chunk_size = 50 * 1024 * 1024  # 50MB chunk size
        
        # Backend calculation
        backend_total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        # Frontend simulation
        frontend_chunks = []
        remaining_size = file_size
        chunk_index = 0
        
        # Frontend processes full chunks (none in this case)
        while remaining_size >= chunk_size:
            frontend_chunks.append(chunk_index)
            chunk_index += 1
            remaining_size -= chunk_size
        
        # Frontend processes remaining tail (the entire file)
        if remaining_size > 0:
            frontend_chunks.append(chunk_index)
            chunk_index += 1
        
        print(f"Single chunk test:")
        print(f"  File size: {file_size} bytes")
        print(f"  Chunk size: {chunk_size} bytes")
        print(f"  Backend chunks: {backend_total_chunks}")
        print(f"  Frontend chunks: {len(frontend_chunks)}")
        print(f"  Frontend indices: {frontend_chunks}")
        
        assert backend_total_chunks == 1
        assert len(frontend_chunks) == 1
        assert frontend_chunks[0] == 0  # Should be chunk index 0


if __name__ == "__main__":
    # Run the tests
    test_instance = TestChunkIndexError()
    
    print("=== Testing chunk calculation scenarios ===\n")
    
    print("1. Testing exact divisible file:")
    test_instance.test_chunk_calculation_exact_divisible_file()
    print("✓ Passed\n")
    
    print("2. Testing file with remainder:")
    test_instance.test_chunk_calculation_with_remainder()
    print("✓ Passed\n")
    
    print("3. Reproducing error scenario:")
    test_instance.test_reproduce_error_scenario()
    print("✓ Passed\n")
    
    print("4. Testing optimize_40gb_transfer:")
    test_instance.test_optimize_40gb_transfer_chunk_calculation()
    print("✓ Passed\n")
    
    print("5. Testing single chunk edge case:")
    test_instance.test_edge_case_single_chunk_file()
    print("✓ Passed\n")
    
    print("=== All tests passed! ===")
