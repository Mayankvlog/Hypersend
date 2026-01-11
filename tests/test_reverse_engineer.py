#!/usr/bin/env python3
"""
Reverse engineer the exact file size from the error.
Error: "Chunk index 37 out of range. Expected: 0-36"
This means backend calculated 37 chunks total.
"""

def reverse_engineer_file_size():
    """Work backwards from the error to find the file size."""
    
    print("=== REVERSE ENGINEERING FILE SIZE ===")
    print("Error: 'Chunk index 37 out of range. Expected: 0-36'")
    print("Backend expects 37 chunks total")
    
    # Backend expects 37 chunks, so we need to find file size
    # that results in exactly 37 chunks with some chunk size
    
    # Try different chunk sizes that might be used
    possible_chunk_sizes_mb = [8, 16, 20, 24, 32, 50]  # Common chunk sizes
    
    for chunk_mb in possible_chunk_sizes_mb:
        # If backend expects 37 chunks, what file size would cause this?
        # Using ceiling division: chunks = ceil(file_size_mb / chunk_mb)
        # So: file_size_mb = (chunks - 1) * chunk_mb + 1 to chunks * chunk_mb
        
        min_file_size_mb = (37 - 1) * chunk_mb + 1  # Minimum size for 37 chunks
        max_file_size_mb = 37 * chunk_mb  # Maximum size for 37 chunks
        
        print(f"\nChunk size: {chunk_mb}MB")
        print(f"File size range for 37 chunks: {min_file_size_mb}MB - {max_file_size_mb}MB")
        
        # Check if any of these file sizes would cause frontend to upload 38 chunks
        # Frontend uses the same chunk size from backend, so should match...
        
        # But maybe there's an edge case with exact division?
        # Let's test the boundaries
        
        for test_size_mb in [min_file_size_mb, max_file_size_mb]:
            # Backend calculation
            backend_chunks = (test_size_mb + chunk_mb - 1) // chunk_mb
            
            # Frontend calculation (same logic)
            frontend_chunks = (test_size_mb + chunk_mb - 1) // chunk_mb
            
            print(f"  {test_size_mb}MB: backend={backend_chunks}, frontend={frontend_chunks}")
    
    # Let's also try the optimization logic
    print(f"\n=== TESTING WITH OPTIMIZATION LOGIC ===")
    
    # The file might be large enough to trigger optimization
    # Let's find file sizes that would result in 37 optimized chunks
    
    def get_optimized_chunk_size(file_size_gb):
        base_chunk_size_mb = 8
        if file_size_gb <= 2:
            return min(base_chunk_size_mb * 4, 32)
        elif file_size_gb <= 5:
            return min(base_chunk_size_mb * 3, 24)
        elif file_size_gb <= 15:
            return base_chunk_size_mb * 2
        elif file_size_gb <= 30:
            return base_chunk_size_mb * 2.5  # 20MB
        else:
            return min(base_chunk_size_mb * 3, 32)
    
    # Search for file size that gives exactly 37 optimized chunks
    for size_gb in [1.0, 1.5, 1.8, 1.9, 2.0, 2.1, 2.5, 3.0]:
        chunk_mb = get_optimized_chunk_size(size_gb)
        size_mb = size_gb * 1024
        chunks = max(1, (size_mb + chunk_mb - 1) // chunk_mb)
        
        print(f"{size_gb}GB with {chunk_mb}MB chunks: {chunks} chunks")
        
        if chunks == 37:
            print(f"  🎯 Found potential match!")
            
            # Now test if frontend would upload more
            frontend_chunks = (size_mb + chunk_mb - 1) // chunk_mb
            if frontend_chunks > chunks:
                print(f"  ❌ Frontend would upload {frontend_chunks}, backend expects {chunks}")


def test_boundary_conditions():
    """Test boundary conditions that might cause off-by-one errors."""
    
    print(f"\n=== TESTING BOUNDARY CONDITIONS ===")
    
    # Test exact division scenarios
    chunk_mb = 50  # 50MB chunks
    
    # File sizes that are exact multiples of chunk size
    exact_multiples = [50, 100, 150, 1850]  # MB
    
    for size_mb in exact_multiples:
        backend_chunks = (size_mb + chunk_mb - 1) // chunk_mb
        
        # Simulate frontend stream processing
        frontend_chunks = 0
        remaining = size_mb
        
        while remaining >= chunk_mb:
            frontend_chunks += 1
            remaining -= chunk_mb
        
        if remaining > 0:
            frontend_chunks += 1
        
        print(f"{size_mb}MB: backend={backend_chunks}, frontend={frontend_chunks}")
        
        if frontend_chunks != backend_chunks:
            print(f"  ❌ MISMATCH!")


if __name__ == "__main__":
    reverse_engineer_file_size()
    test_boundary_conditions()
