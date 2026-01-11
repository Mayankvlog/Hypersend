#!/usr/bin/env python3
"""
Test to identify the exact cause of the chunk index mismatch.
The issue might be in the optimize_40gb_transfer function.
"""

def simulate_optimize_40gb_transfer(file_size_bytes):
    """Simulate the optimize_40gb_transfer function logic."""
    # Convert to GB for calculations
    file_size_gb = file_size_bytes / (1024 ** 3)
    
    # Base chunk size (assuming 8MB from config)
    base_chunk_size_mb = 8
    
    # Adaptive chunk sizing based on file size
    if file_size_gb <= 2:
        chunk_size_mb = min(base_chunk_size_mb * 4, 32)  # Max 32MB
    elif file_size_gb <= 5:
        chunk_size_mb = min(base_chunk_size_mb * 3, 24)  # Max 24MB
    elif file_size_gb <= 15:
        chunk_size_mb = base_chunk_size_mb * 2  # 16MB
    elif file_size_gb <= 30:
        chunk_size_mb = base_chunk_size_mb * 2.5  # 20MB
    else:
        chunk_size_mb = min(base_chunk_size_mb * 3, 32)  # Max 32MB
    
    # Calculate target chunks
    file_size_mb = file_size_gb * 1024
    target_chunks = max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb)
    
    return {
        "file_size_bytes": file_size_bytes,
        "file_size_gb": file_size_gb,
        "chunk_size_mb": chunk_size_mb,
        "chunk_size_bytes": chunk_size_mb * 1024 * 1024,
        "target_chunks": target_chunks
    }


def test_optimization_vs_standard_calculation():
    """Test if optimization causes mismatch with standard calculation."""
    
    test_cases = [
        (1850 * 1024 * 1024, "1850MB file (error case)"),
        (2048 * 1024 * 1024, "2GB file"),
        (5120 * 1024 * 1024, "5GB file"),
        (10240 * 1024 * 1024, "10GB file"),
    ]
    
    for file_size, description in test_cases:
        print(f"\n=== {description} ===")
        
        # Standard calculation (what frontend might use)
        standard_chunk_size = 50 * 1024 * 1024  # 50MB
        standard_chunks = (file_size + standard_chunk_size - 1) // standard_chunk_size
        
        # Optimized calculation (what backend uses for large files)
        optimization = simulate_optimize_40gb_transfer(file_size)
        optimized_chunks = optimization["target_chunks"]
        optimized_chunk_size = optimization["chunk_size_bytes"]
        
        print(f"File size: {file_size // (1024*1024)}MB")
        print(f"Standard: {standard_chunks} chunks of {standard_chunk_size // (1024*1024)}MB each")
        print(f"Optimized: {optimized_chunks} chunks of {optimized_chunk_size // (1024*1024)}MB each")
        
        # Check if this could cause the error
        if standard_chunks != optimized_chunks:
            print(f"❌ MISMATCH: Standard={standard_chunks}, Optimized={optimized_chunks}")
            print(f"   If frontend uses standard chunks but backend uses optimized, this could cause the error!")
            
            # Simulate what happens
            print(f"   Frontend would upload chunks 0-{standard_chunks-1}")
            print(f"   Backend would expect chunks 0-{optimized_chunks-1}")
            
            if standard_chunks > optimized_chunks:
                print(f"   ❌ Frontend would try to upload chunk {optimized_chunks} which backend rejects!")
                print(f"   Error: 'Chunk index {optimized_chunks} out of range. Expected: 0-{optimized_chunks-1}'")
        else:
            print(f"✓ Match: Both calculate {standard_chunks} chunks")


def test_actual_error_scenario():
    """Test the exact scenario from the error logs."""
    print("\n=== ACTUAL ERROR SCENARIO ===")
    print("Error: 'Chunk index 37 out of range. Expected: 0-36'")
    print("This means backend expects 37 chunks (0-36), but frontend tried to upload chunk 37")
    
    # What file size would cause backend to expect exactly 37 chunks?
    # Let's work backwards
    
    # If backend uses optimization and expects 37 chunks
    backend_chunks = 37
    
    # Try different file sizes to see which would result in 37 optimized chunks
    test_sizes = [
        1800 * 1024 * 1024,  # 1800MB
        1850 * 1024 * 1024,  # 1850MB  
        1900 * 1024 * 1024,  # 1900MB
        1950 * 1024 * 1024,  # 1950MB
        2000 * 1024 * 1024,  # 2000MB
    ]
    
    for file_size in test_sizes:
        optimization = simulate_optimize_40gb_transfer(file_size)
        if optimization["target_chunks"] == 37:
            print(f"\nFound matching file size: {file_size // (1024*1024)}MB")
            print(f"Optimized chunk size: {optimization['chunk_size_mb']}MB")
            print(f"Backend expects: {optimization['target_chunks']} chunks")
            
            # What would standard calculation give?
            standard_chunk_size = 50 * 1024 * 1024  # 50MB
            standard_chunks = (file_size + standard_chunk_size - 1) // standard_chunk_size
            
            print(f"Standard calculation: {standard_chunks} chunks of 50MB each")
            
            if standard_chunks > backend_chunks:
                print(f"❌ FOUND IT! Frontend would try to upload chunk {backend_chunks} but backend only expects {backend_chunks}")
                print(f"   This matches the error exactly!")
                return file_size
    
    print("No matching file size found in test cases")


if __name__ == "__main__":
    test_optimization_vs_standard_calculation()
    test_actual_error_scenario()
