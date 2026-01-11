#!/usr/bin/env python3
"""
Test the float chunk size issue in optimize_40gb_transfer.
"""

def test_float_chunk_size_issue():
    """Test the specific issue with float chunk sizes."""
    
    print("=== FLOAT CHUNK SIZE ISSUE ===")
    
    # Simulate the problematic case
    file_size_gb = 20.0  # 20GB file (between 15GB and 30GB)
    base_chunk_size_mb = 8
    
    # This creates a float
    chunk_size_mb = base_chunk_size_mb * 2.5  # 20.0 (float!)
    
    print(f"File size: {file_size_gb}GB")
    print(f"Chunk size: {chunk_size_mb}MB (type: {type(chunk_size_mb)})")
    
    # Calculate chunks using the problematic formula
    file_size_mb = file_size_gb * 1024
    target_chunks = max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb)
    
    print(f"File size in MB: {file_size_mb}")
    print(f"Target chunks (with float): {target_chunks} (type: {type(target_chunks)})")
    
    # What should happen with proper integer chunk size
    chunk_size_mb_int = int(chunk_size_mb)  # Convert to int
    target_chunks_int = max(1, (file_size_mb + chunk_size_mb_int - 1) // chunk_size_mb_int)
    
    print(f"Target chunks (with int): {target_chunks_int}")
    
    # Test the difference
    if target_chunks != target_chunks_int:
        print(f"❌ MISMATCH: float={target_chunks}, int={target_chunks_int}")
    else:
        print(f"✓ Match: both calculate {target_chunks}")
    
    # Test specific values that might cause the error
    print(f"\n=== TESTING SPECIFIC VALUES ===")
    
    test_cases = [
        (1850, "1850MB"),
        (1900, "1900MB"), 
        (2000, "2000MB"),
        (2048, "2048MB"),
        (2560, "2560MB"),
    ]
    
    for size_mb, desc in test_cases:
        file_size_gb = size_mb / 1024
        chunk_size_mb = 20.0  # From the 2.5x multiplier
        
        # Backend calculation (with float issue)
        file_size_mb_calc = file_size_gb * 1024
        backend_chunks = max(1, (file_size_mb_calc + chunk_size_mb - 1) // chunk_size_mb)
        
        # Frontend calculation (receives chunk_size in bytes, so no float issue)
        chunk_size_bytes = int(chunk_size_mb * 1024 * 1024)
        file_size_bytes = size_mb * 1024 * 1024
        frontend_chunks = (file_size_bytes + chunk_size_bytes - 1) // chunk_size_bytes
        
        print(f"{desc}: backend={backend_chunks}, frontend={frontend_chunks}")
        
        if backend_chunks != frontend_chunks:
            print(f"  ❌ MISMATCH could cause error!")
            if frontend_chunks > backend_chunks:
                problematic_chunk = backend_chunks
                print(f"  ❌ Frontend would try to upload chunk {problematic_chunk} but backend expects max {backend_chunks-1}")
                print(f"  Error: 'Chunk index {problematic_chunk} out of range. Expected: 0-{backend_chunks-1}'")


def test_exact_37_chunk_scenario():
    """Try to find exact scenario that causes 37 chunks error."""
    print(f"\n=== SEARCHING FOR 37 CHUNK SCENARIO ===")
    
    # Search for file sizes that result in exactly 37 backend chunks
    for size_mb in range(1000, 3000):  # Search 1GB to 3GB
        file_size_gb = size_mb / 1024
        
        # Determine chunk size based on file size
        base_chunk_size_mb = 8
        if file_size_gb <= 2:
            chunk_size_mb = min(base_chunk_size_mb * 4, 32)
        elif file_size_gb <= 5:
            chunk_size_mb = min(base_chunk_size_mb * 3, 24)
        elif file_size_gb <= 15:
            chunk_size_mb = base_chunk_size_mb * 2
        elif file_size_gb <= 30:
            chunk_size_mb = base_chunk_size_mb * 2.5  # This creates float!
        else:
            chunk_size_mb = min(base_chunk_size_mb * 3, 32)
        
        # Backend calculation (with potential float)
        file_size_mb_calc = file_size_gb * 1024
        backend_chunks = max(1, (file_size_mb_calc + chunk_size_mb - 1) // chunk_size_mb)
        
        # Frontend calculation
        chunk_size_bytes = int(chunk_size_mb * 1024 * 1024)
        file_size_bytes = size_mb * 1024 * 1024
        frontend_chunks = (file_size_bytes + chunk_size_bytes - 1) // chunk_size_bytes
        
        # Check if this matches the error
        if backend_chunks == 37 and frontend_chunks > backend_chunks:
            print(f"🎯 FOUND IT!")
            print(f"File size: {size_mb}MB ({file_size_gb:.2f}GB)")
            print(f"Chunk size: {chunk_size_mb}MB")
            print(f"Backend expects: {backend_chunks} chunks (0-36)")
            print(f"Frontend uploads: {frontend_chunks} chunks")
            print(f"❌ This causes: 'Chunk index 37 out of range. Expected: 0-36'")
            return size_mb
    
    print("No 37-chunk scenario found in range")


if __name__ == "__main__":
    test_float_chunk_size_issue()
    test_exact_37_chunk_scenario()
