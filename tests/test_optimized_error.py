#!/usr/bin/env python3
"""
Test the exact scenario: frontend receives optimized chunk_size from backend
but still calculates chunks incorrectly.
"""

def simulate_optimized_scenario(file_size_bytes):
    """Simulate the exact scenario with backend optimization."""
    
    # Simulate backend optimization
    file_size_gb = file_size_bytes / (1024 ** 3)
    base_chunk_size_mb = 8
    
    # Apply same logic as backend
    if file_size_gb <= 2:
        chunk_size_mb = min(base_chunk_size_mb * 4, 32)
    elif file_size_gb <= 5:
        chunk_size_mb = min(base_chunk_size_mb * 3, 24)
    elif file_size_gb <= 15:
        chunk_size_mb = base_chunk_size_mb * 2
    elif file_size_gb <= 30:
        chunk_size_mb = base_chunk_size_mb * 2.5
    else:
        chunk_size_mb = min(base_chunk_size_mb * 3, 32)
    
    chunk_size_bytes = chunk_size_mb * 1024 * 1024
    
    # Backend calculates total_chunks
    file_size_mb = file_size_gb * 1024
    backend_total_chunks = max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb)
    
    # Frontend receives chunk_size from backend and processes stream
    frontend_chunks = []
    chunk_index = 0
    
    # Simulate stream processing with the received chunk_size
    remaining_size = file_size_bytes
    buffer_size = 0
    
    # Process in small parts to simulate real stream
    part_size = 1024 * 1024  # 1MB parts
    
    while remaining_size > 0:
        current_part = min(part_size, remaining_size)
        buffer_size += current_part
        remaining_size -= current_part
        
        # Process chunks when buffer is full
        while buffer_size >= chunk_size_bytes:
            frontend_chunks.append(chunk_index)
            chunk_index += 1
            buffer_size -= chunk_size_bytes
    
    # Process remaining tail
    if buffer_size > 0:
        frontend_chunks.append(chunk_index)
        chunk_index += 1
    
    return {
        'file_size_mb': file_size_mb,
        'chunk_size_mb': chunk_size_mb,
        'chunk_size_bytes': chunk_size_bytes,
        'backend_total_chunks': backend_total_chunks,
        'frontend_chunks': frontend_chunks,
        'frontend_total_chunks': len(frontend_chunks),
        'frontend_chunk_indices': frontend_chunks,
        'final_chunk_index': chunk_index
    }


def test_optimized_chunk_scenarios():
    """Test various file sizes with optimized chunks."""
    
    # Test file sizes that might cause the issue
    test_cases = [
        1850 * 1024 * 1024,  # 1850MB - close to error case
        1900 * 1024 * 1024,  # 1900MB
        2000 * 1024 * 1024,  # 2000MB
        2048 * 1024 * 1024,  # 2GB
    ]
    
    for file_size in test_cases:
        result = simulate_optimized_scenario(file_size)
        
        print(f"\n=== File: {result['file_size_mb']:.0f}MB ===")
        print(f"Backend chunk size: {result['chunk_size_mb']}MB")
        print(f"Backend expects: {result['backend_total_chunks']} chunks (0-{result['backend_total_chunks']-1})")
        print(f"Frontend uploaded: {result['frontend_total_chunks']} chunks")
        print(f"Frontend indices: {result['frontend_chunk_indices']}")
        
        # Check for the specific error
        if result['frontend_total_chunks'] > result['backend_total_chunks']:
            print(f"❌ ERROR: Frontend uploaded more chunks than backend expects!")
            
            # Find the problematic chunk
            for i, chunk_idx in enumerate(result['frontend_chunk_indices']):
                if chunk_idx >= result['backend_total_chunks']:
                    print(f"   Problematic chunk: {chunk_idx} (backend max: {result['backend_total_chunks']-1})")
                    print(f"   This would cause: 'Chunk index {chunk_idx} out of range. Expected: 0-{result['backend_total_chunks']-1}'")
                    break
        elif result['frontend_total_chunks'] < result['backend_total_chunks']:
            print(f"⚠️  WARNING: Frontend uploaded fewer chunks than backend expects")
        else:
            print(f"✓ Match: Both expect {result['backend_total_chunks']} chunks")


def test_exact_error_reproduction():
    """Try to reproduce the exact error: 'Chunk index 37 out of range. Expected: 0-36'"""
    print("\n=== EXACT ERROR REPRODUCTION ATTEMPT ===")
    print("Target: 'Chunk index 37 out of range. Expected: 0-36'")
    print("This means backend expects 37 chunks, frontend tries to upload chunk 37")
    
    # Search for file size that causes this exact error
    for file_size_mb in range(1800, 2100):  # Search range
        file_size = file_size_mb * 1024 * 1024
        result = simulate_optimized_scenario(file_size)
        
        # Check if backend expects exactly 37 chunks
        if result['backend_total_chunks'] == 37:
            # Check if frontend tries to upload chunk 37
            if 37 in result['frontend_chunk_indices']:
                print(f"\n🎯 FOUND IT!")
                print(f"File size: {file_size_mb}MB")
                print(f"Backend chunk size: {result['chunk_size_mb']}MB")
                print(f"Backend expects: 37 chunks (0-36)")
                print(f"Frontend tries to upload: {result['frontend_total_chunks']} chunks")
                print(f"Frontend chunk indices: {result['frontend_chunk_indices']}")
                print(f"❌ This would cause: 'Chunk index 37 out of range. Expected: 0-36'")
                return file_size_mb
            else:
                print(f"File {file_size_mb}MB: Backend expects 37 chunks, but frontend upload is OK")
    
    print("Could not reproduce exact error in search range")


if __name__ == "__main__":
    test_optimized_chunk_scenarios()
    test_exact_error_reproduction()
