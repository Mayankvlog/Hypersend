#!/usr/bin/env python3
"""
Simulate the exact frontend stream processing to find the bug.
"""

def simulate_frontend_stream_bug(file_size_bytes, chunk_size_bytes):
    """Simulate frontend stream processing to find the off-by-one bug."""
    
    print(f"=== SIMULATING FRONTEND STREAM PROCESSING ===")
    print(f"File size: {file_size_bytes // (1024*1024)}MB")
    print(f"Chunk size: {chunk_size_bytes // (1024*1024)}MB")
    
    # Backend calculation
    backend_total_chunks = (file_size_bytes + chunk_size_bytes - 1) // chunk_size_bytes
    
    # Frontend simulation - exact logic from file_transfer_service.dart
    chunk_index = 0
    sent_bytes = 0
    buffer = []
    chunks_uploaded = []
    
    # Simulate stream in small parts (like real file reading)
    part_size = 1024 * 1024  # 1MB parts
    remaining_file = file_size_bytes
    
    print(f"\nStream processing:")
    
    while remaining_file > 0:
        # Read part from stream
        part_bytes = min(part_size, remaining_file)
        buffer.extend([0] * part_bytes)  # Add to buffer
        remaining_file -= part_bytes
        
        print(f"  Read {part_bytes // (1024*1024)}MB, buffer: {len(buffer) // (1024*1024)}MB")
        
        # Process chunks while buffer has enough
        while len(buffer) >= chunk_size_bytes:
            # Extract chunk
            chunk = buffer[:chunk_size_bytes]
            buffer = buffer[chunk_size_bytes:]
            
            # Upload chunk
            chunks_uploaded.append({
                'index': chunk_index,
                'size': len(chunk)
            })
            
            print(f"    Upload chunk {chunk_index} ({len(chunk) // (1024*1024)}MB)")
            
            chunk_index += 1
            sent_bytes += len(chunk)
    
    # Process remaining tail after stream ends
    if buffer:
        chunks_uploaded.append({
            'index': chunk_index,
            'size': len(buffer)
        })
        
        print(f"  Upload tail chunk {chunk_index} ({len(buffer) // (1024*1024)}MB)")
        
        chunk_index += 1
        sent_bytes += len(buffer)
    
    frontend_total_chunks = len(chunks_uploaded)
    
    print(f"\nResults:")
    print(f"Backend expects: {backend_total_chunks} chunks (0-{backend_total_chunks-1})")
    print(f"Frontend uploaded: {frontend_total_chunks} chunks")
    print(f"Frontend indices: {[c['index'] for c in chunks_uploaded]}")
    print(f"Final chunk_index: {chunk_index}")
    
    # Check for the bug
    if frontend_total_chunks > backend_total_chunks:
        print(f"❌ BUG FOUND: Frontend uploaded {frontend_total_chunks}, backend expected {backend_total_chunks}")
        
        # Find problematic chunk
        for chunk in chunks_uploaded:
            if chunk['index'] >= backend_total_chunks:
                print(f"   Problematic chunk: {chunk['index']} (backend max: {backend_total_chunks-1})")
                print(f"   Error: 'Chunk index {chunk['index']} out of range. Expected: 0-{backend_total_chunks-1}'")
                return True
    elif frontend_total_chunks < backend_total_chunks:
        print(f"⚠️  Frontend uploaded fewer chunks: {frontend_total_chunks} vs {backend_total_chunks}")
    else:
        print(f"✓ Match: Both {backend_total_chunks} chunks")
    
    return False


def test_exact_error_scenario():
    """Test the exact scenario that causes the error."""
    
    print(f"=== EXACT ERROR SCENARIO TEST ===")
    
    # From error: "Chunk index 37 out of range. Expected: 0-36"
    # This means backend expects 37 chunks, frontend tries to upload chunk 37
    
    # Let's try file sizes that would result in 37 backend chunks
    # with various chunk sizes
    
    test_cases = [
        (721 * 1024 * 1024, 20 * 1024 * 1024, "721MB file, 20MB chunks"),
        (740 * 1024 * 1024, 20 * 1024 * 1024, "740MB file, 20MB chunks"),
        (1801 * 1024 * 1024, 50 * 1024 * 1024, "1801MB file, 50MB chunks"),
        (1850 * 1024 * 1024, 50 * 1024 * 1024, "1850MB file, 50MB chunks"),
    ]
    
    for file_size, chunk_size, desc in test_cases:
        print(f"\n--- {desc} ---")
        
        backend_chunks = (file_size + chunk_size - 1) // chunk_size
        print(f"Backend calculation: {backend_chunks} chunks")
        
        if backend_chunks == 37:
            bug_found = simulate_frontend_stream_bug(file_size, chunk_size)
            if bug_found:
                print(f"🎯 FOUND THE EXACT ERROR SCENARIO!")
                return file_size, chunk_size
    
    print("Could not reproduce exact error")


def test_boundary_case():
    """Test a specific boundary case that might cause the issue."""
    
    print(f"\n=== BOUNDARY CASE TEST ===")
    
    # What if there's a bug in the frontend logic where it processes
    # one extra chunk due to a race condition or buffer issue?
    
    file_size = 1850 * 1024 * 1024  # 1850MB
    chunk_size = 50 * 1024 * 1024  # 50MB
    
    backend_chunks = (file_size + chunk_size - 1) // chunk_size
    print(f"Backend: {backend_chunks} chunks")
    
    # What if frontend has a bug and processes one extra chunk?
    # This could happen if there's a timing issue or if the stream
    # reporting is incorrect
    
    print(f"If frontend has off-by-one bug:")
    print(f"  Frontend would try to upload chunk {backend_chunks}")
    print(f"  Backend would reject: 'Chunk index {backend_chunks} out of range. Expected: 0-{backend_chunks-1}'")


if __name__ == "__main__":
    test_exact_error_scenario()
    test_boundary_case()
