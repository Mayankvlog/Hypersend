#!/usr/bin/env python3
"""
More accurate test to reproduce the exact stream processing logic from the frontend.
"""

def simulate_frontend_stream_processing(file_size, chunk_size):
    """Simulate the exact frontend stream processing logic."""
    chunk_index = 0
    sent_bytes = 0
    chunks_uploaded = []
    
    # Simulate stream data (in chunks smaller than chunk_size to simulate real stream)
    stream_parts = []
    remaining = file_size
    part_size = 1024 * 1024  # 1MB parts to simulate stream
    
    while remaining > 0:
        current_part = min(part_size, remaining)
        stream_parts.append(current_part)
        remaining -= current_part
    
    # Simulate the exact frontend logic
    buffer = []
    
    for part in stream_parts:
        # Add part to buffer (simulate buffer.add(part))
        buffer.extend([0] * part)  # Add dummy data
        
        # Process chunks while buffer has enough data
        while len(buffer) >= chunk_size:
            # Take chunk_size bytes from buffer
            chunk = buffer[:chunk_size]
            remaining_in_buffer = buffer[chunk_size:]
            
            # Upload chunk
            chunks_uploaded.append({
                'index': chunk_index,
                'size': len(chunk)
            })
            
            chunk_index += 1
            sent_bytes += len(chunk)
            
            # Update buffer with remaining
            buffer = remaining_in_buffer
    
    # Process remaining tail (after stream is done)
    if buffer:
        chunks_uploaded.append({
            'index': chunk_index,
            'size': len(buffer)
        })
        sent_bytes += len(buffer)
        chunk_index += 1
    
    return {
        'chunks_uploaded': chunks_uploaded,
        'total_chunks': len(chunks_uploaded),
        'final_chunk_index': chunk_index,
        'sent_bytes': sent_bytes
    }


def test_stream_processing_scenarios():
    """Test various scenarios with the stream processing logic."""
    
    test_cases = [
        (50 * 1024 * 1024, 50 * 1024 * 1024, "50MB file, 50MB chunks (exact division)"),
        (51 * 1024 * 1024, 50 * 1024 * 1024, "51MB file, 50MB chunks (with remainder)"),
        (100 * 1024 * 1024, 50 * 1024 * 1024, "100MB file, 50MB chunks (exact division)"),
        (1850 * 1024 * 1024, 50 * 1024 * 1024, "1850MB file, 50MB chunks (37 chunks - error case)"),
    ]
    
    for file_size, chunk_size, description in test_cases:
        print(f"\n=== {description} ===")
        
        # Backend calculation
        backend_total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        # Frontend simulation
        frontend_result = simulate_frontend_stream_processing(file_size, chunk_size)
        
        print(f"File size: {file_size // (1024*1024)}MB")
        print(f"Chunk size: {chunk_size // (1024*1024)}MB")
        print(f"Backend expects: {backend_total_chunks} chunks (0-{backend_total_chunks-1})")
        print(f"Frontend uploaded: {frontend_result['total_chunks']} chunks")
        print(f"Frontend chunk indices: {[c['index'] for c in frontend_result['chunks_uploaded']]}")
        print(f"Final chunk_index: {frontend_result['final_chunk_index']}")
        
        # Check for mismatch
        if frontend_result['total_chunks'] != backend_total_chunks:
            print(f"❌ MISMATCH: Frontend uploaded {frontend_result['total_chunks']}, backend expected {backend_total_chunks}")
            
            # Check if any chunk exceeds backend limit
            for chunk in frontend_result['chunks_uploaded']:
                if chunk['index'] >= backend_total_chunks:
                    print(f"❌ ERROR: Chunk {chunk['index']} exceeds backend limit {backend_total_chunks-1}")
                    print(f"   This would cause: 'Chunk index {chunk['index']} out of range. Expected: 0-{backend_total_chunks-1}'")
        else:
            print(f"✓ Match: Both expect {backend_total_chunks} chunks")
        
        # Verify total bytes
        if frontend_result['sent_bytes'] != file_size:
            print(f"❌ Byte count mismatch: sent {frontend_result['sent_bytes']}, expected {file_size}")
        else:
            print(f"✓ Byte count matches: {frontend_result['sent_bytes']}")


if __name__ == "__main__":
    test_stream_processing_scenarios()
