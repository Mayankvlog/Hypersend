#!/usr/bin/env python3
"""
Test the float total_chunks issue in the optimization function.
"""

def test_float_division_issue():
    """Test if float division causes float total_chunks."""
    
    print("=== FLOAT DIVISION ISSUE ===")
    
    # Simulate the exact problematic calculation
    file_size_mb = 740.0  # Example file size
    chunk_size_mb = 20.0  # Float chunk size from optimization
    
    # This is the problematic line from the code
    target_chunks = max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb)
    
    print(f"file_size_mb: {file_size_mb} (type: {type(file_size_mb)})")
    print(f"chunk_size_mb: {chunk_size_mb} (type: {type(chunk_size_mb)})")
    print(f"target_chunks: {target_chunks} (type: {type(target_chunks)})")
    
    # Test various scenarios
    print(f"\n=== TESTING VARIOUS FILE SIZES ===")
    
    test_cases = [
        (721, "721MB"),  # Min for 37 chunks with 20MB
        (740, "740MB"),  # Max for 37 chunks with 20MB
        (1850, "1850MB"), # From error logs
    ]
    
    for size_mb, desc in test_cases:
        file_size_mb = float(size_mb)
        chunk_size_mb = 20.0  # From optimization (2.5 * 8MB)
        
        # Problematic calculation
        target_chunks = max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb)
        
        print(f"{desc}: {target_chunks} (type: {type(target_chunks)})")
        
        # Check if this causes issues in comparisons
        chunk_index = int(target_chunks)  # What frontend might use
        
        print(f"  chunk_index {chunk_index} >= target_chunks {target_chunks}? {chunk_index >= target_chunks}")
        
        if chunk_index >= target_chunks and type(target_chunks) == float:
            print(f"  ❌ This could cause the error!")
            print(f"  Error: 'Chunk index {chunk_index} out of range. Expected: 0-{int(target_chunks)-1}'")


def test_fix_with_int_conversion():
    """Test the fix with proper integer conversion."""
    
    print(f"\n=== TESTING FIX ===")
    
    file_size_mb = 740.0
    chunk_size_mb = 20.0
    
    # Fixed calculation - convert to int
    target_chunks_fixed = int(max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb))
    
    print(f"Original: {max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb)} (type: {type(max(1, (file_size_mb + chunk_size_mb - 1) // chunk_size_mb))})")
    print(f"Fixed: {target_chunks_fixed} (type: {type(target_chunks_fixed)})")
    
    # Test the fix
    chunk_index = target_chunks_fixed  # Frontend would use this
    
    print(f"chunk_index {chunk_index} >= target_chunks_fixed {target_chunks_fixed}? {chunk_index >= target_chunks_fixed}")
    
    if chunk_index >= target_chunks_fixed:
        print(f"❌ Still causes issue")
    else:
        print(f"✓ Fix works!")


if __name__ == "__main__":
    test_float_division_issue()
    test_fix_with_int_conversion()
