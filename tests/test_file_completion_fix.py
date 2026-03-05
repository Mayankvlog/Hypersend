#!/usr/bin/env python3
"""
Test for 500 error fix in file completion endpoint
Tests that the _handle_file_error function issue is resolved
"""

import pytest
import sys
import os
from pathlib import Path

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
sys.path.insert(0, backend_path)

def test_file_completion_error_handling():
    """Test that file completion endpoint handles errors properly"""
    
    # Check that the _handle_file_error function call is removed
    files_py_path = Path(__file__).parent.parent / "backend" / "routes" / "files.py"
    if files_py_path.exists():
        try:
            with open(files_py_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            # Fallback to reading with latin-1 encoding if UTF-8 fails
            with open(files_py_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        # Verify the problematic function call is removed
        assert "_handle_file_error(" not in content, "_handle_file_error function call should be removed"
        
        # Verify proper error handling is in place
        assert "if isinstance(e, (OSError, IOError)):" in content, "Should handle OSError/IOError properly"
        assert "if isinstance(e, MemoryError):" in content, "Should handle MemoryError properly"
        assert "HTTP_503_SERVICE_UNAVAILABLE" in content, "Should return 503 for storage errors"
        assert "HTTP_507_INSUFFICIENT_STORAGE" in content, "Should return 507 for memory errors"
        assert "HTTP_500_INTERNAL_SERVER_ERROR" in content, "Should return 500 for unexpected errors"
        
        print("✅ File completion error handling verified")
    else:
        pytest.skip("files.py not found")

def test_file_completion_function_structure():
    """Test that complete_upload function has proper structure"""
    
    files_py_path = Path(__file__).parent.parent / "backend" / "routes" / "files.py"
    if files_py_path.exists():
        with open(files_py_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Verify function exists and has proper structure
        assert "async def complete_upload(" in content, "complete_upload function should exist"
        assert "@router.post(\"/{upload_id}/complete\"" in content, "Should have correct route decorator"
        assert "response_model=dict" in content, "Should have proper response model"
        
        # Verify error handling structure
        assert "except HTTPException:" in content, "Should handle HTTPException"
        assert "except Exception as e:" in content, "Should handle general exceptions"
        
        print("✅ File completion function structure verified")
    else:
        pytest.skip("files.py not found")

def test_error_logging_consistency():
    """Test that error logging is consistent"""
    
    files_py_path = Path(__file__).parent.parent / "backend" / "routes" / "files.py"
    if files_py_path.exists():
        with open(files_py_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Verify consistent error logging pattern
        assert '_log("error"' in content, "Should have error logging"
        assert '"user_id": current_user' in content, "Should log user_id"
        assert '"operation":' in content, "Should log operation"
        assert '"upload_id": upload_id' in content, "Should log upload_id"
        
        print("✅ Error logging consistency verified")
    else:
        pytest.skip("files.py not found")

if __name__ == "__main__":
    print("Testing file completion 500 error fix...")
    test_file_completion_error_handling()
    test_file_completion_function_structure()
    test_error_logging_consistency()
    print("🎉 All file completion error tests passed!")
