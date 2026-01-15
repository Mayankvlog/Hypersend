#!/usr/bin/env python3
"""
Quick test to verify file download fix
"""

import sys
import os

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

def test_file_download_fix():
    """Test that file download code uses mime_type field"""
    print("🧪 Testing File Download Fix")
    
    # Read the files.py to check if fix is applied
    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'backend', 'routes', 'files.py'), 'r') as f:
            content = f.read()
        
        # Check for the old problematic pattern
        old_pattern_count = content.count('file_doc["mime"]')
        new_pattern_count = content.count('file_doc.get("mime_type"')
        
        print(f"📥 Old pattern (file_doc[\"mime\"]): {old_pattern_count} instances")
        print(f"📥 New pattern (file_doc.get(\"mime_type\")): {new_pattern_count} instances")
        
        if old_pattern_count == 0 and new_pattern_count >= 4:
            print("✅ File download fix applied successfully!")
            print("✅ All instances now use mime_type field with .get() method")
            return True
        else:
            print("❌ Fix not properly applied")
            return False
            
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return False

if __name__ == "__main__":
    success = test_file_download_fix()
    if success:
        print("\n🎉 File download fix verification PASSED")
        print("🔄 Restart Docker container to apply changes")
    else:
        print("\n❌ File download fix verification FAILED")
        sys.exit(1)
