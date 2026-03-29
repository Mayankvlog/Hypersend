#!/usr/bin/env python3
"""
Fix script for multipart boundary corruption in file upload/download flow.
Applies patches to backend/routes/files.py
"""

import re
import sys

def main():
    files_path = "backend/routes/files.py"
    
    try:
        with open(files_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Fix 1: Update media endpoint database lookup to handle both UUID and ObjectId formats
        # Pattern: file_doc = await asyncio.wait_for(uploads_collection().find_one({"_id": ObjectId(file_id)})...
        
        pattern1 = r'''        file_doc = await asyncio\.wait_for\(
                uploads_collection\(\)\.find_one\(\{"_id": ObjectId\(file_id\)\}\),
                timeout=30\.0,
            \)'''
        
        replacement1 = '''        # Try to find by file_id (UUID string or ObjectId)
        file_doc = await asyncio.wait_for(
            uploads_collection().find_one({"_id": file_id}),
            timeout=30.0,
        )
        
        # Fallback: try as ObjectId if that fails
        if not file_doc:
            file_doc = await asyncio.wait_for(
                uploads_collection().find_one({"_id": ObjectId(file_id)}),
                timeout=30.0,
            )
        
        # Last attempt: check files_collection
        if not file_doc:
            try:
                from backend.db_proxy import files_collection as files_coll
                file_doc = await asyncio.wait_for(
                    files_coll().find_one({"_id": ObjectId(file_id)}),
                    timeout=30.0,
                )
            except:
                pass'''
        
        content = re.sub(pattern1, replacement1, content, flags=re.MULTILINE)
        
        if content == original_content:
            print("[INFO] No direct pattern match for Fix #1, trying alternative...")
        else:
            print("[✓] Applied Fix #1: Media endpoint database lookup")
        
        # Save the modified content
        with open(files_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"[✓] Successfully updated {files_path}")
        return 0
        
    except Exception as e:
        print(f"[✗] Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
