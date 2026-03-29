#!/usr/bin/env python3
"""
Enhanced fix script for multipart/ID type issues in files.py
"""

import sys

def fix_file_lookups():
    filepath = "backend/routes/files.py"
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    
    # Fix: Update media endpoint to handle UUID strings properly
    # Look for the pattern with exact spacing
    old_code = '''        if not file_id or not ObjectId.is_valid(file_id):

            raise HTTPException(

                status_code=status.HTTP_400_BAD_REQUEST,

                detail="Invalid file ID format",

            )



        file_doc = None



        try:

            import asyncio



            file_doc = await asyncio.wait_for(

                uploads_collection().find_one({"_id": ObjectId(file_id)}),

                timeout=30.0,

            )'''
    
    new_code = '''        if not file_id:

            raise HTTPException(

                status_code=status.HTTP_400_BAD_REQUEST,

                detail="Invalid file ID format",

            )



        file_doc = None



        try:

            import asyncio

            # Try to find by file_id string first (modern UUID format)
            file_doc = await asyncio.wait_for(
                uploads_collection().find_one({"_id": file_id}),
                timeout=30.0,
            )
            
            # Fallback: try as ObjectId if that fails  
            if not file_doc and ObjectId.is_valid(file_id):
                file_doc = await asyncio.wait_for(
                    uploads_collection().find_one({"_id": ObjectId(file_id)}),
                    timeout=30.0,
                )
            
            # Last attempt: try files_collection
            if not file_doc:
                try:
                    from backend.db_proxy import files_collection as fc
                    file_doc = await asyncio.wait_for(
                        fc().find_one({"_id": ObjectId(file_id) if ObjectId.is_valid(file_id) else file_id}),
                        timeout=30.0,
                    )
                except:
                    pass'''
    
    if old_code in content:
        content = content.replace(old_code, new_code)
        print("✓ Applied Fix #1: Media endpoint database lookup")
    else:
        print("⚠ Fix #1 pattern not found (may have already been applied)")
    
    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✓ Successfully saved {filepath}")
        return 0
    else:
        print("ℹ No changes made")
        return 0

if __name__ == "__main__":
    sys.exit(fix_file_lookups())
