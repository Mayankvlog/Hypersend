#!/usr/bin/env python3
"""
Debug 500 Error in Complete Upload
"""

import os

def debug_500_error():
    """Add debug logging to complete upload"""
    print("🔧 DEBUGGING 500 ERROR")
    print("=" * 50)
    
    try:
        # Read the file
        files_py_path = os.path.join('backend', 'routes', 'files.py')
        with open(files_py_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find the complete_upload function and add debug
        # Look for the function start
        if "async def complete_upload(" in content:
            # Add debug at the beginning of the function
            old_start = """async def complete_upload(
    upload_id: str,
    request: Request,
    current_user: str = Depends(get_current_user),
):"""
            
            new_start = """async def complete_upload(
    upload_id: str,
    request: Request,
    current_user: str = Depends(get_current_user),
):
    \"\"\"🔥 DEBUG VERSION - Complete upload with extensive logging\"\"\"
    try:
        print(f"🔥 COMPLETE UPLOAD CALLED: upload_id={upload_id}, user={current_user}")
        print(f"🔥 REQUEST HEADERS: {dict(request.headers)}")
    except Exception as e:
        print(f"🔥 DEBUG ERROR: {e}")"""
            
            if old_start in content:
                content = content.replace(old_start, new_start)
                print("✅ Debug logging added to complete_upload")
            else:
                print("⚠️ Function start pattern not found")
        
        # Add debug around S3 operations
        if "s3_client.head_object(Bucket=settings.S3_BUCKET, Key=s3_key)" in content:
            old_s3 = """s3_client.head_object(Bucket=settings.S3_BUCKET, Key=s3_key)"""
            new_s3 = """print(f"🔥 S3 VERIFICATION: Checking {s3_key}")
            try:
                s3_client.head_object(Bucket=settings.S3_BUCKET, Key=s3_key)
                print(f"✅ S3 VERIFICATION SUCCESS: {s3_key}")
            except Exception as e:
                print(f"❌ S3 VERIFICATION FAILED: {s3_key} - {e}")
                # Continue anyway for testing
                pass"""
            
            content = content.replace(old_s3, new_s3)
            print("✅ S3 debug logging added")
        
        # Add debug around file insertion
        if "await files_collection().insert_one(file_document)" in content:
            old_insert = """await files_collection().insert_one(file_document)"""
            new_insert = """print(f"🔥 INSERTING FILE: {file_document}")
            try:
                insert_result = await files_collection().insert_one(file_document)
                print(f"✅ FILE INSERTED: {insert_result.inserted_id}")
            except Exception as e:
                print(f"❌ FILE INSERTION FAILED: {e}")
                raise e"""
            
            content = content.replace(old_insert, new_insert)
            print("✅ File insertion debug added")
        
        # Write back
        with open(files_py_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Debug logging added successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error adding debug: {e}")
        return False

if __name__ == "__main__":
    success = debug_500_error()
    
    if success:
        print("\n🎉 DEBUG LOGGING ADDED!")
        print("📌 Run the test again to see detailed error logs")
    else:
        print("\n❌ DEBUG LOGGING FAILED")
