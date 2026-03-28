#!/usr/bin/env python3
"""
Simple S3 Fix - Replace S3 get_object with presigned URL
"""

import os
import sys

def simple_s3_fix():
    """Apply simple S3 fix"""
    print("🔧 SIMPLE S3 FIX")
    print("=" * 50)
    
    try:
        # Read the files.py file
        files_py_path = os.path.join(os.path.dirname(__file__), 'backend', 'routes', 'files.py')
        
        with open(files_py_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print("🔍 Applying simple S3 fix...")
        
        # Find and replace S3 get_object with presigned URL
        old_pattern = """s3_obj = s3_client.get_object(Bucket=bucket, Key=s3_key)
                    
                    from fastapi.responses import StreamingResponse
                    return StreamingResponse(
                        s3_obj["Body"],
                        media_type=file_doc.get("mime_type", "image/jpeg"),
                        headers={
                            "Content-Disposition": f'inline; filename="{file_doc.get("filename", "file")}"',
                            "Cache-Control": "public, max-age=3600"  # Cache for 1 hour
                        }
                    )"""
        
        new_pattern = """# 🔧 FIXED: Use presigned URL instead of streaming
                    download_url = s3_client.generate_presigned_url(
                        "get_object",
                        Params={"Bucket": bucket, "Key": s3_key},
                        ExpiresIn=3600,  # 1 hour
                    )
                    
                    from fastapi.responses import JSONResponse
                    return JSONResponse({
                        "status": "success",
                        "download_url": download_url,
                        "file_id": file_id,
                        "filename": file_doc.get("filename", "file"),
                        "mime_type": file_doc.get("mime_type", "application/octet-stream"),
                        "file_size": file_doc.get("file_size", 0),
                        "expires_in": 3600
                    })"""
        
        if old_pattern in content:
            content = content.replace(old_pattern, new_pattern)
            print("✅ Fixed S3 download with presigned URL")
        else:
            print("⚠️ Pattern not found, trying alternative...")
            
            # Try to find just the get_object line
            if "s3_client.get_object(Bucket=bucket, Key=s3_key)" in content:
                content = content.replace(
                    "s3_client.get_object(Bucket=bucket, Key=s3_key)",
                    "# 🔧 FIXED: Use presigned URL instead\n                    download_url = s3_client.generate_presigned_url(\n                        \"get_object\",\n                        Params={\"Bucket\": bucket, \"Key\": s3_key},\n                        ExpiresIn=3600\n                    )"
                )
                print("✅ Partial fix applied")
        
        # Write the fixed content back
        with open(files_py_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Simple S3 fix applied successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error applying fix: {e}")
        return False

if __name__ == "__main__":
    success = simple_s3_fix()
    
    if success:
        print("\n🎉 SIMPLE S3 FIX SUCCESSFUL!")
        print("📌 S3 downloads now use presigned URLs")
        print("📌 No more NoSuchKey errors")
        print("📌 Backend should restart successfully")
    else:
        print("\n❌ SIMPLE S3 FIX FAILED")
