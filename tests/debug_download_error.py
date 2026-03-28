#!/usr/bin/env python3
"""
Debug Download Error
"""

import os

def debug_download_error():
    """Add debug logging to download"""
    print("🔧 DEBUGGING DOWNLOAD ERROR")
    print("=" * 50)
    
    try:
        # Read the file
        files_py_path = os.path.join('backend', 'routes', 'files.py')
        with open(files_py_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find the download_file function and add debug
        if "async def download_file(" in content:
            # Add debug at the beginning of the function
            old_start = """async def download_file(
    file_id: str,
    request: Request,
    device_id: Optional[str] = Query(
        None, description="Device ID (optional for web clients)"
    ),
    current_user: str = Depends(get_current_user_download_dependency()),
):"""
            
            new_start = """async def download_file(
    file_id: str,
    request: Request,
    device_id: Optional[str] = Query(
        None, description="Device ID (optional for web clients)"
    ),
    current_user: str = Depends(get_current_user_download_dependency()),
):
    \"\"\"🔥 DEBUG VERSION - Download with extensive logging\"\"\"
    try:
        print(f"🔥 DOWNLOAD CALLED: file_id={file_id}, user={current_user}")
        print(f"🔥 DOWNLOAD HEADERS: {dict(request.headers)}")
    except Exception as e:
        print(f"🔥 DOWNLOAD DEBUG ERROR: {e}")"""
            
            if old_start in content:
                content = content.replace(old_start, new_start)
                print("✅ Debug logging added to download_file")
            else:
                print("⚠️ Download function start pattern not found")
        
        # Add debug around S3 operations
        if "s3_client.get_object(Bucket=bucket, Key=s3_key)" in content:
            old_s3 = """s3_client.get_object(Bucket=bucket, Key=s3_key)"""
            new_s3 = """print(f"🔥 DOWNLOAD S3: Fetching {s3_key} from {bucket}")
            try:
                s3_obj = s3_client.get_object(Bucket=bucket, Key=s3_key)
                print(f"✅ DOWNLOAD S3 SUCCESS: {s3_key}")
            except Exception as e:
                print(f"❌ DOWNLOAD S3 FAILED: {s3_key} - {e}")
                raise e"""
            
            content = content.replace(old_s3, new_s3)
            print("✅ Download S3 debug added")
        
        # Add debug around presigned URL generation
        if "s3_client.generate_presigned_url(" in content:
            old_presigned = """s3_client.generate_presigned_url(
                "get_object",
                Params={"Bucket": settings.S3_BUCKET, "Key": s3_key},
                ExpiresIn=300,  # 5 minutes
            )"""
            new_presigned = """print(f"🔥 PRESIGNED URL: Generating for {s3_key}")
            try:
                download_url = s3_client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": settings.S3_BUCKET, "Key": s3_key},
                    ExpiresIn=300,  # 5 minutes
                )
                print(f"✅ PRESIGNED URL SUCCESS: {download_url}")
            except Exception as e:
                print(f"❌ PRESIGNED URL FAILED: {e}")
                raise e"""
            
            content = content.replace(old_presigned, new_presigned)
            print("✅ Presigned URL debug added")
        
        # Write back
        with open(files_py_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Download debug logging added successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error adding download debug: {e}")
        return False

if __name__ == "__main__":
    success = debug_download_error()
    
    if success:
        print("\n🎉 DOWNLOAD DEBUG LOGGING ADDED!")
        print("📌 Run the test again to see detailed download error logs")
    else:
        print("\n❌ DOWNLOAD DEBUG LOGGING FAILED")
