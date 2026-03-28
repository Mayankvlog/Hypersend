#!/usr/bin/env python3
"""
Ultimate Download Fix - Copy-Paste Safe Code
"""

import os

def ultimate_download_fix():
    """Apply ultimate download fix"""
    print("🔧 ULTIMATE DOWNLOAD FIX")
    print("=" * 50)
    
    try:
        # Read the file
        files_py_path = os.path.join('backend', 'routes', 'files.py')
        with open(files_py_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print("🔍 Applying ultimate download fix...")
        
        # Find the download function and replace with safe code
        # Look for the existing download function signature
        download_start = "async def download_file("
        
        if download_start in content:
            # Find the function start
            start_idx = content.find(download_start)
            if start_idx != -1:
                # Find the next function definition to determine the end
                next_function = content.find("@router.", start_idx + 1)
                if next_function == -1:
                    next_function = len(content)
                
                # Extract the current download function
                current_function = content[start_idx:next_function]
                
                # Replace with the safe version
                safe_function = '''async def download_file(
    file_id: str,
    request: Request,
    device_id: Optional[str] = Query(
        None, description="Device ID (optional for web clients)"
    ),
    current_user: str = Depends(get_current_user_download_dependency()),
):
    """🔥 ULTIMATE SAFE VERSION - Download with comprehensive error handling"""
    try:
        print("🔍 FILE_ID:", file_id)

        # 1. DB fetch
        from bson import ObjectId
        file_oid = ObjectId(file_id)
        
        file_doc = await asyncio.wait_for(
            files_collection().find_one({"_id": file_oid}),
            timeout=30.0,
        )

        if not file_doc:
            print("❌ File not found in DB")
            raise HTTPException(status_code=404, detail="File not found")

        print("✅ FILE FOUND:", file_doc.get("filename", "unknown"))

        # 2. s3_key check
        s3_key = file_doc.get("s3_key") or file_doc.get("object_key")

        if not s3_key:
            print("❌ Missing s3_key")
            raise HTTPException(status_code=500, detail="File missing S3 key")

        print("📦 S3 KEY:", s3_key)

        # 3. Get S3 client
        s3_client = _get_s3_client()
        if not s3_client:
            print("❌ S3 client not available")
            raise HTTPException(status_code=503, detail="S3 service not available")

        # 4. generate presigned URL
        from backend.config import settings
        bucket = settings.S3_BUCKET
        
        print("🚀 GENERATING PRESIGNED URL...")
        url = s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": bucket,
                "Key": s3_key
            },
            ExpiresIn=3600
        )

        print("✅ PRESIGNED URL GENERATED")

        # 5. Return redirect to presigned URL
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url)

    except HTTPException:
        raise
    except Exception as e:
        print("💥 DOWNLOAD ERROR:", str(e))
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")'''
                
                # Replace the function
                content = content[:start_idx] + safe_function + content[next_function:]
                print("✅ Download function replaced with safe version")
            else:
                print("❌ Could not find download function")
                return False
        else:
            print("❌ Download function not found")
            return False
        
        # Write back
        with open(files_py_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Ultimate download fix applied successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error applying ultimate fix: {e}")
        return False

def check_env_variables():
    """Check environment variables"""
    print("\n🔍 CHECKING ENVIRONMENT VARIABLES")
    print("=" * 50)
    
    env_vars = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY", 
        "AWS_REGION",
        "S3_BUCKET"
    ]
    
    missing_vars = []
    
    for var in env_vars:
        value = os.getenv(var)
        if value:
            print(f"✅ {var}: {'*' * (len(value) - 4)}{value[-4:]}")
        else:
            print(f"❌ {var}: MISSING")
            missing_vars.append(var)
    
    if missing_vars:
        print(f"\n⚠️ Missing environment variables: {missing_vars}")
        print("👉 Please set these in your .env file")
    else:
        print("\n✅ All environment variables present!")
    
    return len(missing_vars) == 0

if __name__ == "__main__":
    success = ultimate_download_fix()
    
    if success:
        print("\n🎉 ULTIMATE DOWNLOAD FIX SUCCESSFUL!")
        print("📌 Safe download function implemented")
        print("📌 Comprehensive error handling added")
        print("📌 Presigned URL generation fixed")
        
        # Check environment variables
        env_ok = check_env_variables()
        
        if env_ok:
            print("\n🚀 READY FOR PRODUCTION!")
            print("📌 All systems go!")
        else:
            print("\n⚠️ Environment variables need to be set")
    else:
        print("\n❌ ULTIMATE DOWNLOAD FIX FAILED")
