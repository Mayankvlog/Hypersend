#!/usr/bin/env python3
"""
Debug script to check file document status in MongoDB
"""

import asyncio
import sys
import os

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

async def debug_file_status():
    """Check file document status for the specific file_id"""
    try:
        from backend.db_proxy import files_collection, uploads_collection
        from bson import ObjectId
        
        # Check the specific file_id mentioned by user
        file_id = "69c6de50087aed60e55e3514"
        
        print(f"🔍 DEBUG: Checking file_id: {file_id}")
        print("=" * 50)
        
        # Check in files_collection
        print("📁 Checking files_collection...")
        file = None
        try:
            if ObjectId.is_valid(file_id):
                file_oid = ObjectId(file_id)
                file = await files_collection().find_one({"_id": file_oid})
                print(f"Result: {file}")
                
                if file:
                    print("\n📋 File Document Analysis:")
                    print(f"  - Status: {file.get('status')}")
                    print(f"  - S3 Uploaded: {file.get('s3_uploaded')}")
                    print(f"  - S3 Key: {file.get('s3_key')}")
                    print(f"  - Created By: {file.get('created_by')}")
                    print(f"  - Created At: {file.get('created_at')}")
                    print(f"  - Completed At: {file.get('completed_at')}")
                else:
                    print("❌ File not found in files_collection")
            else:
                print("❌ Invalid ObjectId format")
        except Exception as e:
            print(f"❌ Error checking files_collection: {e}")
        
        print("\n" + "=" * 50)
        
        # Check in uploads_collection (since we use upload_id as _id)
        print("📤 Checking uploads_collection...")
        upload = None
        try:
            upload = await uploads_collection().find_one({"_id": file_id})
            print(f"Result: {upload}")
            
            if upload:
                print("\n📋 Upload Document Analysis:")
                print(f"  - Status: {upload.get('status')}")
                print(f"  - S3 Uploaded: {upload.get('s3_uploaded')}")
                print(f"  - S3 Key: {upload.get('s3_key')}")
                print(f"  - Created By: {upload.get('created_by')}")
                print(f"  - Created At: {upload.get('created_at')}")
                print(f"  - Completed At: {upload.get('completed_at')}")
            else:
                print("❌ Upload not found in uploads_collection")
        except Exception as e:
            print(f"❌ Error checking uploads_collection: {e}")
        
        print("\n" + "=" * 50)
        
        # Check all recent files to understand the pattern
        print("🔍 Checking recent uploads (last 5)...")
        try:
            recent_uploads = await uploads_collection().find().sort("created_at", -1).limit(5).to_list(None)
            for i, upload in enumerate(recent_uploads):
                print(f"\n📋 Upload {i+1}:")
                print(f"  - ID: {upload.get('_id')}")
                print(f"  - Status: {upload.get('status')}")
                print(f"  - S3 Uploaded: {upload.get('s3_uploaded')}")
                print(f"  - File Name: {upload.get('file_name')}")
        except Exception as e:
            print(f"❌ Error checking recent uploads: {e}")
        
        print("\n" + "=" * 50)
        print("🎯 DIAGNOSIS:")
        
        # Final diagnosis
        if not file and not upload:
            print("❌ FRONTEND WRONG ID - No records found with this ID")
        elif upload and upload.get("s3_uploaded") is False:
            print("❌ UPLOAD INCOMPLETE - S3 upload not marked as complete")
        elif upload and upload.get("s3_key") is None:
            print("❌ COMPLETE API BROKEN - S3 key is missing")
        elif file and file.get("status") == "completed":
            print("✅ FILE COMPLETE - All systems working")
        else:
            print("🤔 UNKNOWN STATE - Check logs above")
            
    except Exception as e:
        print(f"❌ DEBUG SCRIPT ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_file_status())
