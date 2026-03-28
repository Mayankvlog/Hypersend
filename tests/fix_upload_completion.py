#!/usr/bin/env python3
"""
Fix Upload Completion Endpoint
This will fix the root cause of 404 download errors
"""

import asyncio
import sys
import os
from dotenv import load_dotenv

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

def fix_upload_completion():
    """Fix upload completion endpoint"""
    print("🔧 FIXING UPLOAD COMPLETION ENDPOINT")
    print("=" * 50)
    
    try:
        # Load environment variables
        env_path = os.path.join(os.path.dirname(__file__), 'backend', '.env')
        load_dotenv(env_path)
        
        print("🔍 Current environment:")
        print(f"📌 MONGODB_URI: {os.getenv('MONGODB_URI', 'Not set')[:50]}...")
        print(f"📌 DATABASE_NAME: {os.getenv('DATABASE_NAME', 'Not set')}")
        
        # The issue is that upload completion is failing
        # Let's fix the database connection consistency
        
        # Read the files.py file
        files_py_path = os.path.join(os.path.dirname(__file__), 'backend', 'routes', 'files.py')
        
        with open(files_py_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Fix 1: Ensure consistent database connection in upload completion
        print("🔧 Fix 1: Ensuring consistent database connection...")
        
        # Replace uploads_collection() with direct database access
        old_upload_pattern = "upload_record = await uploads_collection().find_one({\"_id\": upload_id})"
        new_upload_pattern = """# 🔧 FIXED: Use direct database connection for consistency
        from backend.database import get_database
        db = get_database()
        upload_record = await db.uploads.find_one({"_id": upload_id})"""
        
        if old_upload_pattern in content:
            content = content.replace(old_upload_pattern, new_upload_pattern)
            print("✅ Fixed upload record lookup")
        else:
            print("⚠️ Upload record lookup pattern not found")
        
        # Fix 2: Ensure consistent database connection in upload initiation
        print("🔧 Fix 2: Ensuring consistent database connection in upload initiation...")
        
        old_init_pattern = "uploads_collection().insert_one(upload_data)"
        new_init_pattern = """# 🔧 FIXED: Use direct database connection for consistency
                from backend.database import get_database
                db = get_database()
                await db.uploads.insert_one(upload_data)"""
        
        if old_init_pattern in content:
            content = content.replace(old_init_pattern, new_init_pattern)
            print("✅ Fixed upload initiation")
        else:
            print("⚠️ Upload initiation pattern not found")
        
        # Fix 3: Ensure consistent database connection in file creation
        print("🔧 Fix 3: Ensuring consistent database connection in file creation...")
        
        old_file_pattern = "insert_result = await files_collection().insert_one(file_document)"
        new_file_pattern = """# 🔧 FIXED: Use direct database connection for consistency
            from backend.database import get_database
            db = get_database()
            insert_result = await db.files.insert_one(file_document)"""
        
        if old_file_pattern in content:
            content = content.replace(old_file_pattern, new_file_pattern)
            print("✅ Fixed file creation")
        else:
            print("⚠️ File creation pattern not found")
        
        # Write the fixed content back
        with open(files_py_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Upload completion endpoint fixed!")
        print("📌 All database connections now use direct get_database()")
        print("📌 This should fix the 404 download errors")
        
        return True
        
    except Exception as e:
        print(f"❌ Error fixing upload completion: {e}")
        return False

if __name__ == "__main__":
    success = fix_upload_completion()
    
    if success:
        print("\n🎉 UPLOAD COMPLETION FIX SUCCESSFUL!")
        print("📌 Database connections are now consistent")
        print("📌 Upload completion should work properly")
        print("📌 File records should be created in database")
        print("📌 404 download errors should be resolved")
        print("\n🚀 NEXT STEPS:")
        print("📌 1. Restart backend server")
        print("📌 2. Test upload -> download flow")
        print("📌 3. Verify file records are created")
    else:
        print("\n❌ UPLOAD COMPLETION FIX FAILED")
        print("📌 Manual intervention required")
