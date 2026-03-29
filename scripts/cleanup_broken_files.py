#!/usr/bin/env python3
"""
MongoDB Cleanup Script for Broken File Records
===============================================

This script removes broken file records and message attachments from MongoDB.
It ensures only valid files with s3_key starting with "uploads/" remain.

STEPS:
1. Keep only valid files (s3_key starts with "uploads/")
2. Delete broken file records
3. Clean up message attachments
"""

import asyncio
import sys
import os
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent.parent / "backend"
sys.path.insert(0, str(backend_path))
os.chdir(str(backend_path))

try:
    from motor.motor_asyncio import AsyncIOMotorClient
    from config import settings
    from bson import ObjectId
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running this from the project root with backend dependencies installed")
    sys.exit(1)

async def cleanup_broken_files():
    """Clean up broken file records and message attachments"""
    
    print("🔧 Starting MongoDB cleanup for broken files...")
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.MONGODB_URI)
    db = client[settings.DATABASE_NAME]
    
    try:
        # STEP 1: Find all valid files (s3_key starts with "uploads/")
        print("\n📋 STEP 1: Finding valid files...")
        valid_files_cursor = db.files.find({"s3_key": {"$regex": "^uploads/"}})
        valid_files = await valid_files_cursor.to_list(length=None)
        print(f"✅ Found {len(valid_files)} valid files with 'uploads/' prefix")
        
        # Show some examples
        if valid_files:
            print("📄 Example valid files:")
            for i, file in enumerate(valid_files[:3]):
                print(f"   - {file.get('filename', 'unknown')} (s3_key: {file.get('s3_key', 'unknown')})")
        
        # STEP 2: Delete broken file records
        print("\n🗑️  STEP 2: Deleting broken file records...")
        
        # Count broken files before deletion
        broken_files_count = await db.files.count_documents({
            "$or": [
                {"s3_key": {"$exists": False}},
                {"s3_key": {"$not": {"$regex": "^uploads/"}}}
            ]
        })
        print(f"📊 Found {broken_files_count} broken file records to delete")
        
        if broken_files_count > 0:
            # Delete broken files
            delete_result = await db.files.delete_many({
                "$or": [
                    {"s3_key": {"$exists": False}},
                    {"s3_key": {"$not": {"$regex": "^uploads/"}}}
                ]
            })
            print(f"✅ Deleted {delete_result.deleted_count} broken file records")
        else:
            print("✅ No broken file records found")
        
        # STEP 3: Clean up message attachments
        print("\n🧹 STEP 3: Cleaning up message attachments...")
        
        # Get all valid file IDs after cleanup
        valid_file_ids = await db.files.distinct("_id")
        print(f"📊 Found {len(valid_file_ids)} valid file IDs")
        
        # Count messages with broken attachments before cleanup
        messages_with_broken_attachments = await db.messages.count_documents({
            "attachments.file_id": {"$nin": valid_file_ids}
        })
        print(f"📊 Found {messages_with_broken_attachments} messages with broken attachments")
        
        if messages_with_broken_attachments > 0:
            # Remove broken attachments from messages
            update_result = await db.messages.update_many(
                {},
                {
                    "$pull": {
                        "attachments": {
                            "file_id": {"$nin": valid_file_ids}
                        }
                    }
                }
            )
            print(f"✅ Updated {update_result.modified_count} messages to remove broken attachments")
        else:
            print("✅ No broken attachments found in messages")
        
        # STEP 4: Final verification
        print("\n🔍 STEP 4: Final verification...")
        
        total_files = await db.files.count_documents({})
        total_messages = await db.messages.count_documents({})
        
        print(f"📊 Final database state:")
        print(f"   - Total files: {total_files}")
        print(f"   - Total messages: {total_messages}")
        print(f"   - Valid files: {len(valid_file_ids)}")
        
        # Verify all remaining files have valid s3_key
        invalid_files_after = await db.files.count_documents({
            "$or": [
                {"s3_key": {"$exists": False}},
                {"s3_key": {"$not": {"$regex": "^uploads/"}}}
            ]
        })
        
        if invalid_files_after == 0:
            print("✅ All remaining files have valid s3_key format")
        else:
            print(f"⚠️  Warning: {invalid_files_after} files still have invalid s3_key format")
        
        print("\n🎉 Cleanup completed successfully!")
        print("📋 Summary:")
        print(f"   - Valid files kept: {len(valid_files)}")
        print(f"   - Broken files deleted: {delete_result.deleted_count if broken_files_count > 0 else 0}")
        print(f"   - Messages cleaned: {update_result.modified_count if messages_with_broken_attachments > 0 else 0}")
        
    except Exception as e:
        print(f"❌ Error during cleanup: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        client.close()
    
    return True

async def show_database_stats():
    """Show current database statistics before cleanup"""
    
    print("📊 Current Database Statistics:")
    print("=" * 50)
    
    client = AsyncIOMotorClient(settings.MONGODB_URI)
    db = client[settings.DATABASE_NAME]
    
    try:
        total_files = await db.files.count_documents({})
        valid_files = await db.files.count_documents({"s3_key": {"$regex": "^uploads/"}})
        broken_files = total_files - valid_files
        
        total_messages = await db.messages.count_documents({})
        
        print(f"📁 Files:")
        print(f"   - Total files: {total_files}")
        print(f"   - Valid files (uploads/): {valid_files}")
        print(f"   - Broken files: {broken_files}")
        
        print(f"\n💬 Messages:")
        print(f"   - Total messages: {total_messages}")
        
        if broken_files > 0:
            print(f"\n⚠️  Warning: {broken_files} broken files found!")
            print("   Run cleanup to remove them.")
        else:
            print(f"\n✅ All files are valid!")
            
    except Exception as e:
        print(f"❌ Error getting stats: {str(e)}")
    
    finally:
        client.close()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Clean up broken file records from MongoDB")
    parser.add_argument("--stats-only", action="store_true", help="Show statistics only, don't clean")
    parser.add_argument("--force", action="store_true", help="Force cleanup without confirmation")
    
    args = parser.parse_args()
    
    if args.stats_only:
        asyncio.run(show_database_stats())
    else:
        if not args.force:
            print("⚠️  This will permanently delete broken file records!")
            print("   - Files without s3_key")
            print("   - Files with s3_key not starting with 'uploads/'")
            print("   - Message attachments pointing to deleted files")
            print("\nContinue? (y/N): ", end="")
            
            try:
                response = input().lower()
                if response not in ['y', 'yes']:
                    print("❌ Cleanup cancelled")
                    sys.exit(0)
            except KeyboardInterrupt:
                print("\n❌ Cleanup cancelled")
                sys.exit(0)
        
        success = asyncio.run(cleanup_broken_files())
        if success:
            print("\n✅ Cleanup completed successfully!")
        else:
            print("\n❌ Cleanup failed!")
            sys.exit(1)
