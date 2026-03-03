#!/usr/bin/env python3
"""
Migration script to fix deleted_from_server vs deleted_from_cloud inconsistency.

This script:
1. Copies deleted_from_server to deleted_from_cloud for existing documents
2. Ensures both fields exist for all file documents
"""

import asyncio
import logging
from datetime import datetime, timezone

try:
    from db_proxy import files_collection
except ImportError:
    from backend.db_proxy import files_collection

logger = logging.getLogger(__name__)

async def migrate_deleted_from_fields():
    """Migrate deleted_from_server to deleted_from_cloud for consistency."""
    
    logger.info("Starting migration for deleted_from fields...")
    
    try:
        # Find all documents that have deleted_from_server but not deleted_from_cloud
        cursor = files_collection().find({
            "deleted_from_server": {"$exists": True},
            "deleted_from_cloud": {"$exists": False}
        })
        
        count = 0
        async for doc in cursor:
            # Copy deleted_from_server to deleted_from_cloud
            await files_collection().update_one(
                {"_id": doc["_id"]},
                {
                    "$set": {
                        "deleted_from_cloud": doc["deleted_from_server"],
                        "migration_timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            count += 1
        
        logger.info(f"Migrated {count} documents to have both deleted_from fields")
        
        # Find all documents that have deleted_from_cloud but not deleted_from_server
        cursor = files_collection().find({
            "deleted_from_cloud": {"$exists": True},
            "deleted_from_server": {"$exists": False}
        })
        
        count = 0
        async for doc in cursor:
            # Copy deleted_from_cloud to deleted_from_server
            await files_collection().update_one(
                {"_id": doc["_id"]},
                {
                    "$set": {
                        "deleted_from_server": doc["deleted_from_cloud"],
                        "migration_timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            count += 1
        
        logger.info(f"Migrated {count} documents to have both deleted_from fields (reverse)")
        
        logger.info("Migration completed successfully")
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise

if __name__ == "__main__":
    # Configure logging for standalone execution
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    asyncio.run(migrate_deleted_from_fields())
