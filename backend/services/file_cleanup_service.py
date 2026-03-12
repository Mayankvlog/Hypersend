"""
File Cleanup Service
====================

Manages automatic cleanup of expired files based on FILE_RETENTION_HOURS.
Safely deletes files from /app/storage and /app/uploads directories
without removing files that are currently being uploaded.

Features:
- Respects FILE_RETENTION_HOURS configuration
- Safely checks for active uploads before deletion
- Removes expired files from both storage and uploads directories
- Memory-efficient batch processing
- Comprehensive logging of all deletion events
- Prevents deletion of files currently being accessed
"""

import os
import asyncio
import logging
from typing import Optional, Set
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple, Any
import aiofiles

try:
    from backend.config import settings
    from backend.db_proxy import files_collection, uploads_collection
except ImportError:
    from config import settings
    from db_proxy import files_collection, uploads_collection

logger = logging.getLogger(__name__)


class FileCleanupService:
    """Service for cleaning up expired files from storage."""
    
    def __init__(self):
        """Initialize the file cleanup service."""
        # Use DATA_ROOT/storage as the default storage path
        self.data_root = Path(settings.DATA_ROOT)
        self.storage_path = self.data_root / "storage"
        self.upload_dir = Path(settings.UPLOAD_DIR)
        self.temp_storage_path = Path(settings.TEMP_STORAGE_PATH)
        self.retention_hours = settings.FILE_RETENTION_HOURS
        self.retention_seconds = settings.FILE_TTL_SECONDS
        
        # Verify directory paths exist
        for dir_path in [self.storage_path, self.upload_dir, self.temp_storage_path]:
            if not dir_path.exists():
                logger.warning(f"[CLEANUP] Directory does not exist: {dir_path}")
    
    async def cleanup_expired_files(self) -> Dict[str, Any]:
        """
        Clean up all expired files from storage and uploads directories.
        
        Returns:
            Dictionary with cleanup statistics:
            {
                "files_deleted": int,
                "files_size_freed_bytes": int,
                "errors": int,
                "active_uploads_skipped": int,
                "deletion_details": List[str]  # Log of deleted files
            }
        """
        logger.info(
            f"[CLEANUP] Starting file cleanup task (retention={self.retention_hours}h, "
            f"threshold={self.retention_seconds}s)"
        )
        
        stats = {
            "files_deleted": 0,
            "files_size_freed_bytes": 0,
            "errors": 0,
            "active_uploads_skipped": 0,
            "uploads_skipped": 0,
            "temp_skipped": 0,
            "deletion_details": []
        }
        
        try:
            # Get set of files currently being uploaded (active uploads)
            active_upload_files = await self._get_active_upload_files()
            if active_upload_files is None:
                logger.error("[CLEANUP] Cannot determine active uploads - aborting cleanup to prevent data loss")
                stats["errors"] += 1
                return stats
            logger.info(f"[CLEANUP] Found {len(active_upload_files)} active uploads - will skip these")
            
            # Clean storage directory
            storage_stats = await self._cleanup_directory(
                self.storage_path, 
                active_upload_files,
                "storage"
            )
            stats["files_deleted"] += storage_stats["files_deleted"]
            stats["files_size_freed_bytes"] += storage_stats["files_size_freed_bytes"]
            stats["errors"] += storage_stats["errors"]
            stats["deletion_details"].extend(storage_stats["deletion_details"])
            # Aggregate per-directory counters
            stats["active_uploads_skipped"] += storage_stats.get("active_uploads_skipped", 0)
            stats["uploads_skipped"] += storage_stats.get("uploads_skipped", 0)
            stats["temp_skipped"] += storage_stats.get("temp_skipped", 0)
            
            # Clean uploads directory
            uploads_stats = await self._cleanup_directory(
                self.upload_dir,
                active_upload_files,
                "uploads"
            )
            stats["files_deleted"] += uploads_stats["files_deleted"]
            stats["files_size_freed_bytes"] += uploads_stats["files_size_freed_bytes"]
            stats["errors"] += uploads_stats["errors"]
            stats["deletion_details"].extend(uploads_stats["deletion_details"])
            # Aggregate per-directory counters
            stats["active_uploads_skipped"] += uploads_stats.get("active_uploads_skipped", 0)
            stats["uploads_skipped"] += uploads_stats.get("uploads_skipped", 0)
            stats["temp_skipped"] += uploads_stats.get("temp_skipped", 0)
            
            # Clean temp directory
            temp_stats = await self._cleanup_directory(
                self.temp_storage_path,
                active_upload_files,
                "temp"
            )
            stats["files_deleted"] += temp_stats["files_deleted"]
            stats["files_size_freed_bytes"] += temp_stats["files_size_freed_bytes"]
            stats["errors"] += temp_stats["errors"]
            stats["deletion_details"].extend(temp_stats["deletion_details"])
            # Aggregate per-directory counters
            stats["active_uploads_skipped"] += temp_stats.get("active_uploads_skipped", 0)
            stats["uploads_skipped"] += temp_stats.get("uploads_skipped", 0)
            stats["temp_skipped"] += temp_stats.get("temp_skipped", 0)
            
            # Log summary
            freed_mb = stats["files_size_freed_bytes"] / (1024 * 1024)
            logger.info(
                f"[CLEANUP] Cleanup completed: {stats['files_deleted']} files deleted, "
                f"{freed_mb:.2f} MB freed, {stats['errors']} errors, "
                f"{stats['active_uploads_skipped']} active uploads skipped"
            )
            
            return stats
            
        except Exception as e:
            logger.error(f"[CLEANUP] Cleanup failed: {type(e).__name__}: {e}", exc_info=True)
            stats["errors"] += 1
            return stats
    
    async def _get_active_upload_files(self) -> Optional[Set[str]]:
        """
        Get set of files currently being uploaded (active uploads).
        
        Returns:
            Set of file IDs that are currently being uploaded, or None if an error occurred
            and we cannot determine active uploads safely.
        """
        try:
            # Get uploads in progress from MongoDB
            active_uploads = await uploads_collection().find(
                {"status": {"$in": ["uploading", "in_progress", "pending"]}},
                {"file_id": 1}
            ).to_list(None)
            
            active_ids = {upload.get("file_id") for upload in active_uploads if upload.get("file_id")}
            logger.debug(f"[CLEANUP] Found {len(active_ids)} active upload file_ids")
            return active_ids
            
        except Exception as e:
            logger.warning(f"[CLEANUP] Failed to fetch active uploads: {e}")
            return None  # Return None on error - signal that we cannot determine active uploads
    
    async def _cleanup_directory(
        self, 
        directory: Path,
        active_upload_files: set,
        dir_type: str
    ) -> Dict[str, Any]:
        """
        Clean up expired files in a specific directory.
        
        Args:
            directory: Path to directory to clean
            active_upload_files: Set of file IDs currently being uploaded
            dir_type: Type of directory (storage, uploads, temp) for logging
            
        Returns:
            Statistics for this directory cleanup
        """
        stats = {
            "files_deleted": 0,
            "files_size_freed_bytes": 0,
            "errors": 0,
            "active_uploads_skipped": 0,
            "uploads_skipped": 0,
            "temp_skipped": 0,
            "deletion_details": []
        }
        
        if not directory.exists():
            logger.warning(f"[CLEANUP] Directory does not exist: {directory}")
            return stats
        
        try:
            # Get current time in UTC
            current_time = datetime.now(timezone.utc)
            expiration_threshold = current_time - timedelta(seconds=self.retention_seconds)
            
            logger.info(
                f"[CLEANUP] Scanning {dir_type} directory: {directory} "
                f"for files older than {expiration_threshold.isoformat()}"
            )
            
            # Iterate through files in directory
            files_to_delete = []
            for file_path in directory.rglob("*"):
                # Skip directories
                if file_path.is_dir():
                    continue
                
                # Skip hidden and system files
                if file_path.name.startswith("."):
                    continue
                
                # Get file modification time
                try:
                    # Use modification time as creation time (most reliable)
                    file_mtime = datetime.fromtimestamp(
                        file_path.stat().st_mtime,
                        tz=timezone.utc
                    )
                    file_size = file_path.stat().st_size
                    
                    # Check if file is expired
                    if file_mtime < expiration_threshold:
                        # Check if this file is being uploaded (skip if so)
                        file_id = file_path.stem  # filename without extension
                        if file_id in active_upload_files:
                            logger.debug(
                                f"[CLEANUP] Skipping active upload file: {file_path.name}"
                            )
                            stats["active_uploads_skipped"] += 1
                            continue
                        
                        # For temp directory, only skip files under specific conditions
                        if dir_type == "temp":
                            # Skip temp files that are currently being written to (modified within last minute)
                            current_check_time = datetime.now(timezone.utc)
                            file_mtime_current = datetime.fromtimestamp(
                                file_path.stat().st_mtime,
                                tz=timezone.utc
                            )
                            if (current_check_time - file_mtime_current) < timedelta(minutes=1):
                                logger.debug(
                                    f"[CLEANUP] Skipping recently modified temp file: {file_path.name}"
                                )
                                stats["temp_skipped"] += 1
                                continue
                        
                        files_to_delete.append((file_path, file_mtime, file_size))
                        
                except (OSError, ValueError) as e:
                    logger.warning(f"[CLEANUP] Error reading file metadata {file_path}: {e}")
                    stats["errors"] += 1
                    continue
            
            logger.info(
                f"[CLEANUP] Found {len(files_to_delete)} expired files in {dir_type} "
                f"to delete"
            )
            
            # Delete expired files
            for file_path, file_mtime, file_size in files_to_delete:
                try:
                    # Final safety check - verify file still exists and is not being modified
                    if not file_path.exists():
                        logger.debug(f"[CLEANUP] File already deleted: {file_path.name}")
                        continue
                    
                    # Check if file has been modified recently (within 1 minute)
                    # This prevents deletion of files being written to
                    current_check_time = datetime.now(timezone.utc)
                    file_mtime_current = datetime.fromtimestamp(
                        file_path.stat().st_mtime,
                        tz=timezone.utc
                    )
                    time_since_modification = (current_check_time - file_mtime_current).total_seconds()
                    
                    if time_since_modification < 60:  # Margin of 1 minute
                        logger.debug(
                            f"[CLEANUP] Skipping recently modified file: {file_path.name} "
                            f"(modified {time_since_modification:.0f}s ago)"
                        )
                        continue
                    
                    # Delete the file
                    try:
                        file_path.unlink()
                        stats["files_deleted"] += 1
                        stats["files_size_freed_bytes"] += file_size
                        
                        detail = (
                            f"Deleted {dir_type}/{file_path.name} "
                            f"(age={int(time_since_modification/3600)}h, "
                            f"size={file_size/1024:.1f}KB)"
                        )
                        stats["deletion_details"].append(detail)
                        logger.info(f"[CLEANUP] ✓ {detail}")
                        
                    except OSError as e:
                        logger.error(
                            f"[CLEANUP] Failed to delete {dir_type}/{file_path.name}: {e}"
                        )
                        stats["errors"] += 1
                    
                except Exception as e:
                    logger.error(
                        f"[CLEANUP] Unexpected error processing {file_path.name}: {e}"
                    )
                    stats["errors"] += 1
                    continue
            
        except Exception as e:
            logger.error(
                f"[CLEANUP] Error during directory cleanup for {dir_type}: "
                f"{type(e).__name__}: {e}",
                exc_info=True
            )
            stats["errors"] += 1
        
        return stats


async def periodic_file_cleanup(interval_minutes: int = 60) -> None:
    """
    Run periodic file cleanup task.
    
    This function is meant to run as an asyncio task during application lifetime.
    
    Args:
        interval_minutes: Interval between cleanup runs (default 60 minutes)
    """
    cleanup_service = FileCleanupService()
    interval_seconds = interval_minutes * 60
    
    logger.info(
        f"[CLEANUP-SCHEDULER] File cleanup task started (interval={interval_minutes}min)"
    )
    
    try:
        while True:
            try:
                await asyncio.sleep(interval_seconds)
                await cleanup_service.cleanup_expired_files()
            except asyncio.CancelledError:
                logger.info("[CLEANUP-SCHEDULER] File cleanup task cancelled")
                break
            except Exception as e:
                logger.error(
                    f"[CLEANUP-SCHEDULER] Unexpected error in cleanup task: "
                    f"{type(e).__name__}: {e}",
                    exc_info=True
                )
                # Continue running despite errors
                await asyncio.sleep(interval_seconds)
    except Exception as e:
        logger.error(
            f"[CLEANUP-SCHEDULER] Fatal error in cleanup scheduler: {e}",
            exc_info=True
        )
