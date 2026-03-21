import os
import uuid
import logging
import asyncio
import tempfile
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.responses import JSONResponse
from bson import ObjectId

from backend.models import (
    StatusCreate,
    StatusInDB,
    StatusResponse,
    StatusListResponse,
    FileInitRequest,
    FileInitResponse,
    FileCompleteResponse,
)
from backend.auth.utils import get_current_user
from backend.config import settings
from backend.database import get_database
from backend.utils.s3_utils import upload_file_to_s3

# Initialize router
router = APIRouter(prefix="/api/v1/status", tags=["status"])

# Initialize logger
logger = logging.getLogger(__name__)


# Status collection helper
async def get_status_collection():
    """Get status collection from database"""
    db = get_database()
    return db["statuses"]


async def get_video_duration(
    file_content: bytes, filename: Optional[str]
) -> Optional[float]:
    """
    Get video duration in seconds using ffprobe (async version)

    Args:
        file_content: Video file bytes
        filename: Original filename for extension (can be None)

    Returns:
        Duration in seconds or None if unable to determine
    """
    try:
        # Create safe filename fallback if None
        safe_filename = filename or "video.mp4"

        # Create temporary file
        with tempfile.NamedTemporaryFile(
            suffix=os.path.splitext(safe_filename)[1], delete=False
        ) as temp_file:
            temp_file.write(file_content)
            temp_file_path = temp_file.name

        try:
            # Use asyncio subprocess to get video duration
            cmd = [
                "ffprobe",
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                temp_file_path,
            ]

            # Run ffprobe asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            try:
                # Add timeout to prevent indefinite hangs
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=10.0
                )
            except asyncio.TimeoutError:
                logger.warning(
                    f"[VIDEO_DURATION] ffprobe timeout for {safe_filename}, terminating process"
                )
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except (asyncio.TimeoutError, ProcessLookupError):
                    logger.warning(
                        f"[VIDEO_DURATION] Force killing ffprobe process for {safe_filename}"
                    )
                    process.kill()
                    await process.wait()
                return None

            if process.returncode == 0:
                duration_str = stdout.decode().strip()
                if duration_str:
                    return float(duration_str)

            logger.warning(
                f"[VIDEO_DURATION] ffprobe failed for {safe_filename}: {stderr.decode()}"
            )
            return None

        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except OSError:
                pass

    except Exception as e:
        logger.error(
            f"[VIDEO_DURATION] Error getting duration for {filename or 'unknown'}: {str(e)}"
        )
        return None


async def validate_video_duration(
    file_content: bytes, filename: Optional[str], max_duration_minutes: int = 3
) -> bool:
    """
    Validate that video duration does not exceed maximum allowed (async version)

    Args:
        file_content: Video file bytes
        filename: Original filename (can be None)
        max_duration_minutes: Maximum allowed duration in minutes (default: 3)

    Returns:
        True if duration is valid, False otherwise
    """
    duration_seconds = await get_video_duration(file_content, filename)

    if duration_seconds is None:
        # If we can't determine duration, allow the file but log warning
        logger.warning(
            f"[VIDEO_DURATION] Could not determine duration for {filename or 'unknown'}, allowing upload"
        )
        return True

    max_seconds = max_duration_minutes * 60
    is_valid = duration_seconds <= max_seconds

    if not is_valid:
        logger.warning(
            f"[VIDEO_DURATION] Video {filename or 'unknown'} duration {duration_seconds:.1f}s exceeds maximum {max_seconds}s"
        )

    return is_valid


# ============================================================================
# BACKGROUND TASK: Auto-delete expired statuses
# ============================================================================
async def periodic_status_cleanup(interval_minutes: int = 5):
    """
    Background task to delete expired statuses from database
    Runs periodically to keep database clean

    Args:
        interval_minutes: How often to run cleanup (default: 5 minutes)
    """
    logger.info(
        f"[STATUS_CLEANUP] Starting status cleanup task (interval={interval_minutes}min)"
    )

    try:
        while True:
            try:
                await asyncio.sleep(interval_minutes * 60)  # Wait before first cleanup

                status_collection = await get_status_collection()
                current_time = datetime.now(timezone.utc)

                # Find all expired statuses
                expired_query = {"expires_at": {"$lt": current_time}}

                # Also delete associated S3 files
                expired_statuses = []
                cursor = status_collection.find(expired_query)
                async for doc in cursor:
                    expired_statuses.append(doc)

                # Clean up S3 files
                for status_doc in expired_statuses:
                    if status_doc.get("file_key"):
                        try:
                            from backend.utils import s3_utils

                            s3_utils.delete_object(
                                settings.S3_BUCKET, status_doc["file_key"]
                            )
                            logger.debug(
                                f"[STATUS_CLEANUP] Deleted S3 object: {status_doc['file_key']}"
                            )
                        except Exception as e:
                            logger.warning(
                                f"[STATUS_CLEANUP] Failed to delete S3 object {status_doc['file_key']}: {str(e)}"
                            )

                # Delete expired statuses from database
                result = await status_collection.delete_many(expired_query)

                if result.deleted_count > 0:
                    logger.info(
                        f"[STATUS_CLEANUP] Deleted {result.deleted_count} expired statuses"
                    )

            except asyncio.CancelledError:
                logger.info("[STATUS_CLEANUP] Status cleanup task cancelled")
                break
            except Exception as e:
                logger.error(
                    f"[STATUS_CLEANUP] Error during cleanup: {type(e).__name__}: {str(e)}"
                )
                # Continue running even if one cleanup cycle fails

    except Exception as e:
        logger.error(
            f"[STATUS_CLEANUP] Fatal error in status cleanup task: {type(e).__name__}: {str(e)}"
        )
        raise


# Helper function to convert StatusInDB to StatusResponse
def status_to_response(status: StatusInDB, current_user_id: str) -> StatusResponse:
    """Convert database status model to API response with proper URL mapping"""
    file_url = None
    if status.file_key:
        # Generate S3 URL using existing media endpoint pattern
        file_url = f"{settings.API_BASE_URL}/media/{status.file_key}"

    # Check if status is expired
    is_expired = datetime.now(timezone.utc) > status.expires_at

    return StatusResponse(
        id=status.id,
        user_id=status.user_id,
        text=status.text,
        file_url=file_url,
        file_type=status.file_type,
        duration=status.duration,
        created_at=status.created_at,
        expires_at=status.expires_at,
        views=status.views,
        is_expired=is_expired,
    )


@router.post("/", response_model=StatusResponse)
async def create_status(
    status_data: StatusCreate, current_user: str = Depends(get_current_user)
):
    """
    Create a new status (text or media)

    Request body:
    {
        "text": "Status text (optional if file_key provided)",
        "file_key": "S3 file key from /status/upload response (optional if text provided)"
    }

    Returns:
    StatusResponse with id, user_id, text, file_url, expires_at, etc.
    """
    try:
        status_collection = await get_status_collection()
        user_id = str(current_user)  # current_user is already a string (user_id) from get_current_user

        logger.info(
            f"[STATUS_CREATE] User {user_id} creating status - text_len: {len(status_data.text or '')}, has_file: {bool(status_data.file_key)}"
        )

        # Validate that either text or file_key is provided (done in model validator, but log it)
        if not status_data.text and not status_data.file_key:
            logger.warning(
                f"[STATUS_CREATE] Invalid: neither text nor file_key provided"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either text or file_key must be provided",
            )

        # Calculate expiry: 24 hours from now
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(hours=24)

        logger.info(
            f"[STATUS_CREATE] Created at: {created_at}, expires at: {expires_at}"
        )

        # Determine file type if file_key is provided
        file_type = None
        if status_data.file_key:
            # Parse file type from extension
            _, ext = os.path.splitext(status_data.file_key)
            if ext.lower() in [".jpg", ".jpeg", ".png", ".gif", ".webp"]:
                file_type = "image"
            elif ext.lower() in [".mp4", ".3gp"]:
                file_type = "video"
            logger.info(
                f"[STATUS_CREATE] Detected file_type: {file_type} from extension: {ext}"
            )

        # Create status document
        status_doc = StatusInDB(
            user_id=user_id,
            text=status_data.text,
            file_key=status_data.file_key,
            file_type=file_type,
            duration=status_data.duration,
            created_at=created_at,
            expires_at=expires_at,
        )

        logger.info(
            f"[STATUS_CREATE] Inserting status document: {status_doc.model_dump(by_alias=True)}"
        )

        # Insert into database
        result = await status_collection.insert_one(
            status_doc.model_dump(by_alias=True)
        )
        status_doc.id = str(result.inserted_id)

        logger.info(f"[STATUS_CREATE] Status created successfully, id: {status_doc.id}")

        # Convert to response
        response = status_to_response(status_doc, user_id)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=response.model_dump(by_alias=True),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[STATUS_CREATE] Error: {type(e).__name__}: {str(e)}")
        import traceback

        logger.error(f"[STATUS_CREATE] Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create status: {str(e)}",
        )


@router.post("/upload", response_model=FileInitResponse)
async def upload_status_media(
    file: UploadFile = File(...), current_user: str = Depends(get_current_user)
):
    """
    Upload media for status using existing S3 upload logic
    Stores file_key (S3 reference), not full URL

    Returns FileInitResponse with metadata for frontend
    """
    try:
        user_id = str(current_user)  # current_user is already a string (user_id) from get_current_user

        logger.info(
            f"[STATUS_UPLOAD] User {user_id} uploading status media: {file.filename}"
        )

        # Validate file type
        allowed_types = [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "video/mp4",
            "video/3gpp",
        ]
        if file.content_type not in allowed_types:
            logger.warning(f"[STATUS_UPLOAD] Invalid file type: {file.content_type}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type {file.content_type} not supported. Allowed types: {', '.join(allowed_types)}",
            )

        # Validate file size (max 16MB for status)
        max_size = 16 * 1024 * 1024  # 16MB
        file_content = await file.read()
        if len(file_content) > max_size:
            logger.warning(f"[STATUS_UPLOAD] File too large: {len(file_content)} bytes")
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File too large. Maximum size is 16MB",
            )

        # Validate video duration for video files (max 3 minutes)
        video_duration = None
        if file.content_type.startswith("video/"):
            logger.info(
                f"[STATUS_UPLOAD] Validating video duration for {file.filename}"
            )
            # Get duration first to include in response
            video_duration = await get_video_duration(file_content, file.filename)

            if video_duration is not None:
                max_seconds = 3 * 60  # 3 minutes
                if video_duration > max_seconds:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Video duration exceeds maximum allowed time of 3 minutes",
                    )
                logger.info(f"[STATUS_UPLOAD] Video duration: {video_duration:.1f}s")
            else:
                logger.warning(
                    f"[STATUS_UPLOAD] Could not determine video duration for {file.filename}"
                )

        # Generate unique file key for status media
        file_extension = os.path.splitext(file.filename)[1] if file.filename else ""
        unique_filename = f"status/{user_id}/{uuid.uuid4()}{file_extension}"

        logger.info(f"[STATUS_UPLOAD] Uploading to S3 as: {unique_filename}")
        print(f"[STATUS_UPLOAD] Starting S3 upload: {unique_filename}")

        # CRITICAL: Upload to S3 and validate success
        try:
            file_key = upload_file_to_s3(
                file_content=file_content,
                file_key=unique_filename,
                content_type=file.content_type,
            )
            logger.info(
                f"[STATUS_UPLOAD] Successfully uploaded to S3, file_key: {file_key}"
            )
            print(f"[STATUS_UPLOAD] S3 upload confirmed, file_key: {file_key}")
        except Exception as e:
            logger.error(f"[STATUS_UPLOAD] S3 upload failed: {str(e)}")
            print(f"[STATUS_UPLOAD] S3 upload failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to upload file to S3: {str(e)}",
            )

        # Return file init response with file_key embedded for later status creation
        return FileInitResponse(
            upload_id=file_key,  # Use file_key as upload_id for transparency
            chunk_size=1024 * 1024,  # 1MB chunks
            total_chunks=1,
            expires_in=86400,  # 24 hours (matches status expiry)
            upload_url=f"{settings.API_BASE_URL}/media/{file_key}",
            duration=video_duration,  # Video duration if applicable
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[STATUS_UPLOAD] Error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload status media: {str(e)}",
        )


@router.get("/", response_model=StatusListResponse)
async def get_all_statuses(
    limit: int = 50, offset: int = 0, current_user: str = Depends(get_current_user)
):
    """
    Get all visible statuses from other users
    Excludes expired statuses and user's own statuses

    CRITICAL: Requires authentication with Bearer token
    Returns: 401 if no token, 403 if invalid token
    """
    print(f"STATUS_DEBUG: get_all_statuses called for user: {current_user}")
    try:
        status_collection = await get_status_collection()
        user_id = str(current_user)  # current_user is already a string (user_id) from get_current_user
        current_time = datetime.now(timezone.utc)

        print(
            f"STATUS_DEBUG: Fetching statuses for user {user_id}, limit={limit}, offset={offset}"
        )

        # Build query for non-expired statuses from other users
        query = {
            "user_id": {"$ne": user_id},  # Exclude own statuses
            "expires_at": {"$gt": current_time},  # Only non-expired
        }

        # Get total count
        total = await status_collection.count_documents(query)

        # Fetch statuses with pagination
        cursor = (
            status_collection.find(query)
            .sort("created_at", -1)
            .skip(offset)
            .limit(limit)
        )
        statuses = []

        async for doc in cursor:
            # Normalize MongoDB ObjectId -> str for Pydantic model
            if isinstance(doc.get("_id"), ObjectId):
                doc["_id"] = str(doc["_id"])
            # Convert to StatusInDB model
            status_doc = StatusInDB(**doc)
            statuses.append(status_to_response(status_doc, user_id))

        # Determine if there are more results
        has_more = (offset + len(statuses)) < total

        print(
            f"STATUS_DEBUG: Returning {len(statuses)} statuses, total={total}, has_more={has_more}"
        )
        return StatusListResponse(statuses=statuses, total=total, has_more=has_more)

    except Exception as e:
        print(f"STATUS_DEBUG: Error in get_all_statuses: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch statuses: {str(e)}",
        )


@router.get("/{user_id}", response_model=StatusListResponse)
async def get_user_statuses(
    user_id: str,
    limit: int = 50,
    offset: int = 0,
    current_user: str = Depends(get_current_user),
):
    """
    Get statuses from a specific user
    Includes both own and other users' statuses
    """
    if not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID format"
        )

    try:
        status_collection = await get_status_collection()
        current_time = datetime.now(timezone.utc)
        requesting_user_id = str(current_user)  # current_user is already a string (user_id) from get_current_user

        # Build query for user's non-expired statuses
        query = {
            "user_id": user_id,
            "expires_at": {"$gt": current_time},  # Only non-expired
        }

        # Get total count
        total = await status_collection.count_documents(query)

        # Fetch statuses with pagination
        cursor = (
            status_collection.find(query)
            .sort("created_at", -1)
            .skip(offset)
            .limit(limit)
        )
        statuses = []
        status_ids_to_increment = []  # Collect IDs that need view increment

        async for doc in cursor:
            # Normalize MongoDB ObjectId -> str for Pydantic model
            if isinstance(doc.get("_id"), ObjectId):
                doc["_id"] = str(doc["_id"])
            # Convert to StatusInDB model
            status_doc = StatusInDB(**doc)
            response = status_to_response(status_doc, requesting_user_id)

            # Collect status IDs for batch update if viewing someone else's status
            if user_id != requesting_user_id:
                status_ids_to_increment.append(ObjectId(status_doc.id))
                response.views += 1  # Pre-increment response view count

            statuses.append(response)

        # Batch update view counts in single DB round-trip
        if status_ids_to_increment:
            await status_collection.update_many(
                {"_id": {"$in": status_ids_to_increment}}, {"$inc": {"views": 1}}
            )

        # Determine if there are more results
        has_more = (offset + len(statuses)) < total

        return StatusListResponse(statuses=statuses, total=total, has_more=has_more)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch user statuses: {str(e)}",
        )


@router.delete("/{status_id}")
async def delete_status(status_id: str, current_user: str = Depends(get_current_user)):
    """
    Delete a status (only own statuses)
    """
    try:
        status_collection = await get_status_collection()
        user_id = str(current_user)  # current_user is already a string (user_id) from get_current_user

        # Validate status_id format
        if not ObjectId.is_valid(status_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status ID format",
            )

        # Find and verify ownership
        status_doc = await status_collection.find_one(
            {"_id": ObjectId(status_id), "user_id": user_id}
        )

        if not status_doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Status not found or you don't have permission to delete it",
            )

        # Delete associated S3 file if file_key exists
        if status_doc.get("file_key"):
            try:
                from backend.utils import s3_utils

                s3_utils.delete_object(settings.S3_BUCKET, status_doc["file_key"])
            except Exception as e:
                # Log but don't fail the deletion if S3 cleanup fails
                import logging

                logger = logging.getLogger(__name__)
                logger.error(
                    f"Failed to delete S3 object {status_doc['file_key']}: {str(e)}"
                )

        # Delete the status from database
        await status_collection.delete_one({"_id": ObjectId(status_id)})

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Status deleted successfully"},
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete status: {str(e)}",
        )
