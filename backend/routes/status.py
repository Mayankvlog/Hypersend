import os
import uuid
import logging
import asyncio
import tempfile
import subprocess
import json
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
router = APIRouter(prefix="/status", tags=["status"])

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
def status_to_response(status: StatusInDB, current_user_id: str, presigned_url: Optional[str] = None) -> StatusResponse:
    """Convert database status model to API response with seen/unseen tracking and viewer list"""
    file_url = presigned_url
    if file_url is None and status.file_key:
        # Generate media endpoint URL (will be converted to presigned URL during download)
        file_url = f"{settings.API_BASE_URL}/media/{status.file_key}"

    # Check if status is expired
    is_expired = datetime.now(timezone.utc) > status.expires_at
    
    # Compute is_seen: check if current_user_id is in views array
    is_seen = current_user_id in status.views
    view_count = len(status.views)
    
    # Only owner sees full viewers list, others see count only
    viewers_list = status.views if status.user_id == current_user_id else None

    return StatusResponse(
        id=status.id,
        user_id=status.user_id,
        text=status.text,
        file_url=file_url,
        file_type=status.file_type,
        duration=status.duration,
        created_at=status.created_at,
        expires_at=status.expires_at,
        is_seen=is_seen,
        view_count=view_count,
        views=viewers_list,
        is_expired=is_expired,
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
            
            # CRITICAL: Verify s3_key is not empty before saving to DB
            if not file_key or not file_key.strip():
                logger.error(f"[STATUS_UPLOAD] CRITICAL: S3 upload returned empty file_key!")
                raise ValueError("S3 upload returned empty file_key")
            
            logger.info(
                f"[STATUS_UPLOAD] Successfully uploaded to S3, s3_key: {file_key} (size: {len(file_content)} bytes)"
            )
            print(f"[STATUS_UPLOAD] S3 UPLOAD SUCCESS: {file_key}")
        except Exception as e:
            logger.error(f"[STATUS_UPLOAD] S3 upload failed: {str(e)}")
            print(f"[STATUS_UPLOAD] S3 upload failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to upload file to S3: {str(e)}",
            )

        # CRITICAL: Log the s3_key that will be stored in database
        logger.info(
            f"[STATUS_UPLOAD] DATABASE_INSERT - s3_key={file_key}, file_type={os.path.splitext(file_key)[1]}, user_id={user_id}"
        )
        
        # Return file init response with file_key embedded for later status creation
        response_data = FileInitResponse(
            uploadId=file_key,  # Use file_key as uploadId for transparency
            file_key=file_key,  # Also set file_key for backward compatibility
            chunk_size=1024 * 1024,  # 1MB chunks
            total_chunks=1,
            expires_in=86400,  # 24 hours (matches status expiry)
            max_parallel=4,  # Default max parallel chunks
            upload_url=f"{settings.API_BASE_URL}/media/{file_key}",
            duration=video_duration,  # Video duration if applicable
        )
        
        # Debug log for response payload
        response_dict = response_data.model_dump(by_alias=True)
        logger.info(f"[STATUS_UPLOAD] Response payload: {response_dict}")
        logger.info(f"[STATUS_UPLOAD] FILE_KEY_IN_RESPONSE: {file_key} (uploadId={response_dict.get('uploadId')}, file_key={response_dict.get('file_key')})")
        logger.info(f"[STATUS_UPLOAD] RESPONSE_SCHEMA: uploadId={type(response_dict.get('uploadId')).__name__}, file_key={type(response_dict.get('file_key')).__name__}, duration={response_dict.get('duration')}")
        
        # CRITICAL: Print for production debugging
        print(f"[STATUS_UPLOAD] RESPONSE_READY: uploadId={file_key}, file_key={file_key}, duration={video_duration}")
        print(f"[STATUS_UPLOAD] JSON_RESPONSE: {json.dumps(response_dict)}")
        
        return response_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[STATUS_UPLOAD] Error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload status media: {str(e)}",
        )


@router.post("/", response_model=StatusResponse)
async def create_status(
    status_create: StatusCreate, current_user: str = Depends(get_current_user)
):
    """
    Create a new status with text and/or media.
    
    CRITICAL: Either text or file_key must be provided
    file_key must be from a previous upload_status_media call
    
    Flow:
    1. User uploads media via POST /upload → gets file_key
    2. User creates status with file_key via this endpoint
    
    Returns: 200 with created status, 400 if validation fails, 500 if DB error
    """
    try:
        user_id = str(current_user)
        logger.info(f"[STATUS_CREATE] User {user_id} creating status")
        print(f"[STATUS_CREATE] Creating status for user: {user_id}")
        
        # Validate that either text or file_key is provided
        if not status_create.text and not status_create.file_key:
            logger.warning(f"[STATUS_CREATE] Validation error - no text or file_key")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either text or file_key must be provided"
            )
        
        # If file_key is provided, verify it exists in S3
        if status_create.file_key:
            logger.info(f"[STATUS_CREATE] Validating file_key exists: {status_create.file_key}")
            try:
                from backend.routes.files import _get_s3_client
                s3_client = _get_s3_client()
                if s3_client:
                    try:
                        s3_client.head_object(
                            Bucket=settings.S3_BUCKET,
                            Key=status_create.file_key
                        )
                        logger.info(f"[STATUS_CREATE] Verified file_key exists in S3: {status_create.file_key}")
                        print(f"[STATUS_CREATE] S3 KEY VALIDATED: {status_create.file_key}")
                    except Exception as e:
                        logger.warning(f"[STATUS_CREATE] file_key not found in S3: {status_create.file_key}")
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"File not found or upload incomplete. Try uploading again."
                        )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[STATUS_CREATE] Error validating file_key: {str(e)}")
                # Don't fail if S3 validation fails - might be permission issue
        
        # Create status document
        status_collection = await get_status_collection()
        
        # Determine file_type from file_key if provided
        file_type = None
        if status_create.file_key:
            # Extract MIME type from file extension
            ext = os.path.splitext(status_create.file_key)[1].lower()
            file_type_map = {
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.gif': 'image/gif',
                '.webp': 'image/webp',
                '.mp4': 'video/mp4',
                '.3gp': 'video/3gpp',
            }
            file_type = file_type_map.get(ext)
        
        # Create status document with views initialized as empty array
        status_doc = StatusInDB(
            user_id=user_id,
            text=status_create.text,
            file_key=status_create.file_key,
            file_type=file_type,
            duration=status_create.duration,
            storage_type="s3",
            views=[],  # Initialize empty views array for tracking viewers
        )
        
        # Convert to dict for MongoDB insertion
        status_dict = status_doc.model_dump(by_alias=True)
        
        logger.info(f"[STATUS_CREATE] Inserting status to DB: user={user_id}, has_file={bool(status_create.file_key)}")
        print(f"[STATUS_CREATE] DB INSERT: user={user_id}, file_key={status_create.file_key}, views_initialized=[]")
        
        # Insert into database
        result = await status_collection.insert_one(status_dict)
        
        logger.info(f"[STATUS_CREATE] Status created successfully with ID: {result.inserted_id}")
        print(f"[STATUS_CREATE] Status inserted with ID: {result.inserted_id}")
        
        # Refresh document from DB to ensure all fields are correct
        inserted_doc = await status_collection.find_one({"_id": ObjectId(result.inserted_id)})
        if inserted_doc:
            if isinstance(inserted_doc.get("_id"), ObjectId):
                inserted_doc["_id"] = str(inserted_doc["_id"])
            status_doc = StatusInDB(**inserted_doc)
        else:
            status_doc.id = str(result.inserted_id)
        
        # Return as StatusResponse
        response = status_to_response(status_doc, user_id)
        
        logger.info(f"[STATUS_CREATE] STATUS SAVED SUCCESS: id={response.id}, user={user_id}, views={len(status_doc.views)}")
        print(f"[STATUS_CREATE] STATUS SAVED SUCCESS: {response.model_dump()}")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[STATUS_CREATE] Error creating status: {type(e).__name__}: {str(e)}")
        print(f"[STATUS_CREATE] ERROR: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create status: {str(e)}",
        )


@router.get("/", response_model=StatusListResponse)
async def get_all_statuses(
    limit: int = 50, offset: int = 0, current_user: str = Depends(get_current_user)
):
    """
    Get all visible statuses from other users grouped by user_id
    - Filters only active statuses (expires_at > now)
    - Sorts unseen statuses first, then seen
    - Deletes expired statuses before fetching
    - Groups by user_id with latest first per group
    - Excludes own statuses

    CRITICAL: Requires authentication with Bearer token
    Returns: 401 if no token, 403 if invalid token
    """
    print(f"[STATUS_GET] get_all_statuses called for user: {current_user}")
    try:
        status_collection = await get_status_collection()
        user_id = str(current_user)
        current_time = datetime.now(timezone.utc)

        print(f"[STATUS_GET] Deleting expired statuses")
        
        # STEP 1: Delete expired statuses safely
        try:
            expired_result = await status_collection.delete_many(
                {"expires_at": {"$lte": current_time}}
            )
            logger.info(f"[STATUS_GET] Deleted {expired_result.deleted_count} expired statuses")
            print(f"[STATUS_GET] Deleted {expired_result.deleted_count} expired statuses")
        except Exception as e:
            logger.warning(f"[STATUS_GET] Warning: Failed to delete expired statuses: {str(e)}")
            print(f"[STATUS_GET] Warning: Failed to delete expired statuses: {str(e)}")
            # Continue - don't break flow

        print(f"[STATUS_GET] Fetching active statuses for user {user_id}, limit={limit}, offset={offset}")

        # STEP 2: Query active, non-own statuses
        query = {
            "user_id": {"$ne": user_id},  # Exclude own statuses
            "expires_at": {"$gt": current_time},  # Only non-expired
        }

        # Get total count
        total = await status_collection.count_documents(query)

        # STEP 3: Fetch all statuses (we'll sort in-memory for reels-like ordering)
        cursor = status_collection.find(query).sort("created_at", -1)
        all_statuses = []

        async for doc in cursor:
            if isinstance(doc.get("_id"), ObjectId):
                doc["_id"] = str(doc["_id"])
            try:
                status_doc = StatusInDB(**doc)
                all_statuses.append(status_doc)
            except Exception as e:
                logger.warning(f"[STATUS_GET] Skipping invalid status doc: {str(e)}")
                continue

        # STEP 4: Group by user_id and compute is_seen status
        grouped_by_user = {}
        for status_doc in all_statuses:
            user = status_doc.user_id
            if user not in grouped_by_user:
                grouped_by_user[user] = []
            is_seen = user_id in status_doc.views
            grouped_by_user[user].append({
                "status": status_doc,
                "is_seen": is_seen,
            })

        # STEP 5: Sort groups - unseen statuses first, then seen
        all_status_responses = []
        
        # First add unseen statuses from all users
        for user, status_list in grouped_by_user.items():
            for status_item in status_list:
                if not status_item["is_seen"]:
                    all_status_responses.append(status_to_response(status_item["status"], user_id))

        # Then add seen statuses
        for user, status_list in grouped_by_user.items():
            for status_item in status_list:
                if status_item["is_seen"]:
                    all_status_responses.append(status_to_response(status_item["status"], user_id))

        # STEP 6: Apply pagination on sorted results
        paginated_statuses = all_status_responses[offset:offset + limit]

        # Determine if there are more results
        has_more = (offset + len(paginated_statuses)) < len(all_status_responses)

        logger.info(f"[STATUS_GET] Returning {len(paginated_statuses)} statuses, total_active={len(all_status_responses)}, has_more={has_more}")
        print(f"[STATUS_GET] Returning {len(paginated_statuses)} statuses, total={total}, has_more={has_more}")
        
        return StatusListResponse(
            statuses=paginated_statuses, 
            total=len(all_status_responses), 
            has_more=has_more
        )

    except Exception as e:
        logger.error(f"[STATUS_GET] Error in get_all_statuses: {type(e).__name__}: {str(e)}")
        print(f"[STATUS_GET] Error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch statuses: {str(e)}",
        )


@router.post("/{status_id}/view", response_model=StatusResponse)
async def mark_status_as_seen(
    status_id: str, current_user: str = Depends(get_current_user)
):
    """
    Mark a status as seen by current user
    Appends current_user.id to views array (prevents duplicates)
    """
    try:
        user_id = str(current_user)
        logger.info(f"[STATUS_MARK_SEEN] User {user_id} marking status {status_id} as seen")
        print(f"[STATUS_MARK_SEEN] Marking status {status_id} as seen by user {user_id}")
        
        # Validate status_id format
        if not ObjectId.is_valid(status_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status ID format",
            )

        status_collection = await get_status_collection()
        
        # Find status
        status_doc = await status_collection.find_one(
            {"_id": ObjectId(status_id)}
        )
        
        if not status_doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Status not found",
            )
        
        # Check if already seen (prevent duplicate user_ids)
        if "views" not in status_doc:
            status_doc["views"] = []
        
        if user_id not in status_doc["views"]:
            # Append user_id to views array
            result = await status_collection.update_one(
                {"_id": ObjectId(status_id)},
                {"$addToSet": {"views": user_id}}  # $addToSet prevents duplicates
            )
            logger.info(f"[STATUS_MARK_SEEN] User {user_id} added to viewers, matched={result.matched_count}, modified={result.modified_count}")
            print(f"[STATUS_MARK_SEEN] Updated views for status {status_id}")
        else:
            logger.info(f"[STATUS_MARK_SEEN] User {user_id} already in viewers")
            print(f"[STATUS_MARK_SEEN] User already marked as seen")
        
        # Fetch updated document
        updated_doc = await status_collection.find_one(
            {"_id": ObjectId(status_id)}
        )
        
        if isinstance(updated_doc.get("_id"), ObjectId):
            updated_doc["_id"] = str(updated_doc["_id"])
        
        status_model = StatusInDB(**updated_doc)
        response = status_to_response(status_model, user_id)
        
        logger.info(f"[STATUS_MARK_SEEN] SUCCESS: Status {status_id} view_count={response.view_count}")
        print(f"[STATUS_MARK_SEEN] SUCCESS: view_count={response.view_count}")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[STATUS_MARK_SEEN] Error: {type(e).__name__}: {str(e)}")
        print(f"[STATUS_MARK_SEEN] ERROR: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to mark status as seen: {str(e)}",
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
        status_ids_to_mark_seen = []  # Collect IDs to mark as seen

        async for doc in cursor:
            # Normalize MongoDB ObjectId -> str for Pydantic model
            if isinstance(doc.get("_id"), ObjectId):
                doc["_id"] = str(doc["_id"])
            # Convert to StatusInDB model
            status_doc = StatusInDB(**doc)
            response = status_to_response(status_doc, requesting_user_id)

            # Mark status as seen if viewing someone else's status
            if user_id != requesting_user_id and requesting_user_id not in status_doc.views:
                status_ids_to_mark_seen.append(ObjectId(status_doc.id))

            statuses.append(response)

        # Batch mark statuses as seen in single DB round-trip (add current user to views)
        if status_ids_to_mark_seen:
            await status_collection.update_many(
                {"_id": {"$in": status_ids_to_mark_seen}}, 
                {"$addToSet": {"views": requesting_user_id}}  # $addToSet prevents duplicates
            )
            logger.info(f"[STATUS_USER] Marked {len(status_ids_to_mark_seen)} statuses as seen for user {requesting_user_id}")

        # Re-fetch statuses to get updated view counts
        updated_statuses = []
        for status_obj in statuses:
            doc = await status_collection.find_one({"_id": ObjectId(status_obj.id)})
            if doc:
                if isinstance(doc.get("_id"), ObjectId):
                    doc["_id"] = str(doc["_id"])
                status_doc = StatusInDB(**doc)
                updated_statuses.append(status_to_response(status_doc, requesting_user_id))
            else:
                updated_statuses.append(status_obj)
        
        statuses = updated_statuses

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
