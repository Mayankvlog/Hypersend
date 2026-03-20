import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.responses import JSONResponse
from bson import ObjectId

from backend.models import (
    StatusCreate, StatusInDB, StatusResponse, StatusListResponse,
    FileInitRequest, FileInitResponse, FileCompleteResponse
)
from backend.auth.utils import get_current_user
from backend.config import settings
from backend.database import get_database
from backend.utils.s3_utils import upload_file_to_s3

# Initialize router
router = APIRouter(prefix="/api/v1/status", tags=["status"])

# Status collection helper
async def get_status_collection():
    """Get status collection from database"""
    db = get_database()
    return db["statuses"]

# Helper function to convert StatusInDB to StatusResponse
def status_to_response(status: StatusInDB, current_user_id: str) -> StatusResponse:
    """Convert database status model to API response with proper URL mapping"""
    file_url = None
    if status.file_key:
        # Generate S3 URL using existing media endpoint pattern
        file_url = f"{settings.API_BASE_URL}/api/v1/media/{status.file_key}"
    
    # Check if status is expired
    is_expired = datetime.now(timezone.utc) > status.expires_at
    
    return StatusResponse(
        id=status.id,
        user_id=status.user_id,
        text=status.text,
        file_url=file_url,
        file_type=status.file_type,
        created_at=status.created_at,
        expires_at=status.expires_at,
        views=status.views,
        is_expired=is_expired
    )

@router.post("/", response_model=StatusResponse)
async def create_status(
    status_data: StatusCreate,
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new status (text or media)
    Reuses existing S3 upload logic
    """
    try:
        status_collection = await get_status_collection()
        user_id = str(current_user["_id"])
        
        # Create status document
        # If file_key is provided, attempt to get metadata for file_type
        file_type = None
        if status_data.file_key:
            # TODO: Implement get_upload_metadata(file_key) to fetch content_type from storage
            # For now, falling back to None until metadata lookup is implemented
            file_type = None
        
        # Validate expiry is in future (service-layer check for creation)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        if expires_at <= datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to set expiry time"
            )
        
        status_doc = StatusInDB(
            user_id=user_id,
            text=status_data.text,
            file_key=status_data.file_key,
            file_type=file_type,
            expires_at=expires_at
        )
        
        # Insert into database
        result = await status_collection.insert_one(status_doc.model_dump(by_alias=True))
        status_doc.id = str(result.inserted_id)
        
        # Convert to response
        response = status_to_response(status_doc, user_id)
        
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=response.model_dump(by_alias=True)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create status: {str(e)}"
        )

@router.post("/upload", response_model=FileInitResponse)
async def upload_status_media(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Upload media for status using existing S3 upload logic
    Stores only file_key, not full S3 URL
    """
    try:
        user_id = str(current_user["_id"])
        
        # Validate file type
        allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/3gpp']
        if file.content_type not in allowed_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type {file.content_type} not supported. Allowed types: {', '.join(allowed_types)}"
            )
        
        # Validate file size (max 16MB for status)
        max_size = 16 * 1024 * 1024  # 16MB
        file_content = await file.read()
        if len(file_content) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File too large. Maximum size is 16MB"
            )
        
        # Generate unique file key for status media
        file_extension = os.path.splitext(file.filename)[1] if file.filename else ''
        unique_filename = f"status/{user_id}/{uuid.uuid4()}{file_extension}"
        
        # Upload to S3 using existing utility
        file_key = upload_file_to_s3(
            file_content=file_content,
            file_key=unique_filename,
            content_type=file.content_type
        )
        
        # Return file init response compatible with existing frontend logic
        return FileInitResponse(
            upload_id=str(uuid.uuid4()),
            chunk_size=1024 * 1024,  # 1MB chunks
            total_chunks=1,
            expires_in=3600,  # 1 hour
            upload_url=f"{settings.API_BASE_URL}/api/v1/media/{file_key}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload status media: {str(e)}"
        )

@router.get("/", response_model=StatusListResponse)
async def get_all_statuses(
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """
    Get all visible statuses from other users
    Excludes expired statuses and user's own statuses
    """
    try:
        status_collection = await get_status_collection()
        user_id = str(current_user["_id"])
        current_time = datetime.now(timezone.utc)
        
        # Build query for non-expired statuses from other users
        query = {
            "user_id": {"$ne": user_id},  # Exclude own statuses
            "expires_at": {"$gt": current_time}  # Only non-expired
        }
        
        # Get total count
        total = await status_collection.count_documents(query)
        
        # Fetch statuses with pagination
        cursor = status_collection.find(query).sort("created_at", -1).skip(offset).limit(limit)
        statuses = []
        
        async for doc in cursor:
            # Convert to StatusInDB model
            status_doc = StatusInDB(**doc)
            statuses.append(status_to_response(status_doc, user_id))
        
        # Determine if there are more results
        has_more = (offset + len(statuses)) < total
        
        return StatusListResponse(
            statuses=statuses,
            total=total,
            has_more=has_more
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch statuses: {str(e)}"
        )

@router.get("/{user_id}", response_model=StatusListResponse)
async def get_user_statuses(
    user_id: str,
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """
    Get statuses from a specific user
    Includes both own and other users' statuses
    """
    try:
        status_collection = await get_status_collection()
        current_time = datetime.now(timezone.utc)
        requesting_user_id = str(current_user["_id"])
        
        # Validate user_id format
        if not ObjectId.is_valid(user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user ID format"
            )
        
        # Build query for user's non-expired statuses
        query = {
            "user_id": user_id,
            "expires_at": {"$gt": current_time}  # Only non-expired
        }
        
        # Get total count
        total = await status_collection.count_documents(query)
        
        # Fetch statuses with pagination
        cursor = status_collection.find(query).sort("created_at", -1).skip(offset).limit(limit)
        statuses = []
        status_ids_to_increment = []  # Collect IDs that need view increment
        
        async for doc in cursor:
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
                {"_id": {"$in": status_ids_to_increment}},
                {"$inc": {"views": 1}}
            )
        
        # Determine if there are more results
        has_more = (offset + len(statuses)) < total
        
        return StatusListResponse(
            statuses=statuses,
            total=total,
            has_more=has_more
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch user statuses: {str(e)}"
        )

@router.delete("/{status_id}")
async def delete_status(
    status_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a status (only own statuses)
    """
    try:
        status_collection = await get_status_collection()
        user_id = str(current_user["_id"])
        
        # Validate status_id format
        if not ObjectId.is_valid(status_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status ID format"
            )
        
        # Find and verify ownership
        status_doc = await status_collection.find_one({
            "_id": ObjectId(status_id),
            "user_id": user_id
        })
        
        if not status_doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Status not found or you don't have permission to delete it"
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
                logger.error(f"Failed to delete S3 object {status_doc['file_key']}: {str(e)}")
        
        # Delete the status from database
        await status_collection.delete_one({"_id": ObjectId(status_id)})
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Status deleted successfully"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete status: {str(e)}"
        )
