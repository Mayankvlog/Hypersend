import hashlib
import uuid
import json
import math
import logging
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import APIRouter, HTTPException, status, Depends, Request, Header
from fastapi.responses import FileResponse, StreamingResponse
from typing import Optional
import aiofiles
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from models import (
    FileInitRequest, FileInitResponse, ChunkUploadResponse, FileCompleteResponse
)
from database import files_collection, uploads_collection, users_collection
from auth.utils import get_current_user
from config import settings

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

router = APIRouter(prefix="/files", tags=["Files"])


@router.post("/init", response_model=FileInitResponse)
async def initialize_upload(
    file_req: FileInitRequest,
    current_user: str = Depends(get_current_user)
):
    """Initialize a resumable file upload"""
    
    # Validate filename and sanitize
    import re
    if not file_req.filename or re.search(r'[<>:"/\\|?*]', file_req.filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename. Please use a valid filename."
        )
    
    # Validate file size
    if file_req.size > settings.MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File size exceeds maximum of {settings.MAX_FILE_SIZE_BYTES} bytes"
        )
    
    # Check user quota (use safe defaults if fields are missing)
    user = await users_collection().find_one({"_id": current_user})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    quota_used = user.get("quota_used", 0)
    quota_limit = user.get("quota_limit", settings.MAX_FILE_SIZE_BYTES)
    if quota_used + file_req.size > quota_limit:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Quota exceeded"
        )
    
    # Calculate chunks
    total_chunks = math.ceil(file_req.size / settings.CHUNK_SIZE)
    upload_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=settings.UPLOAD_EXPIRE_HOURS)
    
    # Create upload record
    upload_doc = {
        "upload_id": upload_id,
        "owner_id": current_user,
        "filename": file_req.filename,
        "size": file_req.size,
        "mime": file_req.mime,
        "chat_id": file_req.chat_id,
        "total_chunks": total_chunks,
        "chunk_size": settings.CHUNK_SIZE,
        "received_chunks": [],
        "checksum": file_req.checksum,
        "expires_at": expires_at,
        "created_at": datetime.utcnow()
    }
    
    await uploads_collection().insert_one(upload_doc)
    
    # Create temp directory for chunks
    upload_dir = settings.DATA_ROOT / "tmp" / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    # Create manifest
    manifest = {
        "upload_id": upload_id,
        "filename": file_req.filename,
        "size": file_req.size,
        "total_chunks": total_chunks,
        "chunk_size": settings.CHUNK_SIZE,
        "received_chunks": []
    }
    
    async with aiofiles.open(upload_dir / "manifest.json", "w") as f:
        await f.write(json.dumps(manifest, indent=2))
    
    return FileInitResponse(
        upload_id=upload_id,
        chunk_size=settings.CHUNK_SIZE,
        total_chunks=total_chunks,
        max_parallel=settings.MAX_PARALLEL_CHUNKS,
        expires_at=expires_at
    )


@router.put("/{upload_id}/chunk", response_model=ChunkUploadResponse)
async def upload_chunk(
    upload_id: str,
    request: Request,
    chunk_index: int,
    x_chunk_checksum: Optional[str] = Header(None),
    current_user: str = Depends(get_current_user)
):
    """Upload a single chunk"""
    
    # Verify upload exists
    upload = await uploads_collection().find_one({"upload_id": upload_id, "owner_id": current_user})
    if not upload:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Upload not found"
        )
    
    # Check if expired
    if upload["expires_at"] < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Upload session expired"
        )
    
    # Validate chunk index
    if chunk_index < 0 or chunk_index >= upload["total_chunks"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid chunk index"
        )
    
    # Read chunk data
    chunk_data = await request.body()
    
    # Verify checksum if provided
    if x_chunk_checksum:
        calculated_checksum = hashlib.sha256(chunk_data).hexdigest()
        if calculated_checksum != x_chunk_checksum:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Chunk checksum mismatch"
            )
    
    # Save chunk to disk
    upload_dir = settings.DATA_ROOT / "tmp" / upload_id
    chunk_path = upload_dir / f"{chunk_index}.part"
    
    async with aiofiles.open(chunk_path, "wb") as f:
        await f.write(chunk_data)
    
    # Update database
    if chunk_index not in upload["received_chunks"]:
        await uploads_collection().update_one(
            {"upload_id": upload_id},
            {"$push": {"received_chunks": chunk_index}}
        )
    
    # Update manifest
    manifest_path = upload_dir / "manifest.json"
    async with aiofiles.open(manifest_path, "r") as f:
        manifest = json.loads(await f.read())
    
    if chunk_index not in manifest["received_chunks"]:
        manifest["received_chunks"].append(chunk_index)
        manifest["received_chunks"].sort()
    
    async with aiofiles.open(manifest_path, "w") as f:
        await f.write(json.dumps(manifest, indent=2))
    
    return ChunkUploadResponse(upload_id=upload_id, chunk_index=chunk_index)


@router.post("/{upload_id}/complete", response_model=FileCompleteResponse)
async def complete_upload(upload_id: str, current_user: str = Depends(get_current_user)):
    """Complete upload and assemble file"""
    
    # Verify upload
    upload = await uploads_collection().find_one({"upload_id": upload_id, "owner_id": current_user})
    if not upload:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Upload not found"
        )
    
    # Check all chunks received
    if len(upload["received_chunks"]) != upload["total_chunks"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing chunks: {len(upload['received_chunks'])}/{upload['total_chunks']}"
        )
    
    # Assemble file
    file_uuid = str(uuid.uuid4())
    file_ext = Path(upload["filename"]).suffix
    final_path = settings.DATA_ROOT / "files" / f"{file_uuid}{file_ext}"
    upload_dir = settings.DATA_ROOT / "tmp" / upload_id
    
    # Stream-concatenate chunks
    hasher = hashlib.sha256()
    async with aiofiles.open(final_path, "wb") as outfile:
        for i in sorted(upload["received_chunks"]):
            chunk_path = upload_dir / f"{i}.part"
            async with aiofiles.open(chunk_path, "rb") as infile:
                chunk_data = await infile.read()
                hasher.update(chunk_data)
                await outfile.write(chunk_data)
    
    final_checksum = hasher.hexdigest()
    
    # Verify checksum if provided during init
    if upload.get("checksum") and upload["checksum"] != final_checksum:
        # Delete assembled file
        final_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File checksum mismatch"
        )
    
    # Create file record
    file_doc = {
        "_id": str(uuid.uuid4()),
        "upload_id": upload_id,
        "file_uuid": file_uuid,
        "filename": upload["filename"],
        "size": upload["size"],
        "mime": upload["mime"],
        "owner_id": current_user,
        "chat_id": upload["chat_id"],
        "storage_path": str(final_path),
        "checksum": final_checksum,
        "status": "completed",
        "created_at": datetime.utcnow()
    }
    
    await files_collection().insert_one(file_doc)
    
    # Update user quota
    await users_collection().update_one(
        {"_id": current_user},
        {"$inc": {"quota_used": upload["size"]}}
    )
    
    # Cleanup chunks
    for chunk_file in upload_dir.glob("*.part"):
        chunk_file.unlink()
    (upload_dir / "manifest.json").unlink(missing_ok=True)
    upload_dir.rmdir()
    
    # Delete upload record
    await uploads_collection().delete_one({"upload_id": upload_id})
    
    return FileCompleteResponse(
        file_id=file_doc["_id"],
        filename=file_doc["filename"],
        size=file_doc["size"],
        checksum=final_checksum,
        storage_path=str(final_path)
    )


@router.get("/{file_id}/download")
async def download_file(
    file_id: str,
    request: Request,
    current_user: str = Depends(get_current_user)
):
    """Download file with range support"""
    
    # Find file
    file_doc = await files_collection().find_one({"_id": file_id})
    if not file_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    file_path = Path(file_doc["storage_path"])
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found on disk"
        )
    
    # Handle range requests
    range_header = request.headers.get("range")
    file_size = file_path.stat().st_size
    
    if range_header:
        # Parse range header
        range_match = range_header.replace("bytes=", "").split("-")
        start = int(range_match[0]) if range_match[0] else 0
        end = int(range_match[1]) if range_match[1] else file_size - 1
        
        async def file_iterator():
            async with aiofiles.open(file_path, "rb") as f:
                await f.seek(start)
                remaining = end - start + 1
                chunk_size = 1024 * 1024  # 1MB chunks
                while remaining > 0:
                    read_size = min(chunk_size, remaining)
                    data = await f.read(read_size)
                    if not data:
                        break
                    remaining -= len(data)
                    yield data
        
        return StreamingResponse(
            file_iterator(),
            status_code=206,
            headers={
                "Content-Range": f"bytes {start}-{end}/{file_size}",
                "Content-Length": str(end - start + 1),
                "Content-Type": file_doc["mime"],
                "Accept-Ranges": "bytes"
            }
        )
    
    # Full file download
    return FileResponse(
        file_path,
        media_type=file_doc["mime"],
        filename=file_doc["filename"]
    )


@router.post("/{upload_id}/cancel")
async def cancel_upload(upload_id: str, current_user: str = Depends(get_current_user)):
    """Cancel upload and cleanup"""
    
    upload = await uploads_collection().find_one({"upload_id": upload_id, "owner_id": current_user})
    if not upload:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Upload not found"
        )
    
    # Cleanup chunks
    upload_dir = settings.DATA_ROOT / "tmp" / upload_id
    if upload_dir.exists():
        for chunk_file in upload_dir.glob("*.part"):
            chunk_file.unlink()
        (upload_dir / "manifest.json").unlink(missing_ok=True)
        upload_dir.rmdir()
    
    # Delete upload record
    await uploads_collection().delete_one({"upload_id": upload_id})
    
    return {"message": "Upload cancelled"}
