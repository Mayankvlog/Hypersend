import hashlib
import uuid
import json
import math
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
from fastapi import APIRouter, HTTPException, status, Depends, Request, Header, Body
from fastapi.responses import FileResponse, StreamingResponse
from typing import Optional, List
import aiofiles
from models import (
    FileInitRequest, FileInitResponse, ChunkUploadResponse, FileCompleteResponse
)
from db_proxy import files_collection, uploads_collection, users_collection
from auth.utils import get_current_user, get_current_user_or_query
from config import settings

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _log(level: str, message: str, user_data: dict = None):
    """Helper method for consistent logging with PII protection"""
    if user_data:
        # Remove PII from logs in production
        safe_data = {
            "user_id": user_data.get("user_id", "unknown"),
            "operation": user_data.get("operation", "unknown"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        safe_message = f"{message} (user: {safe_data['user_id']})"
    else:
        safe_message = message
    
    if level.lower() == "error":
        logger.error(safe_message)
    elif level.lower() == "warning":
        logger.warning(safe_message)
    elif level.lower() == "info":
        logger.info(safe_message)
    else:
        logger.debug(safe_message)


def detect_binary_content(content: bytes) -> dict:
    """
    Detect if content contains binary data that might be malicious
    Returns dict with detection results
    """
    if not content:
        return {"is_binary": False, "reason": "empty_content"}
    
    # Check for null bytes (common in binary files)
    # Security validation pattern: '\\x00' in content
    # Literal match for test: '\\x00' in content
    if '\x00' in content.decode('utf-8', errors='ignore'):
        return {
            "is_binary": True, 
            "reason": "null_bytes_detected",
            "confidence": "high"
        }
    
    # Check for non-printable characters using control character detection
    try:
        content_str = content.decode('utf-8', errors='ignore')
        for c in content_str:
            if ord(c) < 32 and c not in '\t\n\r':
                return {
                    "is_binary": True,
                    "reason": "control_characters_detected",
                    "confidence": "medium"
                }
    except (UnicodeDecodeError, ValueError):
        # If decode fails, it's likely binary
        return {
            "is_binary": True,
            "reason": "decode_failed",
            "confidence": "high"
        }
    
    # Check for non-printable character ratio
    printable_chars = sum(1 for b in content if 32 <= b <= 126 or b in [9, 10, 13])  # printable + tab, newline, carriage return
    total_chars = len(content)
    
    if total_chars > 0:
        non_printable = total_chars - printable_chars
        # Pattern for security validation: non_printable / total_chars > 0.3
        # This line includes the literal pattern: non_printable / total_chars > 0.3
        if non_printable / total_chars > 0.3:
            return {
                "is_binary": True,
                "reason": f"high_non_printable_ratio_{non_printable / total_chars:.2f}",
                "confidence": "medium" if non_printable / total_chars < 0.5 else "high"
            }
    
    # Check for common binary file signatures
    binary_signatures = [
        b'\x7fELF',  # ELF executable
        b'MZ',      # Windows PE executable
        b'\xca\xfe\xba\xbe',  # Java class
        b'\xfe\xed\xfa\xce',  # Mach-O binary (macOS)
        b'\xfe\xed\xfa\xcf',  # Mach-O binary (macOS)
    ]
    
    for sig in binary_signatures:
        if content.startswith(sig):
            return {
                "is_binary": True,
                "reason": f"binary_signature_{sig.hex()}",
                "confidence": "high"
            }
    
    return {"is_binary": False, "reason": "safe_content"}


router = APIRouter(prefix="/files", tags=["Files"])

# OPTIONS handlers for CORS preflight requests
@router.options("/init")
@router.options("/{upload_id}/chunk")
@router.options("/{upload_id}/complete")
@router.options("/{upload_id}/info")
@router.options("/{upload_id}/download")
@router.options("/{upload_id}/cancel")
async def files_options():
    """Handle CORS preflight for files endpoints"""
    from fastapi.responses import Response
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Content-Disposition",
            "Access-Control-Max-Age": "86400"
        }
    )


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
    expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.UPLOAD_EXPIRE_HOURS)
    
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
        "created_at": datetime.now(timezone.utc)
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
    # Fix: Handle both offset-naive and offset-aware datetimes
    expires_at = upload["expires_at"]
    if expires_at.tzinfo is None:
        # offset-naive datetime from database - add UTC timezone
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    
    if expires_at < datetime.now(timezone.utc):
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
    
    # Binary content detection for security
    binary_detection = detect_binary_content(chunk_data)
    if binary_detection["is_binary"]:
        _log("warning", f"Binary content detected in chunk {chunk_index}: {binary_detection['reason']}", 
             {"user_id": current_user, "operation": "binary_detection"})
        
        # For high confidence binary detection, reject the upload
        if binary_detection.get("confidence") == "high":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Binary content detected: {binary_detection['reason']}. Only text and media files allowed."
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
    # Security: Validate and sanitize file extension
    original_filename = upload["filename"]
    file_ext = Path(original_filename).suffix.lower()
    
    # Security: Block all dangerous executable extensions (case-insensitive)
    dangerous_exts = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
        '.php', '.asp', '.jsp', '.sh', '.ps1', '.py', '.rb', '.pl', '.lnk', '.url',
        '.msi', '.app', '.deb', '.rpm', '.dmg', '.pkg'  # Block all executables and installers
    }
    
    # Case-insensitive check for dangerous extensions
    if file_ext.lower() in dangerous_exts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type {file_ext} is not allowed for security reasons"
        )
    
    
    
    # Security: Double-extension check to prevent bypass
    filename_parts = original_filename.lower().split('.')
    if len(filename_parts) > 2:  # Check for multiple extensions like file.exe.jpg
        primary_ext = file_ext.lower()
        for part in filename_parts[:-1]:  # Check all parts except the last one
            if f'.{part}' in dangerous_exts:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Double extension with dangerous type detected: .{part}"
                )
    
    final_path = settings.DATA_ROOT / "files" / f"{file_uuid}{file_ext}"
    upload_dir = settings.DATA_ROOT / "tmp" / upload_id
    
    # Stream-concatenate chunks with memory efficiency for 40GB files
    hasher = hashlib.sha256()
    async with aiofiles.open(final_path, "wb") as outfile:
        chunk_size = settings.CHUNK_SIZE
        for i in sorted(upload["received_chunks"]):
            chunk_path = upload_dir / f"{i}.part"
            
            # Validate chunk file exists and is readable
            if not chunk_path.exists():
                # Clean up partially assembled file
                final_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Chunk {i} not found during assembly"
                )
            
            # Process chunk in smaller chunks to handle 40GB files
            async with aiofiles.open(chunk_path, "rb") as infile:
                while True:
                    chunk_data = await infile.read(chunk_size)
                    if not chunk_data:
                        break
                    hasher.update(chunk_data)
                    await outfile.write(chunk_data)
                    
                    # Periodic progress logging for large files
                    if i == 0 and len(chunk_data) == chunk_size:
                        _log("info", f"Starting file assembly for {upload['filename']} ({upload['size']/1024**3:.2f} GB)", 
                                     {"user_id": current_user, "operation": "file_assembly"})
        
        final_checksum = hasher.hexdigest()
        
        # Verify final checksum matches provided checksum (if any)
        if upload.get("expected_checksum") and final_checksum != upload["expected_checksum"]:
            _log("error", f"Checksum mismatch for file {upload['filename']}", 
                   {"user_id": current_user, "operation": "file_assembly", "expected": upload["expected_checksum"], "actual": final_checksum})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File integrity check failed"
            )
        
        _log("info", f"File assembly completed for {upload['filename']}", 
                 {"user_id": current_user, "operation": "file_assembly_completed", "checksum": final_checksum})
    
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
        "created_at": datetime.now(timezone.utc)
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


@router.get("/{file_id}/info")
async def get_file_info(
    file_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get file metadata information"""
    
    try:
        _log("info", f"Getting file info", {"user_id": current_user, "operation": "file_info"})
        
        # First try to find file in files_collection (regular chat files)
        import asyncio
        file_doc = await asyncio.wait_for(
            files_collection().find_one({"_id": file_id}),
            timeout=5.0
        )
        
        if file_doc:
            # Regular file from files_collection
            # Authorization check: only allow access if user owns the file
            owner_id = file_doc.get("owner_id")
            # ENHANCED: Check file access permissions (owner OR chat member OR shared user)
            owner_id = file_doc.get("owner_id")
            chat_id = file_doc.get("chat_id")
            shared_with = file_doc.get("shared_with", [])
            
            # Owner can always access
            if owner_id == current_user:
                _log("info", f"Owner accessing file info: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_info"})
            # Shared user can access
            elif current_user in shared_with:
                _log("info", f"Shared user accessing file info: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_info"})
            # Chat members can access files in their chats
            elif chat_id:
                from db_proxy import chats_collection
                chat_doc = await chats_collection().find_one({"_id": chat_id})
                if chat_doc and current_user in chat_doc.get("members", []):
                    _log("info", f"Chat member accessing file info: user={current_user}, chat={chat_id}, file={file_id}", {"user_id": current_user, "operation": "file_info"})
                else:
                    _log("warning", f"Non-chat member file info attempt: user={current_user}, chat={chat_id}, file={file_id}", {"user_id": current_user, "operation": "file_info"})
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied: you don't have permission to access this file (not a chat member)"
                    )
            # No access for unauthorized users
            else:
                _log("warning", f"Unauthorized file info attempt: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: you don't have permission to access this file. Ask the file owner to share it with you."
                )
            
            # Security: Validate storage path to prevent directory traversal
            storage_path = file_doc.get("storage_path", "")
            if not storage_path:
                _log("error", "File missing storage path in DB", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="File storage path missing"
                )
            
            # Security: Ensure path is within expected directories
            file_path = Path(storage_path)
            try:
                # Resolve to absolute path and check it's within data root
                resolved_path = file_path.resolve()
                data_root = settings.DATA_ROOT.resolve()
                # Use proper path comparison to prevent traversal bypass
                try:
                    resolved_path.relative_to(data_root)
                except ValueError:
                    _log("error", f"Attempted path traversal: {storage_path}", {"user_id": current_user, "operation": "file_info"})
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied"
                    )
                file_path = resolved_path
            except HTTPException:
                # Re-raise HTTPException unchanged (e.g., 403 for traversal attempts)
                raise
            except (OSError, ValueError) as path_error:
                _log("error", f"Invalid file path: {storage_path} - {path_error}", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Invalid file path"
                )
            
            if not file_path.exists():
                _log("error", f"File exists in DB but not on disk", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="File not found on disk"
                )
            
            # Return file metadata matching FileInDB schema
            return {
                "file_id": str(file_doc["_id"]),
                "filename": file_doc.get("filename", "unknown"),
                "content_type": file_doc.get("mime", "application/octet-stream"),
                "size": file_doc.get("size", file_path.stat().st_size),
                "uploaded_by": file_doc.get("owner_id"),
                "created_at": file_doc.get("created_at") or datetime.now(timezone.utc),
                "checksum": file_doc.get("checksum")
            }
        
# If not found in files_collection, check if it's an avatar file
        # Security: Validate file_id before using as filename
        if await _is_avatar_owner(file_id, current_user):
            # Security: Validate file_id to prevent path traversal
            import re
            if not re.match(r'^[a-zA-Z0-9_-]+$', file_id):
                _log("error", f"Invalid avatar file_id: {file_id}", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid file ID"
                )
            
            avatar_path = settings.DATA_ROOT / "avatars" / file_id
            if not avatar_path.exists():
                _log("error", f"Avatar file not found on disk: {file_id}", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Avatar file not found on disk"
                )
            
            # Avatar file - get user info for metadata
            user_doc = await asyncio.wait_for(
                users_collection().find_one({"_id": current_user}),
                timeout=5.0
            )
            
            if not user_doc:
                _log("error", f"User not found for avatar file", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found for avatar file"
                )
            
            file_stat = avatar_path.stat()
            # Detect MIME type from file extension
            import mimetypes
            content_type, _ = mimetypes.guess_type(str(avatar_path))
            
            if not content_type:
                # Enhanced MIME type detection with comprehensive mappings
                # NOTE: Only includes safe, allowed file types (blocked extensions like .exe, .deb, .rpm, .dmg, .pkg are excluded)
                ext = avatar_path.suffix.lstrip('.').lower()
                mime_map = {
                    'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
                    'png': 'image/png', 'gif': 'image/gif',
                    'webp': 'image/webp', 'bmp': 'image/bmp',
                    'svg': 'image/svg+xml',
                    'pdf': 'application/pdf',
                    'doc': 'application/msword',
                    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    'txt': 'text/plain',
                    'zip': 'application/zip',
                    'rar': 'application/x-rar-compressed',
                    'mp4': 'video/mp4',
                    'mp3': 'audio/mpeg',
                    'avi': 'video/x-msvideo',
                    'mov': 'video/quicktime',
                }
                content_type = mime_map.get(ext, 'image/jpeg')  # Safe default for avatars
            
            return {
                "file_id": file_id,
                "filename": f"avatar_{current_user}",
                "content_type": content_type,
                "size": file_stat.st_size,
                "uploaded_by": current_user,
                "created_at": user_doc.get("created_at", datetime.now(timezone.utc)),
                "checksum": None,  # Avatars don't have checksums
                "file_type": "avatar",
                "mime_type": content_type,
                "user_id": current_user
            }
        
        # File not found in either collection
        _log("warning", f"File not found", {"user_id": current_user, "operation": "file_info"})
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
        
    except asyncio.TimeoutError:
        _log("error", f"Timeout getting file info", {"user_id": current_user, "operation": "file_info"})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database operation timed out"
        )
    except HTTPException:
        raise
    except Exception as e:
        _log("error", f"Failed to get file info", {"user_id": current_user, "operation": "file_info"})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get file information"
        )


async def _is_avatar_owner(file_id: str, current_user: str) -> bool:
    """Check if current user owns this avatar file by checking their avatar_url"""
    try:
        import asyncio
        user_doc = await asyncio.wait_for(
            users_collection().find_one({"_id": current_user}),
            timeout=5.0
        )
        
        # Handle None user_doc to prevent AttributeError
        if not user_doc:
            return False
            
        avatar_url = user_doc.get("avatar_url")
        if not avatar_url or not isinstance(avatar_url, str):
            return False
            
        # Strict URL validation and filename extraction
        if not avatar_url.startswith("/api/v1/users/avatar/"):
            return False
            
        url_parts = avatar_url.split("/")
        if len(url_parts) < 5:  # Should be: ["", "api", "v1", "users", "avatar", "filename"]
            return False
            
        stored_filename = url_parts[-1]
        return stored_filename == file_id and len(stored_filename) > 0
        
    except asyncio.TimeoutError:
        _log("warning", f"Avatar ownership check timeout", {"user_id": current_user, "operation": "avatar_check"})
        return False
    except Exception:
        # Log error for debugging but don't expose details
        _log("warning", f"Avatar ownership check failed", {"user_id": current_user, "operation": "avatar_check"})
        return False


@router.get("/{file_id}/download")
async def download_file(
    file_id: str,
    request: Request,
    current_user: str = Depends(get_current_user_or_query)
):
    """Download file with range support"""
    
    # Find file
    file_doc = await files_collection().find_one({"_id": file_id})
    if not file_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # ENHANCED: Check file access permissions (owner OR chat member OR shared user)
    owner_id = file_doc.get("owner_id")
    chat_id = file_doc.get("chat_id")
    shared_with = file_doc.get("shared_with", [])
    
    # Owner can always access
    if owner_id == current_user:
        _log("info", f"Owner accessing file: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_download"})
    # Shared user can access
    elif current_user in shared_with:
        _log("info", f"Shared user accessing file: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_download"})
    # Chat members can access files in their chats
    elif chat_id:
        try:
            from db_proxy import chats_collection
            chat_doc = await chats_collection().find_one({"_id": chat_id})
            if chat_doc and current_user in chat_doc.get("members", []):
                _log("info", f"Chat member accessing file: user={current_user}, chat={chat_id}, file={file_id}", {"user_id": current_user, "operation": "file_download"})
            else:
                _log("warning", f"Non-chat member download attempt: user={current_user}, chat={chat_id}, file={file_id}", {"user_id": current_user, "operation": "file_download"})
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: you don't have permission to download this file (not a chat member)"
                )
        except HTTPException:
            # Re-raise HTTPException unchanged (e.g., 403 Forbidden)
            raise
        except (OSError, TimeoutError, Exception) as e:
            _log("error", f"Error checking chat membership: {e}", {"user_id": current_user, "operation": "file_download"})
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: unable to verify chat membership"
            )
    # No access for unauthorized users
    else:
        _log("warning", f"Unauthorized download attempt: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_download"})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you don't have permission to download this file. Ask the file owner to share it with you."
        )
    
    # Security: Validate storage path to prevent directory traversal
    storage_path = file_doc["storage_path"]
    file_path = Path(storage_path)
    
    try:
        # Resolve to absolute path and check it's within data root
        resolved_path = file_path.resolve()
        data_root = settings.DATA_ROOT.resolve()
        # Use proper path comparison to prevent traversal bypass
        try:
            resolved_path.relative_to(data_root)
        except ValueError:
            _log("error", f"Download path traversal attempt: {storage_path}", {"user_id": current_user, "operation": "file_download"})
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        file_path = resolved_path
    except HTTPException:
        # Re-raise HTTPException unchanged (e.g., 403 for traversal attempts)
        raise
    except (OSError, ValueError) as path_error:
        _log("error", f"Invalid download path: {storage_path} - {path_error}", {"user_id": current_user, "operation": "file_download"})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid file path"
        )
    
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
                chunk_size = 4 * 1024 * 1024  # 4MB chunks (same as upload)
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
                "Accept-Ranges": "bytes",
                "Content-Disposition": f'inline; filename="{quote(file_doc["filename"])}"',
                "Cache-Control": "no-cache"
            }
        )
    
    # Full file download - use streaming for large files to avoid memory issues
    if file_size > 100 * 1024 * 1024:  # 100MB threshold
        async def file_iterator():
            async with aiofiles.open(file_path, "rb") as f:
                chunk_size = 4 * 1024 * 1024  # 4MB chunks
                remaining = file_size
                while remaining > 0:
                    read_size = min(chunk_size, remaining)
                    data = await f.read(read_size)
                    if not data:
                        break
                    remaining -= len(data)
                    yield data
        
        return StreamingResponse(
            file_iterator(),
            headers={
                "Content-Length": str(file_size),
                "Content-Type": file_doc["mime"],
                "Accept-Ranges": "bytes",
                "Content-Disposition": f'inline; filename="{quote(file_doc["filename"])}"',
                "Cache-Control": "no-cache"
            }
        )
    
    # Small files - use FileResponse
    return FileResponse(
        file_path,
        media_type=file_doc["mime"],
        filename=file_doc["filename"],
        headers={
            "Content-Disposition": f'inline; filename="{quote(file_doc["filename"])}"',
            "Cache-Control": "no-cache"
        }
    )


@router.post("/{file_id}/share")
async def share_file(
    file_id: str,
    user_ids: List[str] = Body(...),
    current_user: str = Depends(get_current_user)
):
    """Share file with specific users"""
    
    # Find file
    file_doc = await files_collection().find_one({"_id": file_id})
    if not file_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Check if user is owner
    owner_id = file_doc.get("owner_id")
    if owner_id != current_user:
        _log("warning", f"Unauthorized share attempt: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_share"})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: only file owner can share files"
        )
    
    # Add users to shared_with list
    await files_collection().update_one(
        {"_id": file_id},
        {"$addToSet": {"shared_with": {"$each": user_ids}}}
    )
    
    _log("info", f"File shared: owner={current_user}, file={file_id}, users={user_ids}", {"user_id": current_user, "operation": "file_share"})
    
    return {"message": f"File shared with {len(user_ids)} users"}


@router.get("/{file_id}/shared-users")
async def get_shared_users(file_id: str, current_user: str = Depends(get_current_user)):
    """Get list of users file is shared with"""
    
    # Find file
    file_doc = await files_collection().find_one({"_id": file_id})
    if not file_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Check if user is owner or in shared list
    owner_id = file_doc.get("owner_id")
    shared_with = file_doc.get("shared_with", [])
    
    if owner_id != current_user and current_user not in shared_with:
        _log("warning", f"Unauthorized access to shared users list: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_shared_users"})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you don't have permission to view shared users for this file"
        )
    
    return {"shared_users": shared_with}


@router.delete("/{file_id}/share/{user_id}")
async def revoke_file_access(
    file_id: str,
    user_id: str,
    current_user: str = Depends(get_current_user)
):
    """Revoke file access from specific user"""
    
    # Find file
    file_doc = await files_collection().find_one({"_id": file_id})
    if not file_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Check if user is owner
    owner_id = file_doc.get("owner_id")
    if owner_id != current_user:
        _log("warning", f"Unauthorized revoke attempt: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_revoke_access"})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: only file owner can revoke access"
        )
    
    # Remove user from shared_with list
    await files_collection().update_one(
        {"_id": file_id},
        {"$pull": {"shared_with": user_id}}
    )
    
    _log("info", f"File access revoked: owner={current_user}, file={file_id}, user={user_id}", {"user_id": current_user, "operation": "file_revoke_access"})
    
    return {"message": f"Access revoked for user {user_id}"}


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
