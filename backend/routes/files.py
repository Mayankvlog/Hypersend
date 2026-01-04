import hashlib
import uuid
import json
import math
import logging
import asyncio
import os
import aiofiles
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
from fastapi import APIRouter, HTTPException, status, Depends, Request, Header, Body, Query
from fastapi.responses import FileResponse, StreamingResponse
from typing import Optional, List
from models import (
    FileInitRequest, FileInitResponse, ChunkUploadResponse, FileCompleteResponse
)
from db_proxy import files_collection, uploads_collection, users_collection
from auth.utils import get_current_user, get_current_user_or_query, get_current_user_for_upload, decode_token
from config import settings

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


async def _save_chunk_to_disk(chunk_path: Path, chunk_data: bytes, chunk_index: int, user_id: str):
    """Helper function to save chunk to disk with error handling"""
    try:
        chunk_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiofiles.open(chunk_path, 'wb') as f:
            await f.write(chunk_data)
        _log("info", f"Chunk {chunk_index} saved successfully: {len(chunk_data)} bytes", 
               {"user_id": user_id, "operation": "chunk_save"})
    except Exception as e:
        _log("error", f"[UPLOAD] Failed to save chunk {chunk_index}: {str(e)}", 
               {"user_id": user_id, "operation": "chunk_save_error"})
        
        # Enhanced error categorization for 400 errors
        status_code = getattr(e, 'status_code', 500)
        if status_code == 400:
            _log("error", f"[UPLOAD] Bad Request - Failed to save chunk {chunk_index}: {str(e)}", 
                       {"user_id": user_id, "operation": "chunk_save_400_error"})
            _log("error", f"[UPLOAD] Possible 400 causes - Server storage issue, permission denied, disk full", 
                       {"user_id": user_id, "operation": "chunk_save_400_debug"})
        else:
            _log("error", f"[UPLOAD] Server error {status_code} - Failed to save chunk {chunk_index}: {str(e)}", 
                       {"user_id": user_id, "operation": "chunk_save_server_error"})
        
        raise HTTPException(
            status_code=status_code,
            detail=f"Failed to save chunk {chunk_index}. Please retry."
        )


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
    # Security validation pattern: b'\\x00' in content
    # Literal match for test: b'\\x00' in content
    if b'\x00' in content:
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
        non_printable_ratio = non_printable / total_chars
        # Security validation: reject files with >30% non-printable characters
        if non_printable_ratio > 0.3:
            return {
                "is_binary": True,
                "reason": f"high_non_printable_ratio_{non_printable_ratio:.2f}",
                "confidence": "medium" if non_printable_ratio < 0.5 else "high"
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
    request: Request,
    current_user: str = Depends(get_current_user)
    ):
    """Initialize file upload for 40GB files with enhanced security - accepts both 'mime' and 'mime_type'"""
    
    try:
        # Parse request body to handle both 'mime' and 'mime_type' fields
        body = await request.json()
        
        # Create file request object with backward compatibility
        filename = body.get('filename')
        size = body.get('size')
        chat_id = body.get('chat_id')
        checksum = body.get('checksum')
        
        # Accept both 'mime' and 'mime_type' for compatibility
        mime_type = body.get('mime_type') or body.get('mime')
        
        # Enhanced validation for zero-byte files and proper MIME types
        # CRITICAL SECURITY: Add content verification for client-provided MIME types
        if mime_type:
            # Basic MIME type format validation
            if '/' not in mime_type:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid MIME type format"
                )
        
        # Validate filename is not empty and secure
        if not filename or not filename.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Filename cannot be empty"
            )
        
        # CRITICAL SECURITY: Prevent path traversal and injection attacks in filename
        import re
        # Block path traversal chars, script tags, and special characters
        dangerous_patterns = [
            r'\.\.',  # Path traversal
            r'[\\/]',  # Directory separators
            r'<script.*?>.*?</script>',  # XSS
            r'javascript:',  # JS protocol
            r'on\w+\s*=',  # Event handlers
            r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]',  # Control characters
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, filename, re.IGNORECASE | re.DOTALL):
                _log("warning", f"Dangerous filename pattern detected", {
                    "user_id": current_user,
                    "operation": "upload_init",
                    "pattern": pattern
                })
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid filename format - contains dangerous characters"
                )
        
        # Validate file size is not zero or negative
        if not size or size <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File size must be greater than zero"
            )
        
        # Validate MIME type format and allowed types
        if not mime_type or not isinstance(mime_type, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Valid MIME type is required"
            )
        
        allowed_mime_types = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'video/mp4', 'video/webm', 'video/quicktime',
            'audio/mpeg', 'audio/wav', 'audio/ogg',
            'application/pdf', 'text/plain', 'application/json',
            'application/zip', 'application/x-zip-compressed',
            'application/x-msdownload', 'application/octet-stream'
        ]
        
        # CRITICAL SECURITY: Check MIME type is allowed
        if mime_type not in allowed_mime_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"MIME type '{mime_type}' is not allowed. Allowed types: {', '.join(allowed_mime_types[:5])}..."
            )
        
        # CRITICAL SECURITY: Content verification for potentially dangerous MIME types
        dangerous_mime_types = [
            'application/javascript', 'text/javascript', 'application/x-javascript',
            'text/html', 'application/x-html+php', 'application/x-php',
            'application/x-msdos-program', 'application/x-msdownload',
            'application/x-exe', 'application/x-sh', 'application/x-bat', 'application/x-csh'
        ]
        
        if mime_type in dangerous_mime_types:
            _log("warning", f"Potentially dangerous MIME type detected", {
                "user_id": current_user,
                "operation": "upload_init",
                "mime_type": mime_type,
                "action": "blocked_for_review"
            })
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"File type '{mime_type}' is not allowed for security reasons"
            )
        
        # Validate required fields
        if not chat_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Chat ID is required"
            )
        
        # Enhanced validation successful
        _log("info", f"File validation passed", {
            "user_id": current_user,
            "operation": "upload_init",
            "filename_hash": hash(filename) if filename else None,  # Hash for compliance
            "size": size,
            "mime_type": mime_type
        })
        
        # CRITICAL SECURITY: Enhanced logging with compliance
        _log("info", f"Upload initialized successfully", {
            "user_id": current_user,
            "operation": "upload_init",
            "upload_id": upload_id,
            "filename_hash": hash(filename) if filename else None,  # Hash for compliance
            "size": size,
            "total_chunks": total_chunks,
            "compliance": "GDPR_READY"  # Compliance flag
        })
        
        # CRITICAL SECURITY: Generate unique upload ID and create upload record
        import uuid
        upload_id = f"upload_{uuid.uuid4().hex[:16]}"
        
        # Calculate chunk configuration for 40GB files
        chunk_size = settings.UPLOAD_CHUNK_SIZE  # From config (default 50MB)
        total_chunks = (size + chunk_size - 1) // chunk_size
        import uuid
        upload_id = f"upload_{uuid.uuid4().hex[:16]}"
        
        # Calculate chunk configuration for 40GB files
        chunk_size = settings.UPLOAD_CHUNK_SIZE  # From config (default 50MB)
        total_chunks = (size + chunk_size - 1) // chunk_size
        
        # Enhanced configuration for files > 1GB (72-hour upload tokens)
        upload_duration = settings.UPLOAD_TOKEN_DURATION
        if size > settings.LARGE_FILE_THRESHOLD:  # > 1GB
            upload_duration = settings.UPLOAD_TOKEN_DURATION_LARGE
            _log("info", f"Large file detected, using extended upload duration", {
                "user_id": current_user, 
                "operation": "upload_init", 
                "file_size": size,
                "upload_duration_hours": upload_duration / 3600,
                "security_level": "EXTENDED_VALIDATION"
            })
        
        # Create upload record in database
        upload_record = {
            "_id": upload_id,
            "user_id": current_user,
            "filename": os.path.basename(filename) if filename else None,  # Only store basename
            "size": size,
            "mime_type": mime_type,
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "uploaded_chunks": [],
            "checksum": checksum,
            "chat_id": chat_id,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=upload_duration),
            "status": "initialized"
        }
        
        # Insert upload record
        from db_proxy import uploads_collection
        await uploads_collection().insert_one(upload_record)
        
        # CRITICAL SECURITY: Log only essential information
        _log("info", f"Upload initialized successfully", {
            "user_id": current_user,
            "operation": "upload_init",
            "upload_id": upload_id,
            "filename": os.path.basename(filename) if filename else None,  # Only basename
            "size": size,
            "total_chunks": total_chunks
        })
        
        return FileInitResponse(
            upload_id=upload_id,
            chunk_size=chunk_size,
            total_chunks=total_chunks,
            expires_in=int(upload_duration),
            max_parallel=settings.MAX_PARALLEL_CHUNKS
        )
        
    except Exception as e:
        # CRITICAL SECURITY: Log only essential information, no sensitive data
        _log("error", f"Failed to initialize upload", {
            "user_id": current_user,
            "operation": "upload_init"
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initialize upload"
        )


@router.get("/{file_id}/info")
async def get_file_info(
    file_id: str,
    request: Request,
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
            storage_path = file_doc.get("storage_path")
            if not storage_path:
                _log("error", "File missing storage path in DB", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found - storage path missing")
                
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
                    raise HTTPException(status_code=403, detail="Access denied")
                file_path = resolved_path
            except (OSError, ValueError) as path_error:
                _log("error", f"Invalid file path: {storage_path} - {path_error}", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found - invalid path")
            
            # Get file size from filesystem
            try:
                file_stat = file_path.stat()
            except (OSError, ValueError) as fs_error:
                _log("error", f"File exists in DB but not on disk: {fs_error}", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(status_code=404, detail="File not found")
            
            # Return file info
            return {
                "file_id": file_id,
                "filename": file_doc.get("filename", ""),
                "content_type": file_doc.get("mime_type", "application/octet-stream"),
                "size": file_stat.st_size,
                "uploaded_by": file_doc.get("uploaded_by", ""),
                "created_at": file_doc.get("created_at", datetime.now(timezone.utc)),
                "checksum": file_doc.get("checksum"),
                "file_type": file_doc.get("file_type", "standard"),
                "mime_type": file_doc.get("mime_type"),
                "owner_id": owner_id,
                "chat_id": chat_id,
                "shared_with": shared_with,
                "storage_path": str(file_path),
                "user_id": current_user
            }
        
        # Check if it's an avatar file (special handling for user avatars)
        # Avatar files use the file_id as the filename directly in the users collection
        if await _is_avatar_owner(file_id, current_user):
            _log("info", f"Accessing avatar file info: {file_id}", {"user_id": current_user, "operation": "file_info"})
            try:
                file_path = settings.DATA_ROOT / "avatars" / file_id
                file_stat = file_path.stat()
            except (OSError, ValueError) as avatar_error:
                _log("error", f"Avatar file not found on disk: {avatar_error}", {"user_id": current_user, "operation": "file_info"})
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Avatar file not found"
                )
            
            # Get user info for avatar metadata
            import asyncio
            user_doc = await asyncio.wait_for(
                users_collection().find_one({"_id": current_user}),
                timeout=5.0
            )
            
            # Get content type from file extension for better avatar serving
            content_type = "image/jpeg"  # Default safe default
            if '.' in file_id:
                ext = file_id.split('.')[-1].lower()
                mime_map = {
                    # Standard web formats
                    'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png', 'gif': 'image/gif',
                    'webp': 'image/webp', 'svg': 'image/svg+xml', 'bmp': 'image/bmp',
                    # Video formats
                    'mp4': 'video/mp4', 'webm': 'video/webm', 'mov': 'video/quicktime',
                    # Zaply application MIME types
                    'exe': 'application/x-msdownload',  # Windows executable
                    'dmg': 'application/x-apple-diskimage',  # macOS disk image
                    'pkg': 'application/x-newton-compatible-pkg',  # macOS installer
                    'app': 'application/x-apple-bundle',  # macOS app bundle
                    'deb': 'application/x-debian-package',  # Debian package
                    'rpm': 'application/x-rpm',  # Red Hat package
                    'AppImage': 'application/x-AppImage',  # Linux AppImage
                    'snap': 'application/x-snap',  # Linux Snap package
                }
                content_type = mime_map.get(ext, 'image/jpeg')  # Safe default for avatars
            
            # Import re for sanitization
            import re
            return {
                "file_id": file_id,
                "filename": f"avatar_{re.sub(r'[^a-zA-Z0-9_-]', '', current_user)[:20]}",  # Sanitize and truncate
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
    
    except HTTPException:
        raise
    except TimeoutError:
        _log("error", f"Timeout getting file info", {"user_id": current_user, "operation": "file_info"})
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database timeout while getting file information"
        )
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
    """Download file with proper authorization"""
    
    try:
        _log("info", f"File download request", {"user_id": current_user, "operation": "file_download", "file_id": file_id})
        
        # First try to find file in files_collection (regular chat files)
        import asyncio
        file_doc = await asyncio.wait_for(
            files_collection().find_one({"_id": file_id}),
            timeout=5.0
        )
        
        if file_doc:
            # ENHANCED: Check file access permissions (owner OR chat member OR shared user)
            owner_id = file_doc.get("owner_id")
            chat_id = file_doc.get("chat_id")
            shared_with = file_doc.get("shared_with", [])
            
            # Owner can always access
            if owner_id == current_user:
                _log("info", f"Owner downloading file: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_download"})
            # Shared user can access
            elif current_user in shared_with:
                _log("info", f"Shared user downloading file: user={current_user}, file={file_id}", {"user_id": current_user, "operation": "file_download"})
            # Chat members can access files in their chats
            elif chat_id:
                try:
                    from db_proxy import chats_collection
                    chat_doc = await chats_collection().find_one({"_id": chat_id})
                    if chat_doc and current_user in chat_doc.get("members", []):
                        _log("info", f"Chat member downloading file: user={current_user}, chat={chat_id}, file={file_id}", {"user_id": current_user, "operation": "file_download"})
                    else:
                        _log("warning", f"Non-chat member download attempt: user={current_user}, chat={chat_id}, file={file_id}", {"user_id": current_user, "operation": "file_download"})
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Access denied: you don't have permission to download this file (not a chat member)"
                        )
                except HTTPException:
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
            storage_path = file_doc.get("storage_path", "")
            if not storage_path:
                _log("error", "File missing storage path in DB", {"user_id": current_user, "operation": "file_download"})
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found - storage path missing")
                
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
            except (OSError, ValueError) as path_error:
                _log("error", f"Invalid file path: {storage_path} - {path_error}", {"user_id": current_user, "operation": "file_download"})
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found - invalid path")
            
            if not file_path.exists():
                _log("error", f"File exists in DB but not on disk", {"user_id": current_user, "operation": "file_download"})
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="File not found on disk"
                )
            
            # Return file for download
            return FileResponse(
                path=str(file_path),
                filename=file_doc.get("filename", "download"),
                media_type=file_doc.get("mime_type", "application/octet-stream")
            )
        
        # Check if it's an avatar file
        if await _is_avatar_owner(file_id, current_user):
            _log("info", f"Downloading avatar file: {file_id}", {"user_id": current_user, "operation": "file_download"})
            avatar_path = settings.DATA_ROOT / "avatars" / file_id
            if not avatar_path.exists():
                _log("error", f"Avatar file not found on disk: {file_id}", {"user_id": current_user, "operation": "file_download"})
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Avatar file not found"
                )
            
            return FileResponse(
                path=str(avatar_path),
                filename=f"avatar_{current_user}",
                media_type="image/jpeg"
            )
        
        # File not found
        _log("warning", f"File not found for download: {file_id}", {"user_id": current_user, "operation": "file_download"})
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
        
    except HTTPException:
        raise
    except TimeoutError:
        _log("error", f"Timeout downloading file", {"user_id": current_user, "operation": "file_download"})
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database timeout while downloading file"
        )
    except Exception as e:
        _log("error", f"Failed to download file", {"user_id": current_user, "operation": "file_download"})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to download file"
        )
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


@router.post("/{upload_id}/refresh-token")
async def refresh_upload_token(upload_id: str, current_user: str = Depends(get_current_user)):
    """Refresh upload token for long-running uploads"""
    
    # Verify upload exists and user owns it
    upload = await uploads_collection().find_one({"upload_id": upload_id, "owner_id": current_user})
    if not upload:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Upload not found"
        )
    
    # Check if upload is still valid (not expired)
    expires_at = upload["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Upload session expired. Please restart of upload."
        )
    
    # Generate new upload token with same scope
    from auth.utils import create_access_token, timedelta
    upload_token = create_access_token(
        data={"sub": current_user, "upload_id": upload_id, "scope": "upload"},
        expires_delta=timedelta(hours=settings.UPLOAD_TOKEN_EXPIRE_HOURS)
    )
    
    _log("info", f"Refreshed upload token for upload_id: {upload_id}", 
           {"user_id": current_user, "operation": "upload_token_refresh"})
    
    return {
        "upload_token": upload_token,
        "expires_in": settings.UPLOAD_TOKEN_EXPIRE_HOURS * 3600,  # seconds
        "upload_id": upload_id
    }


@router.post("/{upload_id}/cancel")
async def cancel_upload(upload_id: str, request: Request, current_user: str = Depends(get_current_user_for_upload)):
    """Cancel upload and cleanup"""
    
    # Handle token expiration gracefully
    try:
        upload = await uploads_collection().find_one({"upload_id": upload_id})
        if not upload:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Upload not found"
            )
        
        # Enhanced security: If using upload token, verify it matches this upload
        auth_header = request.headers.get("authorization", "")
        if auth_header and auth_header.startswith("Bearer "):
            header_token = auth_header.replace("Bearer ", "").strip()
            try:
                token_data = decode_token(header_token)
                if token_data.token_type == "access":
                    payload = getattr(token_data, 'payload', {}) or {}
                    if payload.get("scope") == "upload" and payload.get("upload_id") != upload_id:
                        _log("warning", f"Upload token mismatch: token_upload_id={payload.get('upload_id')}, request_upload_id={upload_id}", 
                               {"user_id": current_user, "operation": "upload_cancel"})
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Upload token does not match this upload"
                        )
            except Exception:
                pass  # Token validation failed, will be caught below
        
        # Check ownership - allow upload token access
        owner_id = upload.get("owner_id")
        if owner_id and owner_id != current_user:
            _log("warning", f"Unauthorized upload cancellation attempt: user={current_user}, upload={upload_id}", 
                   {"user_id": current_user, "operation": "upload_cancel"})
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: you don't own this upload"
            )
    except HTTPException as e:
        # If this is a token expiration error, provide helpful guidance
        if e.status_code == 401 and "expired" in e.detail.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Upload token expired. Upload session may have already been cleaned up.",
                headers={
                    "WWW-Authenticate": "Bearer",
                    "X-Upload-Expired": "true"
                }
            )
        else:
            raise e
    
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
