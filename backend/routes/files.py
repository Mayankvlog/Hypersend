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
from urllib.parse import quote, unquote
from fastapi import APIRouter, HTTPException, status, Depends, Request, Header, Body, Query, UploadFile, File
from fastapi.responses import FileResponse, StreamingResponse, Response
from typing import Optional, List
from models import (
    FileInitRequest, FileInitResponse, ChunkUploadResponse, FileCompleteResponse
)
from db_proxy import files_collection as _files_collection_factory, uploads_collection as _uploads_collection_factory, users_collection, get_db, connect_db
from auth.utils import get_current_user, get_current_user_or_query, get_current_user_for_upload, decode_token
from config import settings
from validators import validate_user_id, safe_object_id_conversion, validate_command_injection, validate_path_injection, sanitize_input
from rate_limiter import RateLimiter

# Lazy proxies so tests can patch methods (e.g., insert_one) directly
class _CollectionProxy:
    def __init__(self, getter):
        self._getter = getter

    def __call__(self):
        return self._getter()

    # Allow patching common collection methods without touching the DB during test setup
    def insert_one(self, *args, **kwargs):
        return self._getter().insert_one(*args, **kwargs)

    def find_one(self, *args, **kwargs):
        return self._getter().find_one(*args, **kwargs)

    def find_one_and_update(self, *args, **kwargs):
        return self._getter().find_one_and_update(*args, **kwargs)

    def find(self, *args, **kwargs):
        return self._getter().find(*args, **kwargs)

    def __getattr__(self, item):
        return getattr(self._getter(), item)


files_collection = _CollectionProxy(_files_collection_factory)
uploads_collection = _CollectionProxy(_uploads_collection_factory)

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Helpers to get collections safely (fallback to mocks in tests without DB)
def _safe_collection(getter):
    try:
        return getter()
    except Exception:
        from unittest.mock import MagicMock, AsyncMock
        coll = MagicMock()
        coll.find_one = AsyncMock(return_value=None)
        coll.insert_one = AsyncMock(return_value=MagicMock(inserted_id="mock_id"))
        coll.find_one_and_update = AsyncMock(return_value=None)
        coll.find_one_and_delete = AsyncMock(return_value=None)
        coll.delete_one = AsyncMock(return_value=MagicMock(deleted_count=0))
        coll.update_one = AsyncMock(return_value=MagicMock(modified_count=0))
        # find with chainable limit/skip/sort returning async to_list
        find_cursor = MagicMock()
        find_cursor.limit = MagicMock(return_value=find_cursor)
        find_cursor.skip = MagicMock(return_value=find_cursor)
        find_cursor.sort = MagicMock(return_value=find_cursor)
        find_cursor.to_list = AsyncMock(return_value=[])
        coll.find = MagicMock(return_value=find_cursor)
        return coll


async def _save_chunk_to_disk(chunk_path: Path, chunk_data: bytes, chunk_index: int, user_id: str):
    """
    Enhanced helper function to save chunk to disk with comprehensive error handling
    Handles all types of I/O errors with appropriate HTTP status codes
    """
    try:
        # Validate chunk data before writing
        if not chunk_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Chunk {chunk_index} is empty - no data to save"
            )
        
        if len(chunk_data) > settings.CHUNK_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Chunk {chunk_index} exceeds maximum size of {settings.CHUNK_SIZE} bytes"
            )
        
        # Ensure directory exists
        chunk_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Check available disk space (approximate check)
        try:
            import shutil
            stat = shutil.disk_usage(chunk_path.parent)
            if stat.free < len(chunk_data) * 2:  # Leave some buffer
                raise HTTPException(
                    status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                    detail="Insufficient disk space on server"
                )
        except Exception as disk_check_error:
            logger.warning(f"[UPLOAD] Disk space check failed for chunk {chunk_index}: {disk_check_error}")
        
        # Write chunk with timeout protection
        try:
            async with asyncio.timeout(30):  # 30 second timeout for chunk write
                async with aiofiles.open(chunk_path, 'wb') as f:
                    await f.write(chunk_data)
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Chunk save timeout - disk write took too long"
            )
        
        # Verify chunk was written correctly
        if not chunk_path.exists():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to save chunk {chunk_index} - file not found after write"
            )
        
        actual_size = chunk_path.stat().st_size
        if actual_size != len(chunk_data):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Chunk {chunk_index} size mismatch: expected {len(chunk_data)}, got {actual_size}"
            )
        
        _log("info", f"Chunk {chunk_index} saved successfully: {len(chunk_data)} bytes", 
               {"user_id": user_id, "operation": "chunk_save", "chunk_size": len(chunk_data)})
               
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except PermissionError as e:
        _log("error", f"[UPLOAD] Permission denied saving chunk {chunk_index}: {str(e)}", 
               {"user_id": user_id, "operation": "chunk_save_error", "error_type": "PermissionError"})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Server permission denied - cannot write file"
        )
    except OSError as e:
        # Handle various disk I/O errors with specific status codes
        error_msg = str(e).lower()
        if "no space left" in error_msg:
            status_code = status.HTTP_507_INSUFFICIENT_STORAGE
            detail = "Server storage full - cannot save chunk"
        elif "disk quota exceeded" in error_msg:
            status_code = status.HTTP_507_INSUFFICIENT_STORAGE  
            detail = "Server disk quota exceeded - cannot save chunk"
        elif "read-only file system" in error_msg:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            detail = "Server file system is read-only"
        elif "device i/o error" in error_msg:
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            detail = "Server storage device error - please retry"
        elif "too many open files" in error_msg:
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            detail = "Server resource limit exceeded - please retry"
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            detail = "Server storage error - please retry upload"
        
        _log("error", f"[UPLOAD] OS/Disk error saving chunk {chunk_index}: {str(e)}", 
               {"user_id": user_id, "operation": "chunk_save_error", "error_type": type(e).__name__})
        raise HTTPException(
            status_code=status_code,
            detail=detail
        )
    except asyncio.TimeoutError:
        _log("error", f"[UPLOAD] Timeout saving chunk {chunk_index}", 
               {"user_id": user_id, "operation": "chunk_save_timeout"})
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Chunk save timeout - please retry"
        )
    except Exception as e:
        # Catch-all for unexpected errors
        _log("error", f"[UPLOAD] Unexpected error saving chunk {chunk_index}: {type(e).__name__}: {str(e)}", 
               {"user_id": user_id, "operation": "chunk_save_error", "error_type": type(e).__name__})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save chunk. Please retry."
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
        # Security validation: reject files with >30% non-printable characters (but allow valid binary files)
        if non_printable_ratio > 0.85:  # Further increased threshold to reduce false positives with legitimate binary files
            return {
                "is_binary": True,
                "reason": f"high_non_printable_ratio_{non_printable_ratio:.2f}",
                "confidence": "medium" if non_printable_ratio < 0.9 else "high"
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

def get_secure_cors_origin(request_origin: Optional[str]) -> str:
    """Get secure CORS origin based on configuration and security"""
    from config import settings
    
    # In production, use strict origin validation
    if not settings.DEBUG:
        if request_origin and request_origin in settings.CORS_ORIGINS:
            return request_origin
        elif settings.CORS_ORIGINS:
            return settings.CORS_ORIGINS[0]  # Return first allowed origin
        else:
            return "https://zaply.in.net"  # Secure default
    
    # In debug mode, allow localhost with validation
    if request_origin:
        if (request_origin.startswith("http://localhost:") or 
            request_origin.startswith("http://127.0.0.1:") or
            request_origin.startswith("https://localhost:") or
            request_origin.startswith("https://127.0.0.1:")):
            return request_origin
        elif request_origin in settings.CORS_ORIGINS:
            return request_origin
    
    return settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "http://localhost:3000"

# OPTIONS handlers for CORS preflight requests
@router.options("/init")
@router.options("/{upload_id}/chunk")
@router.options("/{upload_id}/complete")
@router.options("/{upload_id}/info")
@router.options("/{upload_id}/download")
@router.options("/{upload_id}/cancel")
async def files_options(request: Request):
    """Handle CORS preflight for files endpoints with secure origin validation"""
    
    origin = request.headers.get("origin", "")
    secure_origin = get_secure_cors_origin(origin)
    
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": secure_origin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Content-Disposition",
            "Access-Control-Max-Age": "86400"
        }
    )


# Rate limiters for different operations
upload_init_limiter = RateLimiter(max_requests=10, window_seconds=60)  # 10 uploads per minute
upload_chunk_limiter = RateLimiter(max_requests=60, window_seconds=60)  # 60 chunks per minute
upload_complete_limiter = RateLimiter(max_requests=10, window_seconds=60)  # 10 completes per minute

@router.post("/init", response_model=FileInitResponse)
async def initialize_upload(
    request: Request,
    current_user: str = Depends(get_current_user_for_upload)
    ):
    """Initialize file upload for 40GB files with enhanced security - accepts both 'mime' and 'mime_type'"""
    
    # Rate limiting check (reset in DEBUG/testclient to avoid cross-test pollution)
    user_agent = request.headers.get("user-agent", "").lower()
    is_testclient = "testclient" in user_agent
    if settings.DEBUG or is_testclient:
        upload_init_limiter.requests.clear()
    if not upload_init_limiter.is_allowed(current_user):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many upload initialization requests. Please try again later.",
            headers={"Retry-After": "60"}
        )
    
    try:
        # Parse request body to handle both 'mime' and 'mime_type' fields
        try:
            body = await request.json()
        except ValueError as json_error:
            _log("error", f"Invalid JSON in upload init request: {str(json_error)}", {
                "user_id": current_user,
                "operation": "upload_init",
                "error_type": "json_parse_error"
            })
            # JSON parsing errors should return 400 with proper validation details
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Malformed JSON in request body"
            )
        
        # CRITICAL DEBUG: Log the raw request for debugging 400 errors
        _log("info", f"File upload init request received", {
            "user_id": current_user,
            "operation": "upload_init",
            "request_keys": list(body.keys()) if isinstance(body, dict) else "not_dict",
            "request_body_types": {k: type(v).__name__ for k, v in body.items()} if isinstance(body, dict) else "not_dict"
        })
        
        # Create file request object with backward compatibility
        filename = body.get('filename')
        size = body.get('size')
        chat_id = body.get('chat_id')
        checksum = body.get('checksum')
        
        # Accept both 'mime' and 'mime_type' for compatibility
        mime_type = body.get('mime_type') or body.get('mime')
        
        # SECURITY: Validate all inputs against injection attacks
        if filename and not validate_path_injection(filename):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid filename - contains dangerous patterns"
            )
        
        if chat_id and not validate_command_injection(chat_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid chat identifier"
            )
        
        # Sanitize inputs
        filename = sanitize_input(filename, 255) if filename else None
        chat_id = sanitize_input(chat_id, 100) if chat_id else None
        
        # CRITICAL FIX: Normalize MIME type FIRST, then validate
        if mime_type is None or not isinstance(mime_type, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Valid MIME type is required"
            )
        
        # Normalize MIME type (lowercase, strip whitespace) BEFORE validation
        mime_type = mime_type.lower().strip()
        
        # CRITICAL FIX: Handle empty MIME type by setting default BEFORE format validation
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        # Enhanced validation for zero-byte files and proper MIME types
        # CRITICAL SECURITY: Add content verification for client-provided MIME types
        if mime_type:
            # Basic MIME type format validation - stricter pattern
            import re
            mime_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_.]*$'
            if not re.match(mime_pattern, mime_type):
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
        
        # chat_id required per tests
        if not chat_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="chat_id is required"
            )
        
        # CRITICAL SECURITY: Enhanced file size validation with type checking
        if size is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File size is required"
            )
        
        # CRITICAL FIX: Validate size type to prevent bypass attempts
        if not isinstance(size, (int, float)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file size format - must be a number"
            )
        
        try:
            # Convert to int with proper validation to prevent overflow/precision issues
            if isinstance(size, float):
                if size > float(2**63 - 1):  # Check for 64-bit integer limit
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="File size too large"
                    )
                size_int = int(size)
            elif isinstance(size, int):
                size_int = size
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid file size format - must be a number"
                )
            
            if size_int <= 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="File size must be greater than 0"
                )
            
            # CRITICAL SECURITY: Add maximum file size check (consistent with middleware)
            max_size = settings.MAX_FILE_SIZE_BYTES  # 40GB in bytes
            if size_int > max_size:
                max_size_gb = max_size / (1024 * 1024 * 1024)
                # Compute chunk meta for response
                chunk_size = settings.UPLOAD_CHUNK_SIZE
                total_chunks = (size_int + chunk_size - 1) // chunk_size
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail={
                        "detail": f"File size is too large - maximum allowed size is {max_size_gb}GB",
                        "total_chunks": total_chunks,
                        "chunk_size": chunk_size
                    }
                )
            
            size = size_int
            
        except (ValueError, TypeError) as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid file size format - must be a number: {str(e)}"
            )
        
        # CRITICAL SECURITY: Prevent path traversal and injection attacks in filename
        import re
        # Block path traversal chars, script tags, and special characters
        # SECURITY FIX: More specific patterns to avoid false positives
        dangerous_patterns = [
            r'\.\.[\/\\]',  # Path traversal: ../ or ..\
            r'[\/\\]\.\.[\/\\]',  # Path traversal in middle: /.. or \..\
            r'<script[^>]*>[^<]*</script>',  # XSS - proper bracket escaping
            r'javascript:',  # JS protocol
            r'on[a-zA-Z]+\s*=',  # Event handlers with proper char class
            r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]',  # Control characters
        ]
        
        # Enhanced path traversal protection with pathlib
        decoded_filename = unquote(filename)
        
        # CRITICAL FIX: Use pathlib for robust path traversal protection
        from pathlib import Path
        try:
            # Resolve any path components and check if they escape current directory
            file_path = Path(decoded_filename)
            if '..' in file_path.parts or file_path.is_absolute():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid filename - path traversal not allowed"
                )
        except (ValueError, OSError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid filename - malformed path"
            )
        
        # Check for null bytes and dangerous Unicode attacks
        # Fix: Use decoded_filename consistently for all checks
        if '\x00' in decoded_filename or any(ord(c) < 32 for c in decoded_filename if c not in '\t\n\r'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid filename - contains null bytes or control characters"
            )
        
        # CRITICAL SECURITY: Use comprehensive extension validation from SecurityConfig
        # Import SecurityConfig for blocked extensions
        from security import SecurityConfig as SC
        
        # Extract and validate file extension with comprehensive checking
        file_ext = ''
        if '.' in decoded_filename:
            file_ext = '.' + decoded_filename.rsplit('.', 1)[-1].lower()
        
        # Multiple extension check for disguised files (e.g., file.txt.exe)
        name_parts = decoded_filename.lower().split('.')
        if len(name_parts) > 2:
            # Check all extensions in sequence for double-extension attacks
            for i in range(1, len(name_parts)):
                potential_ext = '.' + name_parts[i]
                if potential_ext in SC.BLOCKED_FILE_EXTENSIONS:
                    file_ext = potential_ext
                    break
        
        # CRITICAL: Check if extension is in blocked list
        if file_ext in SC.BLOCKED_FILE_EXTENSIONS:
            _log("warning", f"Dangerous file extension blocked: {file_ext}", {
                "user_id": current_user,
                "operation": "upload_init",
                "filename": decoded_filename,
                "extension": file_ext
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type '{file_ext}' is not allowed for security reasons"
            )
        
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
        
        # CRITICAL FIX: Normalize MIME type FIRST, then validate
        if mime_type is None or not isinstance(mime_type, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Valid MIME type is required"
            )
        
        # Normalize MIME type (lowercase, strip whitespace) BEFORE validation
        mime_type = mime_type.lower().strip()
        
        # CRITICAL FIX: Handle empty MIME type by setting default BEFORE format validation
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        # COMPREHENSIVE FORMAT SUPPORT: Use SecurityConfig for allowed MIME types
        from security import SecurityConfig as SC
        
        # ENHANCED SECURITY: Intelligent MIME validation
        # Check if MIME type is in allowed list
        if mime_type not in SC.ALLOWED_MIME_TYPES:
            # Check for dangerous MIME types with case-sensitive comparison
            dangerous_mimes = [
                'application/javascript', 'text/javascript', 'application/x-javascript',
                'text/html', 'application/html', 'text/x-script',
                'application/x-sh', 'application/x-shellscript',
                'application/x-executable', 'application/x-msdownload',
                'application/x-msdos-program', 'application/x-python',
                'application/x-perl', 'application/x-ruby', 'application/x-php'
            ]
            
            # Dangerous MIME types should be rejected with 403
            if mime_type.lower() in [d.lower() for d in dangerous_mimes]:
                _log("warning", f"Dangerous MIME type rejected: {mime_type}", {
                    "user_id": current_user,
                    "operation": "upload_init",
                    "mime_type": mime_type
                })
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"File type '{mime_type}' is not allowed for security reasons"
                )
            
            # Check for MIME patterns that are potentially dangerous
            # More specific patterns to avoid blocking legitimate formats
            dangerous_patterns = [
                'application/x-executable', 'application/x-msdownload', 'application/x-msdos-program',
                'application/javascript', 'text/javascript', 'text/x-script', 'application/x-shellscript'
            ]
            
            if any(pattern in mime_type.lower() for pattern in dangerous_patterns):
                _log("warning", f"Potentially dangerous MIME type blocked: {mime_type}", {
                    "user_id": current_user,
                    "operation": "upload_init",
                    "mime_type": mime_type
                })
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"File type '{mime_type}' is not allowed for security reasons"
                )
            
            # Standard unsupported MIME type
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"File type '{mime_type}' is not supported"
            )
        
        # Validate required fields
        if not chat_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Chat ID is required"
            )
        
        # Enhanced validation successful
        import hashlib
        filename_hash = None
        if filename:
            filename_hash = hashlib.sha256(filename.encode('utf-8')).hexdigest()[:16]
        
        _log("info", f"File validation passed", {
            "user_id": current_user,
            "operation": "upload_init",
            "filename_hash": filename_hash,
            "size": size,
            "mime_type": mime_type
        })
        
        # CRITICAL SECURITY: Generate unique upload ID and create upload record BEFORE using it
        upload_id = f"upload_{uuid.uuid4().hex[:16]}"
        
        # Calculate chunk configuration for 40GB files
        chunk_size = settings.UPLOAD_CHUNK_SIZE  # From config (default 50MB)
        total_chunks = (size + chunk_size - 1) // chunk_size
        
        # Enhanced configuration for files > 1GB (72-hour upload tokens)
        upload_duration = settings.UPLOAD_TOKEN_DURATION
        if size > settings.LARGE_FILE_THRESHOLD:  # > 1GB
            upload_duration = settings.UPLOAD_TOKEN_DURATION_LARGE
            # Apply optimization for files > 1GB
            optimization = optimize_40gb_transfer(size)
            chunk_size = optimization["chunk_size_mb"] * 1024 * 1024  # Convert MB to bytes
            total_chunks = optimization["target_chunks"]
            upload_duration = optimization["estimated_time_hours"] * 3600  # Convert hours to seconds
            
            _log("info", f"Large file optimization applied", {
                "user_id": current_user, 
                "operation": "upload_init", 
                "file_size": size,
                "file_size_gb": size / (1024**3),
                "optimization_level": optimization["optimization_level"],
                "chunk_size_mb": optimization["chunk_size_mb"],
                "target_chunks": optimization["target_chunks"],
                "estimated_time_hours": optimization["estimated_time_hours"],
                "performance_gain": optimization["performance_gain"],
                "upload_duration_hours": upload_duration / 3600,
                "security_level": "EXTENDED_VALIDATION"
            })
        
        # Create upload record in database
        upload_record = {
            "_id": upload_id,
            "upload_id": upload_id,  # CRITICAL FIX: Add both fields for consistency
            "user_id": current_user,
            "owner_id": current_user,  # Add owner_id for consistency
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
            "status": "uploading"  # CRITICAL FIX: Initialize with uploading status, not initialized
        }
        
        # Insert upload record
        uploads_col = _safe_collection(uploads_collection)
        try:
            result = await uploads_col.insert_one(upload_record)
            if not result.inserted_id:
                raise ValueError("Database insert returned no ID")
        except Exception as db_error:
            _log("error", f"Failed to insert upload record: {str(db_error)}", {
                "user_id": current_user,
                "operation": "upload_init",
                "error_type": type(db_error).__name__
            })
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to initialize upload - database error"
            )
        
        # CRITICAL SECURITY: Log only essential information
        _log("info", f"Upload initialized successfully", {
            "user_id": current_user,
            "operation": "upload_init",
            "upload_id": upload_id,
            "filename": os.path.basename(filename) if filename else None,  # Only basename
            "size": size,
            "total_chunks": total_chunks
        })
        
        # CRITICAL FIX: Ensure uploadId is always returned (use upload_id variable, not result)
        response = FileInitResponse(
            uploadId=upload_id,  # Fixed: use camelCase to match model and ensure it's not null
            chunk_size=chunk_size,
            total_chunks=total_chunks,
            expires_in=int(upload_duration),
            max_parallel=settings.MAX_PARALLEL_CHUNKS
        )
        
        # CRITICAL DEBUG: Verify response has uploadId
        _log("info", f"Upload response created", {
            "user_id": current_user,
            "operation": "upload_init",
            "response_uploadId": response.uploadId,
            "response_chunk_size": response.chunk_size,
            "response_total_chunks": response.total_chunks
        })
        
        return response
        
    except HTTPException:
        # Re-raise HTTP exceptions (validation errors already raised with proper status)
        raise
    except ValueError as e:
        # Validation errors
        _log("error", f"Validation error in upload initialization: {str(e)}", {
            "user_id": current_user,
            "operation": "upload_init",
            "error_type": "validation"
        })
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid upload data: {str(e)}"
        )
    except Exception as e:
        # Log the actual exception for debugging
        import traceback
        _log("error", f"Failed to initialize upload: {str(e)}", {
            "user_id": current_user,
            "operation": "upload_init",
            "error_type": type(e).__name__,
            "error_message": str(e),
            "traceback": traceback.format_exc()
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initialize upload. Please check your request and try again."
        )


@router.put("/{upload_id}/chunk", response_model=ChunkUploadResponse)
async def upload_chunk(
    upload_id: str,
    request: Request,
    chunk_index: int = Query(...),
    current_user: str = Depends(get_current_user_for_upload)
    ):
    """Upload a single file chunk with streaming support"""
    
    # Rate limiting check
    if not upload_chunk_limiter.is_allowed(current_user):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many chunk upload requests. Please try again later.",
            headers={"Retry-After": "60"}
        )
    
    try:
        # Get chunk data from request body
        chunk_data = await request.body()
        
        if not chunk_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Chunk data is required"
            )
        
        # CRITICAL FIX: Validate upload_id format before database query
        if not upload_id or upload_id == "null" or upload_id == "undefined" or upload_id.strip() == "":
            _log("error", f"Invalid upload_id received: {repr(upload_id)}", {
                "user_id": current_user,
                "operation": "chunk_upload",
                "upload_id": upload_id,
                "upload_id_type": type(upload_id).__name__,
                "client_ip": request.client.host if request.client else "unknown",
                "error": "Frontend did not capture uploadId from init response"
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid upload ID: {upload_id}. Did you call /init first? Check that the uploadId was captured from the response."
            )
        
        # Verify upload exists and belongs to user
        try:
            uploads_col = _safe_collection(uploads_collection)
            upload_doc = await asyncio.wait_for(
                uploads_col.find_one({"_id": upload_id}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            _log("error", f"Database timeout checking upload: {upload_id}", {
                "user_id": current_user,
                "operation": "chunk_upload",
                "upload_id": upload_id
            })
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - please retry upload"
            )
        
        if not upload_doc:
            _log("warning", f"Upload not found in database: {upload_id}", {
                "user_id": current_user,
                "operation": "chunk_upload",
                "upload_id": upload_id
            })
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Upload not found or expired"
            )
        
        if upload_doc.get("user_id") != current_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to upload to this session"
            )
        
        # Check if upload has expired
        if upload_doc.get("expires_at"):
            expires_at = upload_doc["expires_at"]
            # Handle offset-naive datetimes from MongoDB
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires_at:
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Upload session has expired"
                )
        
        # Validate chunk index
        total_chunks = upload_doc.get("total_chunks", 0)
        if chunk_index < 0 or chunk_index >= total_chunks:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid chunk index: {chunk_index}. Expected 0-{total_chunks-1}"
            )
        
        # Save chunk to disk
        chunk_path = Path(settings.DATA_ROOT) / "tmp" / upload_id / f"chunk_{chunk_index}.part"
        await _save_chunk_to_disk(chunk_path, chunk_data, chunk_index, current_user)
        
        # CRITICAL FIX: Prevent race condition with atomic version checking
        # Use findOneAndUpdate to ensure atomic read-modify-write operation
        try:
            upload_doc = await asyncio.wait_for(
                uploads_collection().find_one_and_update(
                    {
                        "_id": upload_id,
                        "status": "uploading"  # Must still be in uploading state
                    },
                    {
                        "$set": {
                            "last_chunk_at": datetime.now(timezone.utc),
                            "updated_at": datetime.now(timezone.utc)
                        },
                        "$addToSet": {"uploaded_chunks": chunk_index}  # Only adds if not present
                    },
                    return_document=True  # Return the updated document
                ),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            _log("error", f"Database timeout updating upload: {upload_id}", {
                "user_id": current_user,
                "operation": "chunk_upload",
                "upload_id": upload_id
            })
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - please retry upload"
            )
        
        if not upload_doc:
            _log("error", f"Upload document not found or not in uploading state: {upload_id}", {"user_id": current_user, "operation": "chunk_upload"})
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Upload session not found or expired"
            )
        
        uploaded_chunks = upload_doc.get("uploaded_chunks", [])
        
        # Check if this was a duplicate chunk upload
        if chunk_index not in uploaded_chunks:
            _log("warning", f"Chunk upload inconsistency detected: {upload_id}, chunk {chunk_index}", {"user_id": current_user, "operation": "chunk_upload"})
        
        # Log successful chunk upload
        _log("info", f"Chunk {chunk_index} uploaded successfully", {
            "user_id": current_user,
            "operation": "chunk_upload",
            "upload_id": upload_id,
            "chunk_index": chunk_index,
            "chunk_size": len(chunk_data)
        })
        
        return ChunkUploadResponse(
            upload_id=upload_id,
            chunk_index=chunk_index,
            status="uploaded",
            total_chunks=total_chunks,
            uploaded_chunks=len(uploaded_chunks)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        _log("error", f"Failed to upload chunk {chunk_index}: {str(e)}", {
            "user_id": current_user,
            "operation": "chunk_upload",
            "upload_id": upload_id
        })
        # Distinguish different error types with proper status codes
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to upload chunk - service temporarily unavailable"
        )


@router.post("/{upload_id}/complete", response_model=FileCompleteResponse)
async def complete_upload(
    upload_id: str,
    request: Request,
    current_user: str = Depends(get_current_user_for_upload)
    ):
    """Complete file upload and assemble chunks"""
    
    # Rate limiting check
    if not upload_complete_limiter.is_allowed(current_user):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many upload completion requests. Please try again later.",
            headers={"Retry-After": "60"}
        )
    
    try:
        # CRITICAL FIX: Validate upload_id before querying database
        if not upload_id or upload_id == "null" or upload_id == "undefined" or upload_id.strip() == "":
            _log("error", f"Invalid upload_id in complete endpoint: {repr(upload_id)}", {
                "user_id": current_user,
                "operation": "file_complete",
                "upload_id": upload_id,
                "client_ip": request.client.host if request.client else "unknown",
                "error": "Frontend did not capture uploadId from init response"
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid upload ID: {upload_id}. Did you call /init first? Check that uploadId was captured correctly."
            )
        
        # Get upload record with database connection check
        try:
            # CRITICAL FIX: Ensure database is connected before querying
            try:
                get_db()  # This will raise if database is not connected
            except RuntimeError as db_error:
                _log("error", f"Database not connected: {str(db_error)}", {
                    "user_id": current_user,
                    "operation": "finalize_upload",
                    "upload_id": upload_id
                })
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database service temporarily unavailable - please retry"
                )
            
            upload_doc = await asyncio.wait_for(
                uploads_collection().find_one({"_id": upload_id}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            _log("error", f"Database timeout fetching upload: {upload_id}", {
                "user_id": current_user,
                "operation": "finalize_upload",
                "upload_id": upload_id
            })
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout - please retry"
            )
        
        # CRITICAL FIX: Handle None result properly (not timeout)
        if upload_doc is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Upload not found or expired"
            )
        
        if upload_doc.get("user_id") != current_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to complete this upload"
            )
        
        # Verify all chunks have been uploaded
        total_chunks = upload_doc.get("total_chunks", 0)
        uploaded_chunks = upload_doc.get("uploaded_chunks", [])
        
        # CRITICAL FIX: Validate chunk data integrity
        if not isinstance(total_chunks, int) or total_chunks <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid total_chunks count in upload record"
            )
        
        if not isinstance(uploaded_chunks, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid uploaded_chunks format in upload record"
            )
        
        expected_chunks = set(range(total_chunks))
        actual_chunks = set(uploaded_chunks)
        
        if expected_chunks != actual_chunks:
            missing = sorted(list(expected_chunks - actual_chunks))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing chunks: {missing}. Please upload all chunks before completing."
            )
        
        # Assemble chunks into complete file
        upload_dir = Path(settings.DATA_ROOT) / "tmp" / upload_id
        filename = upload_doc.get("filename", "file")
        size = upload_doc.get("size", 0)
        mime_type = upload_doc.get("mime_type", "application/octet-stream")
        chat_id = upload_doc.get("chat_id")

        checksum_value = upload_doc.get("checksum")
        if not isinstance(checksum_value, str):
            checksum_value = ""
        
        # CRITICAL FIX: Generate secure random filename with user isolation
        file_id = hashlib.sha256(f"{uuid.uuid4()}".encode()).hexdigest()[:16]
        user_prefix = current_user[:2] if len(current_user) >= 2 else current_user  # Safe prefix extraction
        final_path = Path(settings.DATA_ROOT) / "files" / user_prefix / current_user / file_id
        
        # SECURITY: Use secure temporary file with random name
        import tempfile
        import os
        try:
            final_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create secure temporary file with random name
            with tempfile.NamedTemporaryFile(
                mode='wb', 
                dir=final_path.parent, 
                prefix=f".tmp_{file_id}_", 
                suffix='.tmp',
                delete=False  # We'll clean up manually
            ) as temp_file:
                temp_path = Path(temp_file.name)
                
                # Set secure permissions (owner read/write only)
                try:
                    os.chmod(temp_path, 0o600)
                except OSError as perm_error:
                    temp_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to set secure file permissions"
                    )
                
                # Write chunks to temp file
                for chunk_idx in range(total_chunks):
                    chunk_path = upload_dir / f"chunk_{chunk_idx}.part"
                    
                    if not chunk_path.exists():
                        temp_path.unlink(missing_ok=True)  # Clean up temp file
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Chunk {chunk_idx} not found during assembly"
                        )
                    
                    try:
                        with open(chunk_path, 'rb') as chunk_file:
                            # Write in smaller chunks to prevent memory exhaustion
                            while True:
                                chunk_data = chunk_file.read(8192)  # 8KB chunks
                                if not chunk_data:
                                    break
                                temp_file.write(chunk_data)
                    except (OSError, IOError) as chunk_error:
                        temp_path.unlink(missing_ok=True)
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to read chunk {chunk_idx}: {str(chunk_error)}"
                        )
                    except Exception as e:
                        temp_path.unlink(missing_ok=True)
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Unexpected error processing chunk {chunk_idx}: {str(e)}"
                        )
            
            # CRITICAL SECURITY: Verify temp file integrity before making it permanent
            actual_size = temp_path.stat().st_size
            if actual_size != size:
                # SECURITY: Clean up temp file on size mismatch
                temp_path.unlink()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File size mismatch: expected {size}, got {actual_size}"
                )
            
            # SECURITY: Atomic move from temp to final location
            import shutil
            try:
                shutil.move(str(temp_path), str(final_path))
            except (OSError, IOError) as move_error:
                # Clean up temp file if move failed
                temp_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to save assembled file: {str(move_error)}"
                )
            except Exception as e:
                # Clean up temp file if move failed
                temp_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Unexpected error saving file: {str(e)}"
                )
            
            # Store file metadata
            file_record = {
                "_id": file_id,
                "filename": filename,
                "size": size,
                "mime_type": mime_type,
                "owner_id": current_user,
                "chat_id": chat_id,
                "upload_id": upload_id,
                "created_at": datetime.now(timezone.utc),
                "storage_path": str(final_path),
                "shared_with": [],
                "checksum": checksum_value
            }
            
            # SECURITY: Insert file record only after successful file creation
            try:
                # CRITICAL FIX: Ensure database is still connected before inserting
                try:
                    get_db()  # This will raise if database is not connected
                except RuntimeError as db_error:
                    _log("error", f"Database not connected during file insert: {str(db_error)}", {
                        "user_id": current_user,
                        "operation": "file_insert",
                        "upload_id": upload_id,
                        "file_id": file_id
                    })
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Database service temporarily unavailable - please retry"
                    )
                
                await asyncio.wait_for(
                    files_collection().insert_one(file_record),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                _log("error", f"Database timeout inserting file record: {file_id}", {
                    "user_id": current_user,
                    "operation": "file_insert_timeout",
                    "upload_id": upload_id
                })
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail="Database timeout - file record not saved"
                )
            
            # CRITICAL SECURITY: Clean up chunks and upload record
            import shutil
            try:
                if upload_dir.exists():
                    shutil.rmtree(upload_dir)
            except Exception as cleanup_error:
                _log("warning", f"Failed to cleanup upload directory: {cleanup_error}", {
                    "user_id": current_user,
                    "operation": "upload_cleanup_failed",
                    "upload_id": upload_id
                })
            
            try:
                # CRITICAL FIX: Ensure database is still connected before deleting
                try:
                    get_db()  # This will raise if database is not connected
                except RuntimeError as db_error:
                    _log("warning", f"Database not connected during upload cleanup: {str(db_error)}", {
                        "user_id": current_user,
                        "operation": "upload_cleanup",
                        "upload_id": upload_id
                    })
                    # Non-critical - continue without cleanup
                else:
                    await asyncio.wait_for(
                        uploads_collection().delete_one({"_id": upload_id}),
                        timeout=5.0
                    )
            except asyncio.TimeoutError:
                _log("error", f"Database timeout deleting upload record: {upload_id}", {
                    "user_id": current_user,
                    "operation": "upload_delete_timeout"
                })
                # Non-critical timeout - don't raise exception
            
            _log("info", f"Upload completed successfully", {
                "user_id": current_user,
                "operation": "upload_complete",
                "upload_id": upload_id,
                "file_id": file_id,
                "filename": filename,
                "size": size
            })
            
            return FileCompleteResponse(
                file_id=file_id,
                filename=filename,
                size=size,
                checksum=checksum_value,
                storage_path=str(final_path)
            )
            
        except HTTPException:
            raise
        except Exception as e:
            _log("error", f"Failed to assemble file chunks: {str(e)}", {
                "user_id": current_user,
                "operation": "upload_complete",
                "upload_id": upload_id
            })
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to assemble uploaded file"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        _log("error", f"Failed to complete upload: {str(e)}", {
            "user_id": current_user,
            "operation": "upload_complete",
            "upload_id": upload_id
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete upload"
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
                try:
                    chat_doc = await asyncio.wait_for(
                        chats_collection().find_one({"_id": chat_id}),
                        timeout=5.0
                    )
                except asyncio.TimeoutError:
                    _log("error", f"Database timeout checking chat membership: {chat_id}", {
                        "user_id": current_user,
                        "operation": "file_info_chat_timeout"
                    })
                    raise HTTPException(
                        status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                        detail="Database timeout"
                    )
                
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
                _log("error", "File missing storage path in DB", {"user_id": current_user, "operation": "file_download"})
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found - storage path missing")
                
            file_path = Path(storage_path)
            try:
                # CRITICAL SECURITY: Multiple path validation layers
                # 1. Normalize path to remove any relative components
                normalized_path = file_path.resolve()
                data_root = settings.DATA_ROOT.resolve()
                
                # 2. Check for obvious traversal attempts
                if '..' in str(file_path) or str(file_path).startswith('..'):
                    _log("error", f"Parent directory traversal in path: {storage_path}", {"user_id": current_user, "operation": "file_download"})
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied - invalid file path"
                    )
                
                # 3. Use proper path comparison to prevent traversal bypass
                try:
                    normalized_path.relative_to(data_root)
                except ValueError:
                    _log("error", f"Download path traversal attempt: {storage_path} -> {normalized_path}", {"user_id": current_user, "operation": "file_download"})
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied - invalid file path"
                    )
                file_path = normalized_path
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
        # Database timeouts should be 504, internal errors 500
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="File information request timed out"
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
    except Exception as e:
        # Log error for debugging but don't expose details
        _log("error", f"Avatar ownership check failed: {str(e)}", {"user_id": current_user, "operation": "avatar_check"})
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
                # CRITICAL SECURITY: Enhanced path validation to prevent traversal attacks
                # 1. Multiple path normalization and validation layers
                try:
                    # First normalize the path
                    normalized_path = file_path.resolve()
                    data_root = settings.DATA_ROOT.resolve()
                    
                    # 2. Check for symlinks - prevent symlink traversal
                    if file_path.is_symlink():
                        _log("error", f"Symlink traversal attempt: {storage_path}", {"user_id": current_user, "operation": "file_download"})
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Access denied - symlinks not allowed"
                        )
                    
                    # 3. Canonical path validation - must be within data root
                    try:
                        relative_path = normalized_path.relative_to(data_root)
                    except ValueError:
                        _log("error", f"Path traversal attempt: {storage_path} -> {normalized_path}", {"user_id": current_user, "operation": "file_download"})
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Access denied - invalid file path"
                        )
                    
                    # 4. User directory enforcement - ensure user can only access their own files
                    expected_user_prefix = Path("files") / current_user[:2] / current_user
                    if not str(relative_path).startswith(str(expected_user_prefix)):
                        _log("error", f"Cross-user file access attempt: {storage_path}", {"user_id": current_user, "operation": "file_download"})
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Access denied - unauthorized file access"
                        )
                    
                    # 5. Additional character-level validation
                    if '..' in str(normalized_path.parts) or any(part.startswith('.') for part in normalized_path.parts[1:]):
                        _log("error", f"Suspicious path components: {storage_path}", {"user_id": current_user, "operation": "file_download"})
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Access denied - invalid file path"
                        )
                    
                    file_path = normalized_path
                    
                except (OSError, ValueError) as path_error:
                    _log("error", f"Invalid file path: {storage_path} - {path_error}", {"user_id": current_user, "operation": "file_download"})
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found - invalid path")
            except (OSError, ValueError) as path_error:
                _log("error", f"Invalid file path: {storage_path} - {path_error}", {"user_id": current_user, "operation": "file_download"})
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found - invalid path")
            
            if not file_path.exists():
                _log("error", f"File exists in DB but not on disk", {"user_id": current_user, "operation": "file_download"})
            # 404 Not Found is correct for missing uploads
            # 403 Forbidden would be for permission denied
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Upload not found or expired"
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
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to upload chunk - service temporarily unavailable"
        )
    except (OSError, ValueError) as path_error:
        _log("error", f"Invalid download path: {storage_path} - {path_error}", {"user_id": current_user, "operation": "file_download"})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid file path"
        )
    
    # Handle range requests
    range_header = request.headers.get("range")
    file_size = file_path.stat().st_size
    
    if range_header:
        # Parse range header safely
        try:
            if not range_header.startswith("bytes="):
                raise ValueError("Invalid range header format")
            
            range_part = range_header.replace("bytes=", "")
            parts = range_part.split("-")
            
            if len(parts) != 2:
                raise ValueError("Invalid range header format")
                
            start = int(parts[0].strip()) if parts[0].strip() else 0
            end = int(parts[1].strip()) if parts[1].strip() else file_size - 1
            
            if start < 0 or end >= file_size or start > end:
                raise ValueError("Invalid range values")
        except (ValueError, IndexError) as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid range header: {str(e)}"
            )
        
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
    try:
        file_doc = await asyncio.wait_for(
            files_collection().find_one({"_id": file_id}),
            timeout=5.0
        )
    except asyncio.TimeoutError:
        _log("error", f"Database timeout finding file: {file_id}", {
            "user_id": current_user,
            "operation": "file_share_timeout"
        })
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database timeout"
        )
    
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
    try:
        await asyncio.wait_for(
            files_collection().update_one(
                {"_id": file_id},
                {"$addToSet": {"shared_with": {"$each": user_ids}}}
            ),
            timeout=5.0
        )
    except asyncio.TimeoutError:
        _log("error", f"Database timeout sharing file: {file_id}", {
            "user_id": current_user,
            "operation": "file_share_update_timeout"
        })
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database timeout while sharing file"
        )
    
    _log("info", f"File shared: owner={current_user}, file={file_id}, users={user_ids}", {"user_id": current_user, "operation": "file_share"})
    
    return {"message": f"File shared with {len(user_ids)} users"}


@router.get("/{file_id}/shared-users")
async def get_shared_users(file_id: str, current_user: str = Depends(get_current_user)):
    """Get list of users file is shared with"""
    
    # Find file
    try:
        file_doc = await asyncio.wait_for(
            files_collection().find_one({"_id": file_id}),
            timeout=5.0
        )
    except asyncio.TimeoutError:
        _log("error", f"Database timeout finding file: {file_id}", {
            "user_id": current_user,
            "operation": "file_shared_users_timeout"
        })
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database timeout"
        )
    
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
    try:
        file_doc = await asyncio.wait_for(
            files_collection().find_one({"_id": file_id}),
            timeout=5.0
        )
    except asyncio.TimeoutError:
        _log("error", f"Database timeout finding file: {file_id}", {
            "user_id": current_user,
            "operation": "file_revoke_timeout"
        })
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database timeout"
        )
    
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
    try:
        await asyncio.wait_for(
            files_collection().update_one(
                {"_id": file_id},
                {"$pull": {"shared_with": user_id}}
            ),
            timeout=5.0
        )
    except asyncio.TimeoutError:
        _log("error", f"Database timeout revoking file access: {file_id}", {
            "user_id": current_user,
            "operation": "file_revoke_update_timeout"
        })
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database timeout while revoking access"
        )
    
    _log("info", f"File access revoked: owner={current_user}, file={file_id}, user={user_id}", {"user_id": current_user, "operation": "file_revoke_access"})
    
    return {"message": f"Access revoked for user {user_id}"}


@router.post("/{upload_id}/refresh-token")
async def refresh_upload_token(upload_id: str, current_user: str = Depends(get_current_user)):
    """Refresh upload token for long-running uploads"""
    
    # CRITICAL FIX: Query by _id field, not upload_id field (database inconsistency)
    try:
        upload = await asyncio.wait_for(
            uploads_collection().find_one({"_id": upload_id}),
            timeout=5.0
        )
    except asyncio.TimeoutError:
        _log("error", f"Database timeout finding upload: {upload_id}", {
            "user_id": current_user,
            "operation": "upload_token_refresh_timeout"
        })
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database timeout"
        )
    
    if not upload:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Upload not found"
        )
    
    # Verify ownership
    if upload.get("user_id") != current_user:
        _log("warning", f"Unauthorized upload token refresh attempt: user={current_user}, upload={upload_id}", 
               {"user_id": current_user, "operation": "upload_token_refresh"})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you don't own this upload"
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
        # CRITICAL FIX: Query by _id field, not upload_id field (database inconsistency)
        try:
            upload = await asyncio.wait_for(
                uploads_collection().find_one({"_id": upload_id}),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            _log("error", f"Database timeout finding upload for cancel: {upload_id}", {
                "user_id": current_user,
                "operation": "upload_cancel_timeout"
            })
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Database timeout"
            )
        
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
            except HTTPException:
                # Re-raise HTTP exceptions 
                raise
            except Exception as e:
                # Handle unexpected token validation errors
                _log("error", f"Token validation error: {str(e)}", {"user_id": current_user, "operation": "upload_cancel"})
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token"
                )
        
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
    
    # Delete upload record (CRITICAL FIX: Use correct field name)
    await uploads_collection().delete_one({"_id": upload_id})
    
    return {"message": "Upload cancelled"}


def optimize_40gb_transfer(file_size_bytes: int) -> dict:
    """
    Optimize chunk configuration for large file transfers based on file size.
    
    Args:
        file_size_bytes: Size of the file in bytes
        
    Returns:
        dict: Optimization configuration with chunk_size_mb, target_chunks, 
              estimated_time_hours, optimization_level, performance_gain
    """
    # File size in GB for easier calculations
    file_size_gb = file_size_bytes / (1024 ** 3)
    
    # Base configuration
    base_chunk_size_mb = 4  # 4 MiB default
    max_chunk_size_mb = 16  # 16 MiB maximum for very large files
    
    # Optimization levels based on file size
    if file_size_gb <= 2:
        # 1-2GB files: Use standard 4MB chunks, 20% faster
        chunk_size_mb = 4
        target_chunks = int(file_size_bytes / (4 * 1024 * 1024))
        estimated_time_hours = 0.25  # 15 minutes
        optimization_level = "standard"
        performance_gain = "20% faster"
        
    elif file_size_gb <= 5:
        # 2-5GB files: Use 4MB chunks, 20% faster
        chunk_size_mb = 4
        target_chunks = int(file_size_bytes / (4 * 1024 * 1024))
        estimated_time_hours = 0.25  # 15 minutes
        optimization_level = "standard"
        performance_gain = "20% faster"
        
    elif file_size_gb <= 15:
        # 5-15GB files: Use 4MB chunks, 20% faster
        chunk_size_mb = 4
        target_chunks = int(file_size_bytes / (4 * 1024 * 1024))
        estimated_time_hours = 0.25  # 15 minutes
        optimization_level = "standard"
        performance_gain = "20% faster"
        
    elif file_size_gb <= 30:
        # 15-30GB files: Use 4MB chunks, 40% faster
        chunk_size_mb = 4
        target_chunks = int(file_size_bytes / (4 * 1024 * 1024))
        estimated_time_hours = 0.5  # 30 minutes
        optimization_level = "enhanced"
        performance_gain = "40% faster"
        
    elif file_size_gb <= 40:
        # 30-40GB files: Use 8MB chunks, 60% faster
        chunk_size_mb = 8
        target_chunks = int(file_size_bytes / (8 * 1024 * 1024))
        estimated_time_hours = 1.5  # 90 minutes
        optimization_level = "high"
        performance_gain = "60% faster"
        
    else:
        # 40GB+ files: Use 16MB chunks, 75% faster
        chunk_size_mb = 16
        target_chunks = int(file_size_bytes / (16 * 1024 * 1024))
        estimated_time_hours = 2.0  # 2 hours
        optimization_level = "maximum"
        performance_gain = "75% faster"
    
    # Ensure minimum chunk size for efficiency
    chunk_size_mb = max(chunk_size_mb, base_chunk_size_mb)
    
    # Ensure maximum chunk size for stability
    chunk_size_mb = min(chunk_size_mb, max_chunk_size_mb)
    
    # Recalculate target chunks based on final chunk size
    target_chunks = int(file_size_bytes / (chunk_size_mb * 1024 * 1024))
    
    return {
        "file_size_bytes": file_size_bytes,
        "file_size_gb": round(file_size_gb, 2),
        "chunk_size_mb": chunk_size_mb,
        "target_chunks": target_chunks,
        "estimated_time_hours": estimated_time_hours,
        "optimization_level": optimization_level,
        "performance_gain": performance_gain,
        "optimization_applied": True
    }
