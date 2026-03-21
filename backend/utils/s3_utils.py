"""
S3 utilities for status uploads
Reuses existing S3 infrastructure from files.py
"""
import uuid
from typing import Optional
from backend.config import settings
from backend.routes.files import _get_s3_client


def upload_file_to_s3(
    file_content: bytes,
    file_key: str,
    content_type: str
) -> str:
    """
    Upload file to S3 and return the file key
    CRITICAL: Validates S3 upload succeeds before returning file_key
    Reuses existing S3 client infrastructure (synchronous boto3)
    """
    try:
        s3_client = _get_s3_client()
        if not s3_client:
            # Log and raise - don't fallback silently
            import logging
            logger = logging.getLogger(__name__)
            error_msg = "S3 client not available - cannot upload file"
            logger.error(f"[S3_UPLOAD] {error_msg}")
            raise ValueError(error_msg)
        
        # Validate S3_BUCKET is configured
        if not settings.S3_BUCKET:
            import logging
            logger = logging.getLogger(__name__)
            error_msg = f"S3_BUCKET not configured in settings"
            logger.error(f"[S3_UPLOAD] {error_msg}")
            raise ValueError(error_msg)
        
        print(f"[S3_UPLOAD] Uploading file: {file_key} (size: {len(file_content)} bytes) to bucket: {settings.S3_BUCKET}")
        
        # CRITICAL: Upload to S3 (synchronous call with sync boto3 client)
        # Verify content is bytes
        if not isinstance(file_content, bytes):
            raise ValueError(f"file_content must be bytes, got {type(file_content)}")
        
        response = s3_client.put_object(
            Bucket=settings.S3_BUCKET,
            Key=file_key,
            Body=file_content,
            ContentType=content_type,
            Metadata={
                'uploaded-by': 'hypersend-status',
                'content-type': content_type,
                'file-size': str(len(file_content))
            }
        )
        
        print(f"[S3_UPLOAD] Successfully uploaded: {file_key}")
        print(f"[S3_UPLOAD] S3 response: ETag={response.get('ETag')}, VersionId={response.get('VersionId')}")
        
        # Verify file was actually uploaded by checking if it exists
        try:
            s3_client.head_object(Bucket=settings.S3_BUCKET, Key=file_key)
            print(f"[S3_UPLOAD] Verified file exists in S3: {file_key}")
        except Exception as e:
            print(f"[S3_UPLOAD] WARNING: Could not verify file upload: {str(e)}")
        
        return file_key
        
    except Exception as e:
        # Log error with full context
        import logging
        logger = logging.getLogger(__name__)
        print(f"[S3_UPLOAD] ERROR: S3 upload failed for key {file_key}: {str(e)}")
        logger.error(f"[S3_UPLOAD] S3 upload failed for key {file_key}: {str(e)}", exc_info=True)
        # CRITICAL: Re-raise to prevent silent failures
        raise


def delete_object(bucket: str, file_key: str) -> bool:
    """
    Delete an object from S3
    Reuses existing S3 client infrastructure
    """
    try:
        s3_client = _get_s3_client()
        if not s3_client:
            # Fallback for testing/mock mode
            return True
        
        s3_client.delete_object(
            Bucket=bucket,
            Key=file_key
        )
        
        return True
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"S3 delete failed for key {file_key}: {str(e)}", exc_info=True)
        raise  # Re-raise to let caller decide how to handle


def generate_status_media_url(file_key: str) -> str:
    """
    Generate media URL for status files
    Uses existing media endpoint pattern
    """
    return f"{settings.API_BASE_URL}/media/{file_key}"
