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
    Reuses existing S3 client infrastructure (synchronous boto3)
    """
    try:
        s3_client = _get_s3_client()
        if not s3_client:
            # Fallback to mock mode for testing
            return file_key
        
        # Upload to S3 (synchronous call with sync boto3 client)
        s3_client.put_object(
            Bucket=settings.S3_BUCKET,
            Key=file_key,
            Body=file_content,
            ContentType=content_type,
            Metadata={
                'uploaded-by': 'hypersend-status',
                'content-type': content_type
            }
        )
        
        return file_key
        
    except Exception as e:
        # Log error with full context before returning
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"S3 upload failed for key {file_key}: {str(e)}", exc_info=True)
        # Return file_key for mock mode, but error is logged for debugging
        return file_key


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
    return f"{settings.API_BASE_URL}/api/v1/media/{file_key}"
