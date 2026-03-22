"""
S3 utilities
"""
import logging

# NOTE: The legacy Status feature has been removed.
# This module remains as a small compatibility shim for any leftover imports.
# All S3 logic should live in backend.routes.files.

from backend.routes.files import _get_s3_client

# Create logger for this module
logger = logging.getLogger(__name__)


def generate_presigned_url(file_key: str, expiration: int = 3600) -> str:
    """
    Generate a presigned URL for S3 file download
    """
    try:
        from backend.config import settings, TESTING

        # Check if we're in testing mode and use mock URL
        if TESTING:
            mock_url = f"http://mock-s3-test-server/{file_key}"
            logger.info(f"[S3_PRESIGNED] MOCK: Using mock presigned URL for {file_key}")
            return mock_url

        s3_client = _get_s3_client()
        if not s3_client:
            raise ValueError("S3 client not available")
        
        if not settings.S3_BUCKET:
            raise ValueError("S3_BUCKET not configured")
        
        # Generate presigned URL for download
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': settings.S3_BUCKET, 'Key': file_key},
            ExpiresIn=expiration
        )
        
        logger.info(f"[S3_PRESIGNED] Generated URL for {file_key}, expires in {expiration}s")
        return url
        
    except Exception as e:
        logger.error(f"[S3_PRESIGNED] Error generating presigned URL: {e}")
        # Fallback to direct URL if presigned fails
        return f"{settings.API_BASE_URL}/media/{file_key}"


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
