#!/usr/bin/env python3
"""
S3 CORS Configuration Fix
=========================

This script configures CORS for the S3 bucket to allow direct file downloads
from the frontend domain.

Usage:
    python fix-s3-cors.py
"""

import boto3
import json
import logging
from backend.config import settings

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def configure_s3_cors():
    """Configure CORS for S3 bucket"""
    try:
        # Create S3 client
        s3_client = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        bucket_name = settings.S3_BUCKET
        logger.info(f"[S3_CORS] Configuring CORS for bucket: {bucket_name}")
        
        # CORS configuration
        cors_configuration = {
            'CORSRules': [
                {
                    'AllowedHeaders': ['*'],
                    'AllowedMethods': ['GET', 'HEAD'],
                    'AllowedOrigins': [
                        'https://zaply.in.net',
                        'https://www.zaply.in.net',
                        'http://localhost:3000',
                        'http://localhost:8080'
                    ],
                    'ExposeHeaders': [],
                    'MaxAgeSeconds': 3600
                }
            ]
        }
        
        # Apply CORS configuration
        s3_client.put_bucket_cors(
            Bucket=bucket_name,
            CORSConfiguration=cors_configuration
        )
        
        logger.info(f"[S3_CORS] ✓ CORS configuration applied successfully to {bucket_name}")
        
        # Verify configuration
        response = s3_client.get_bucket_cors(Bucket=bucket_name)
        logger.info(f"[S3_CORS] Current CORS rules: {json.dumps(response['CORSRules'], indent=2)}")
        
        return True
        
    except Exception as e:
        logger.error(f"[S3_CORS] Failed to configure CORS: {e}")
        return False

if __name__ == "__main__":
    success = configure_s3_cors()
    if success:
        print("✅ S3 CORS configuration completed successfully")
    else:
        print("❌ Failed to configure S3 CORS")
        exit(1)
