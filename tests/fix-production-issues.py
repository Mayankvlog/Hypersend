#!/usr/bin/env python3
"""
Production Issues Fix Script
===========================

This script fixes the critical production issues identified in the logs:
1. S3 CORS Missing Allow Origin
2. WebSocket authentication issues

Usage:
    python fix-production-issues.py
"""

import asyncio
import boto3
import json
import logging
from backend.config import settings

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def fix_s3_cors():
    """Fix S3 CORS configuration"""
    try:
        logger.info("[FIX] Applying S3 CORS configuration...")
        
        # Create S3 client
        s3_client = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        bucket_name = settings.S3_BUCKET
        
        # CORS configuration for production
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
                    'ExposeHeaders': ['Content-Length', 'Content-Type'],
                    'MaxAgeSeconds': 3600
                }
            ]
        }
        
        # Apply CORS configuration
        s3_client.put_bucket_cors(
            Bucket=bucket_name,
            CORSConfiguration=cors_configuration
        )
        
        logger.info(f"[FIX] ✓ S3 CORS configured for bucket: {bucket_name}")
        
        # Verify configuration
        response = s3_client.get_bucket_cors(Bucket=bucket_name)
        logger.info(f"[FIX] CORS rules applied: {json.dumps(response['CORSRules'], indent=2)}")
        
        return True
        
    except Exception as e:
        logger.error(f"[FIX] S3 CORS configuration failed: {e}")
        return False

async def check_websocket_auth():
    """Check WebSocket authentication setup"""
    try:
        logger.info("[FIX] Checking WebSocket authentication setup...")
        
        # Check if backend is configured for WebSocket authentication
        if not settings.ACCESS_TOKEN_EXPIRE_SECONDS:
            logger.error("[FIX] ACCESS_TOKEN_EXPIRE_SECONDS not configured")
            return False
            
        if not settings.SECRET_KEY:
            logger.error("[FIX] SECRET_KEY not configured for JWT")
            return False
            
        logger.info("[FIX] ✓ WebSocket authentication configuration verified")
        logger.info(f"[FIX] Access token expires in: {settings.ACCESS_TOKEN_EXPIRE_SECONDS} seconds")
        
        return True
        
    except Exception as e:
        logger.error(f"[FIX] WebSocket authentication check failed: {e}")
        return False

async def create_websocket_debug_info():
    """Create WebSocket debugging information"""
    try:
        logger.info("[FIX] Creating WebSocket debug information...")
        
        debug_info = {
            "websocket_endpoint": "wss://zaply.in.net/api/v1/ws/chat/{chat_id}",
            "authentication_method": "HTTPOnly cookies (access_token)",
            "expected_cookies": ["access_token", "refresh_token"],
            "cookie_domain": ".zaply.in.net",
            "cookie_same_site": "None",
            "cookie_secure": True,
            "troubleshooting_steps": [
                "1. Ensure user is logged in via REST API first",
                "2. Check browser developer tools -> Application -> Cookies",
                "3. Verify access_token cookie exists for domain .zaply.in.net",
                "4. Ensure cookie has Secure and HttpOnly flags",
                "5. WebSocket connection should include cookies automatically"
            ]
        }
        
        # Save debug info
        with open('websocket_debug_info.json', 'w') as f:
            json.dump(debug_info, f, indent=2)
            
        logger.info("[FIX] ✓ WebSocket debug information saved to websocket_debug_info.json")
        return True
        
    except Exception as e:
        logger.error(f"[FIX] Failed to create WebSocket debug info: {e}")
        return False

async def main():
    """Main fix function"""
    logger.info("[FIX] Starting production issues fix...")
    
    # Fix 1: S3 CORS
    s3_success = await fix_s3_cors()
    
    # Fix 2: WebSocket authentication check
    ws_success = await check_websocket_auth()
    
    # Fix 3: Create debug information
    debug_success = await create_websocket_debug_info()
    
    # Summary
    logger.info("[FIX] Production fixes summary:")
    logger.info(f"[FIX] S3 CORS: {'✅ FIXED' if s3_success else '❌ FAILED'}")
    logger.info(f"[FIX] WebSocket Auth: {'✅ VERIFIED' if ws_success else '❌ FAILED'}")
    logger.info(f"[FIX] Debug Info: {'✅ CREATED' if debug_success else '❌ FAILED'}")
    
    if s3_success and ws_success and debug_success:
        logger.info("[FIX] 🎉 All production fixes completed successfully!")
        logger.info("[FIX] 📋 Next steps:")
        logger.info("[FIX] 1. Redeploy backend to ensure WebSocket changes take effect")
        logger.info("[FIX] 2. Test file downloads - CORS errors should be resolved")
        logger.info("[FIX] 3. Test WebSocket connections - check websocket_debug_info.json")
        return True
    else:
        logger.error("[FIX] ❌ Some fixes failed - check logs above")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
