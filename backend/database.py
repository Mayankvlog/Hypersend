import os
import random
import secrets
import threading
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import HTTPException, status
from config import settings

client = None
db = None


async def connect_db():
    """Connect to MongoDB with improved retry logic and exponential backoff for VPS"""
    global client, db
    max_retries = 5
    initial_retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            # Create client with extended timeouts for VPS connectivity
            client = AsyncIOMotorClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=30000,  # Increased to 30 seconds for Linux VPS compatibility
                connectTimeoutMS=30000,  # Increased for slower Linux connections
                socketTimeoutMS=60000,   # Increased for large file operations
                retryWrites=True,
                maxPoolSize=50,
                minPoolSize=10,
                # Linux-specific connection settings
                compressors=["zlib"],  # Fix: compressors should be a list, not string
                zlibCompressionLevel=6  # Balanced compression level
            )
            # Test the connection
            await client.admin.command('ping')
            db = client[settings._MONGO_DB]
            
            if settings.DEBUG:
                try:
                    safe_uri = settings.MONGODB_URI.split("@")[-1]
                except Exception as e:
                    safe_uri = "[redacted]"
                    if settings.DEBUG:
                        print(f"[DEBUG] URI parse error: {e}")
                print(f"[OK] Connected to MongoDB: {safe_uri}")
            return
            
        except ConnectionError as e:
            # Database connectivity issues should return 503 Service Unavailable
            error_msg = str(e)
            print(f"[ERROR] MongoDB connection attempt {attempt + 1}/{max_retries} failed")
            print(f"[ERROR] Details: {error_msg}")
            
            if attempt < max_retries - 1:
                import asyncio
                import math
                import random
                import secrets
                # ENHANCED: Better exponential backoff with proper jitter
                retry_delay = initial_retry_delay * (2 ** attempt)
                # Add cryptographic jitter using secrets for better distribution
                # Fix: secrets.randbelow() takes only one argument (upper bound)
                jitter_range = 0.4  # 0.1 to 0.5 range = 0.4 total range
                jitter = (secrets.randbelow(int(jitter_range * 1000)) / 1000 + 0.1) * retry_delay
                retry_delay = min(retry_delay + jitter, 60)  # Cap at 60 seconds
                # Single error message per retry attempt
                print(f"[ERROR] Retrying in {retry_delay:.1f} seconds...")
                await asyncio.sleep(retry_delay)
                continue
            else:
                print("[ERROR] All connection attempts failed. Troubleshooting steps:")
                print("  1. Verify MongoDB container is running: docker ps | grep mongodb")
                print("  2. Check MongoDB logs: docker logs hypersend_mongodb")
                print("  3. Verify credentials: MONGO_USER, MONGO_PASSWORD in docker-compose.yml")
                print(f"  4. Check host:port connectivity: {settings._MONGO_HOST}:{settings._MONGO_PORT}")
                print("  5. Ensure MongoDB is bound to 0.0.0.0 (check: mongod --bind_ip 0.0.0.0)")
                print("  6. For VPS, verify firewall allows MongoDB port")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database service temporarily unavailable"
                )
        except TimeoutError as e:
            # Database timeout should return 504 Gateway Timeout
            print(f"[ERROR] MongoDB connection timeout on attempt {attempt + 1}")
            if attempt >= max_retries - 1:
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail="Database connection timeout"
                )
            else:
                import asyncio
                retry_delay = 5.0
                print(f"[ERROR] Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                continue
        except Exception as e:
            error_msg = str(e)
            print(f"[ERROR] MongoDB connection attempt {attempt + 1}/{max_retries} failed")
            print(f"[ERROR] Details: {error_msg}")
            
            if attempt < max_retries - 1:
                import asyncio
                import math
                import random
                import secrets
                # ENHANCED: Better exponential backoff with proper jitter
                retry_delay = initial_retry_delay * (2 ** attempt)
                # Add cryptographic jitter using secrets for better distribution
                # Fix: secrets.randbelow() takes only one argument (upper bound)
                jitter_range = 0.4  # 0.1 to 0.5 range = 0.4 total range
                jitter = (secrets.randbelow(int(jitter_range * 1000)) / 1000 + 0.1) * retry_delay
                retry_delay = min(retry_delay + jitter, 60)  # Cap at 60 seconds
                # Single error message per retry attempt
                print(f"[ERROR] Retrying in {retry_delay:.1f} seconds...")
                await asyncio.sleep(retry_delay)
                continue
            else:
                print("[ERROR] All connection attempts failed. Troubleshooting steps:")
                print("  1. Verify MongoDB container is running: docker ps | grep mongodb")
                print("  2. Check MongoDB logs: docker logs hypersend_mongodb")
                print("  3. Verify credentials: MONGO_USER, MONGO_PASSWORD in docker-compose.yml")
                print(f"  4. Check host:port connectivity: {settings._MONGO_HOST}:{settings._MONGO_PORT}")
                print("  5. Ensure MongoDB is bound to 0.0.0.0 (check: mongod --bind_ip 0.0.0.0)")
                print("  6. For VPS, verify firewall allows MongoDB port")
                raise


async def close_db():
    """Close MongoDB connection with proper error handling"""
    global client
    if client:
        try:
            client.close()
            if settings.DEBUG:
                print("[CLOSE] MongoDB connection closed")
        except Exception as e:
            # Log error but don't raise - cleanup should continue
            if settings.DEBUG:
                print(f"[ERROR] Failed to close MongoDB connection: {str(e)}")
            else:
                # In production, log to proper logging system
                import logging
                logging.getLogger(__name__).error(f"Database connection close error: {str(e)}")
    # Always clear the global reference
    client = None


def get_db():
    """Get database instance"""
    if db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return db


# Collection shortcuts
def users_collection():
    database = get_db()
    return database.users


def chats_collection():
    database = get_db()
    return database.chats


def messages_collection():
    database = get_db()
    return database.messages


def files_collection():
    database = get_db()
    return database.files


def uploads_collection():
    database = get_db()
    return database.uploads


def refresh_tokens_collection():
    database = get_db()
    return database.refresh_tokens


def reset_tokens_collection():
    database = get_db()
    return database.reset_tokens


def group_activity_collection():
    database = get_db()
    return database.group_activity

