#!/usr/bin/env python3
"""
Test script to verify MIME type preservation in S3 uploads
"""
import requests
import json
import base64
import os
from pathlib import Path

# Configuration
BASE_URL = "https://zaply.in.net/api/v1"  # Using production URL as per .env
USERNAME = "test@example.com"
PASSWORD = "TestPassword123!"

def login():
    """Login and get auth token"""
    response = requests.post(f"{BASE_URL}/auth/login", json={
        "email": USERNAME,
        "password": PASSWORD
    })
    
    if response.status_code not in [200, 201]:
        print(f"Login failed: {response.status_code} - {response.text}")
        return None
    
    token_data = response.json()
    return token_data.get("access_token")

def test_file_upload():
    """Test file upload with MIME type preservation"""
    # Login first
    token = login()
    if not token:
        print("Failed to login")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: Upload JPEG image
    print("\n=== Testing JPEG Upload ===")
    
    # Create a simple JPEG file header
    jpeg_data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.\' \",#\x1c\x1c(7),01444\x1f\'9=82<.342\xff\xc0\x00\x11\x08\x00\x01\x00\x01\x01\x01\x11\x00\x02\x11\x01\x03\x11\x01\xff\xc4\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00\xaa\xff\xd9'
    
    # Initialize upload
    init_data = {
        "file_name": "test-image.jpg",
        "file_size": len(jpeg_data),
        "mime_type": "image/jpeg",
        "chat_id": "test-chat-123"
    }
    
    response = requests.post(f"{BASE_URL}/attach/photos-videos/init", 
                         json=init_data, headers=headers)
    
    if response.status_code != 200:
        print(f"Upload init failed: {response.status_code} - {response.text}")
        return
    
    init_result = response.json()
    upload_id = init_result.get("upload_id")
    print(f"Upload initialized with ID: {upload_id}")
    
    # Upload chunk
    files = {"chunk_data": ("chunk", jpeg_data, "image/jpeg")}
    params = {
        "token": upload_id,
        "media_key": base64.b64encode(b"test-media-key").decode(),
        "chunk_index": 0
    }
    
    response = requests.post(f"{BASE_URL}/files/upload-chunk", 
                         files=files, params=params, headers=headers)
    
    if response.status_code != 200:
        print(f"Chunk upload failed: {response.status_code} - {response.text}")
        return
    
    print("Chunk uploaded successfully!")
    
    # Complete upload
    response = requests.post(f"{BASE_URL}/complete-upload", 
                         json={"upload_id": upload_id}, headers=headers)
    
    if response.status_code != 200:
        print(f"Upload completion failed: {response.status_code} - {response.text}")
        return
    
    print("Upload completed successfully!")
    
    # Test download to verify MIME type
    # Get file ID from database (this would need to be implemented)
    # For now, let's just verify the S3 object directly
    print("\n=== Verifying S3 Object MIME Type ===")
    
    # Use AWS CLI to check the object metadata
    os.system(f"aws s3api head-object --bucket zaply-object-storage-781953767677-us-east-1-an --key media/$(date +%Y%m%d)/{upload_id} --query ContentType")

if __name__ == "__main__":
    test_file_upload()
