#!/usr/bin/env python3
"""
Production test for upload initialization endpoint
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from main import app

def test_production_upload():
    client = TestClient(app)
    
    # Test valid upload initialization
    valid_payload = {
        'file_name': 'production_test.jpg',
        'file_size': 2048000,
        'chat_id': '507f1f77bcf86cd799439011',
        'mime_type': 'image/jpeg'
    }
    
    print('Testing production upload initialization...')
    response = client.post('/api/v1/attach/photos-videos/init', json=valid_payload)
    
    # Assert the response status code
    assert response.status_code in [200, 201], f"Expected success status (200/201), got {response.status_code}: {response.text}"
    
    # Assert the response contains expected fields
    data = response.json()
    assert "uploadId" in data or "upload_id" in data, "Response missing upload ID"
    assert "file_id" in data, "Response missing file ID"
    assert "upload_url" in data, "Response missing upload URL"
    
    print('✅ SUCCESS: Upload initialized successfully')
    print(f'Upload ID: {data.get("uploadId", data.get("upload_id", "N/A"))}')
    print(f'File ID: {data.get("file_id", "N/A")}')
    upload_url = data.get('upload_url', 'N/A')
    url_preview = upload_url[:50] + '...' if len(str(upload_url)) > 50 else upload_url
    print(f'Upload URL: {url_preview}')

if __name__ == "__main__":
    test_production_upload()
