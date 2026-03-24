#!/usr/bin/env python3
"""
Direct test to bypass error handlers and see the actual error
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

import asyncio
from fastapi import Request
from unittest.mock import MagicMock
from routes.files import init_photo_video_upload

async def test_direct():
    # Create a mock request
    mock_request = MagicMock()
    mock_request.method = "POST"
    mock_request.url.path = "/api/v1/attach/photos-videos/init"
    mock_request.headers = {"user-agent": "testclient", "content-type": "application/json"}
    
    # Mock the JSON method to return our payload
    payload = {
        'file_name': 'direct_test.jpg',
        'file_size': 1024,
        'chat_id': '507f1f77bcf86cd799439011',
        'mime_type': 'image/jpeg'
    }
    
    async def mock_json():
        return payload
    
    mock_request.json = mock_json
    
    print('Testing direct function call...')
    print(f'Payload: {payload}')
    
    try:
        result = await init_photo_video_upload(mock_request, None)
        print(f'Success: {result}')
    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_direct())
