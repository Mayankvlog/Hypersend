#!/usr/bin/env python3
"""
Debug test to identify the ValueError source
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from main import app

def debug_upload():
    client = TestClient(app)
    
    # Test with minimal payload
    minimal_payload = {
        'file_name': 'debug.jpg',
        'file_size': 1024,
        'chat_id': '507f1f77bcf86cd799439011',
        'mime_type': 'image/jpeg'
    }
    
    print('Testing minimal payload...')
    print(f'Payload: {minimal_payload}')
    
    try:
        response = client.post('/api/v1/attach/photos-videos/init', json=minimal_payload)
        print(f'Status Code: {response.status_code}')
        print(f'Response: {response.text[:500]}...')
    except Exception as e:
        print(f'Exception during request: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_upload()
