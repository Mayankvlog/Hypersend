#!/usr/bin/env python3
"""
Simple test for avatar upload endpoints
"""
import requests
import json
import os

def test_avatar_upload():
    """Test avatar upload endpoint directly"""
    
    base_url = "http://localhost:8000"
    avatar_url = f"{base_url}/api/v1/users/avatar"
    
    # Create a simple test image file
    test_image_path = "test_avatar.png"
    png_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\tpHYs\x00\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\nIDATx\x9cc\xf8\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00IEND\xaeB`\x82'
    
    with open(test_image_path, 'wb') as f:
        f.write(png_data)
    
    print(f"Created test image: {test_image_path} ({len(png_data)} bytes)")
    
    # Test 1: Upload without authentication
    print("\n=== Test 1: Upload without auth ===")
    try:
        with open(test_image_path, 'rb') as f:
            files = {'file': (test_image_path, f, 'image/png')}
            response = requests.post(avatar_url, files=files, timeout=10)
            
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {response.text}")
        
        if response.headers.get('content-type', '').startswith('application/json'):
            data = response.json()
            print(f"[OK] avatar_url found: {data.get('avatar_url', 'MISSING')}")
            print(f"[OK] avatar found: {data.get('avatar', 'MISSING')}")
        
    except Exception as e:
        print(f"[ERROR] Upload failed: {e}")
    
    # Cleanup
    if os.path.exists(test_image_path):
        os.remove(test_image_path)

if __name__ == "__main__":
    test_avatar_upload()