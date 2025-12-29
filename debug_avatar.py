#!/usr/bin/env python3
"""
Debug script to test avatar upload endpoint directly
"""
import requests
import json
import os
from pathlib import Path

def test_avatar_upload():
    """Test avatar upload endpoint directly"""
    
    # Test configuration
    base_url = "http://localhost:8000"
    avatar_url = f"{base_url}/api/v1/users/avatar"
    
    # Create a simple test image file
    test_image_path = "test_avatar.png"
    
    # Create a simple 1x1 PNG image (magic number + minimal PNG data)
    png_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\tpHYs\x00\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\nIDATx\x9cc\xf8\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00IEND\xaeB`\x82'
    
    with open(test_image_path, 'wb') as f:
        f.write(png_data)
    
    print(f"Created test image: {test_image_path} ({len(png_data)} bytes)")
    
    # Test 1: Upload without authentication (should work according to backend)
    print("\n=== Test 1: Upload without auth ===")
    try:
        with open(test_image_path, 'rb') as f:
            files = {'file': (test_image_path, f, 'image/png')}
            response = requests.post(avatar_url, files=files, timeout=10)
            
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print(f"Response Body: {response.text}")
        
        if response.headers.get('content-type', '').startswith('application/json'):
            try:
                data = response.json()
                print(f"Parsed JSON: {json.dumps(data, indent=2)}")
                
                # Check expected fields
                if 'avatar_url' in data:
                    print(f"[OK] avatar_url found: {data['avatar_url']}")
                else:
                    print("[ERROR] avatar_url missing")
                    
                if 'avatar' in data:
                    print(f"[OK] avatar found: {data['avatar']}")
                else:
                    print("[ERROR] avatar missing")
                    
            except json.JSONDecodeError as e:
                print(f"❌ Failed to parse JSON: {e}")
        else:
            print(f"❌ Response is not JSON: {response.headers.get('content-type')}")
            
    except Exception as e:
        print(f"[ERROR] Upload failed: {e}")
    
    # Test 2: Upload with authentication (if token is available)
    token = os.getenv('AUTH_TOKEN')
    if token:
        print("\n=== Test 2: Upload with auth ===")
        headers = {'Authorization': f'Bearer {token}'}
        try:
            with open(test_image_path, 'rb') as f:
                files = {'file': (test_image_path, f, 'image/png')}
                response = requests.post(avatar_url, files=files, headers=headers, timeout=10)
                
            print(f"Status Code: {response.status_code}")
            print(f"Response Body: {response.text}")
            
    except Exception as e:
        print(f"[ERROR] Authenticated upload failed: {e}")
    else:
        print("\n=== Test 2: Skipped (no AUTH_TOKEN) ===")
    
    # Test 3: Test GET avatar endpoint
    print("\n=== Test 3: Test GET avatar documentation ===")
    try:
        response = requests.get(f"{avatar_url}/", timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"GET avatar failed: {e}")
    
    # Test 4: Test alternative avatar upload endpoint
    print("\n=== Test 4: Test alternative avatar upload endpoint ===")
    alt_avatar_url = f"{base_url}/api/v1/users/avatar-upload"
    try:
        with open(test_image_path, 'wb') as f:
            f.write(png_data)
        
        with open(test_image_path, 'rb') as f:
            files = {'file': (test_image_path, f, 'image/png')}
            response = requests.post(alt_avatar_url, files=files, timeout=10)
            
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {response.text}")
        
        if response.headers.get('content-type', '').startswith('application/json'):
            try:
                data = response.json()
                print(f"Parsed JSON: {json.dumps(data, indent=2)}")
            except json.JSONDecodeError as e:
                print(f"Failed to parse JSON: {e}")
        
    except Exception as e:
        print(f"[ERROR] Alternative avatar upload failed: {e}")
    
    # Cleanup
    if os.path.exists(test_image_path):
        os.remove(test_image_path)
        print(f"\n🧹 Cleaned up test file: {test_image_path}")

if __name__ == "__main__":
    test_avatar_upload()