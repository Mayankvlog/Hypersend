import requests
import os

def test_download_endpoint():
    """Test the download endpoint directly"""
    
    # Test both file IDs
    file_ids = ['69c777ebaf94684d63c5361b', '69c765dd20ca22c64a0bfb7d']
    base_url = "https://zaply.in.net/api/v1/files/download"
    
    for file_id in file_ids:
        print(f"\n🔍 Testing file_id: {file_id}")
        
        try:
            # Try without auth first
            response = requests.get(f"{base_url}/{file_id}")
            print(f"  Status: {response.status_code}")
            print(f"  Content-Type: {response.headers.get('content-type', 'N/A')}")
            print(f"  Content-Length: {response.headers.get('content-length', 'N/A')}")
            
            if response.status_code == 200:
                print(f"  ✅ SUCCESS - File downloaded")
                # Check if it's actually an image
                if response.content.startswith(b'\xff\xd8\xff'):  # JPEG
                    print(f"  📷 It's a JPEG image")
                elif response.content.startswith(b'\x89PNG\r\n\x1a\n'):  # PNG
                    print(f"  🖼️ It's a PNG image")
                else:
                    print(f"  ❌ Not an image file (starts with: {response.content[:20]})")
            else:
                print(f"  ❌ FAILED - Response: {response.text[:200]}")
                
        except Exception as e:
            print(f"  ❌ ERROR: {e}")

if __name__ == "__main__":
    test_download_endpoint()
