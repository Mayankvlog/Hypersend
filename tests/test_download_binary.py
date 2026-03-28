import requests

def test_download_binary():
    """Test the download endpoint and save binary data"""
    
    file_id = "69c777ebaf94684d63c5361b"
    url = f"https://zaply.in.net/api/v1/files/download/{file_id}"
    
    print(f"🔍 Testing binary download: {file_id}")
    
    try:
        response = requests.get(url, stream=True)
        print(f"  Status: {response.status_code}")
        print(f"  Content-Type: {response.headers.get('content-type', 'N/A')}")
        print(f"  Content-Length: {response.headers.get('content-length', 'N/A')}")
        print(f"  Transfer-Encoding: {response.headers.get('transfer-encoding', 'N/A')}")
        
        if response.status_code == 200:
            # Read first few bytes to check if it's an image
            data = response.raw.read(20)
            print(f"  First 20 bytes: {data}")
            
            # Check image signatures
            if data.startswith(b'\xff\xd8\xff'):
                print("  ✅ It's a JPEG image!")
            elif data.startswith(b'\x89PNG'):
                print("  ✅ It's a PNG image!")
            elif data.startswith(b'---dio'):
                print("  ❌ Getting dio-boundary response!")
            else:
                print(f"  ❓ Unknown format - starts with: {data}")
                
            # Save the file to check
            with open(f"downloaded_{file_id}.png", "wb") as f:
                response.raw.decompress()
                f.write(response.content)
            print(f"  💾 Saved as downloaded_{file_id}.png")
            
        else:
            print(f"  ❌ FAILED - {response.text[:200]}")
            
    except Exception as e:
        print(f"  ❌ ERROR: {e}")

if __name__ == "__main__":
    test_download_binary()
