import subprocess
import json

def test_with_curl():
    """Test download endpoint with curl to avoid client-side issues"""
    
    file_id = "69c777ebaf94684d63c5361b"  # The one that returns dio-boundary
    url = f"https://zaply.in.net/api/v1/files/download/{file_id}"
    
    print(f"🔍 Testing with curl: {file_id}")
    
    try:
        # Use curl to get raw response
        result = subprocess.run([
            'curl', '-v', url,
            '-H', 'Accept: image/*',
            '--max-time', '10'
        ], capture_output=True, text=True)
        
        print(f"  Exit code: {result.returncode}")
        print(f"  STDERR:\n{result.stderr}")
        print(f"  STDOUT (first 200 chars): {result.stdout[:200]}")
        
        # Check if stdout starts with image headers
        if result.stdout.startswith('\xff\xd8\xff'):
            print("  ✅ It's a JPEG image!")
        elif result.stdout.startswith('\x89PNG'):
            print("  ✅ It's a PNG image!")
        elif 'dio-boundary' in result.stdout:
            print("  ❌ Still getting dio-boundary response")
        else:
            print(f"  ❓ Unknown response format")
            
    except Exception as e:
        print(f"  ❌ ERROR: {e}")

if __name__ == "__main__":
    test_with_curl()
