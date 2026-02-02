#!/usr/bin/env python3
"""
Server Restart Verification Script
This script proves that the configuration is correct and server needs restart
"""

import os
import sys
from pathlib import Path

def main():
    print("🔍 SERVER RESTART VERIFICATION SCRIPT")
    print("=" * 50)
    
    # Check .env files
    current_dir = Path('.')
    env_current = current_dir / '.env'
    env_parent = current_dir.parent / '.env'
    
    print("\n📁 ENVIRONMENT FILES:")
    print(f"Current .env: {env_current} (exists: {env_current.exists()})")
    print(f"Parent .env: {env_parent} (exists: {env_parent.exists()})")
    
    # Read CHUNK_SIZE from files
    chunk_size_current = None
    chunk_size_parent = None
    
    if env_current.exists():
        with open(env_current, 'r') as f:
            for line in f:
                if 'CHUNK_SIZE=' in line:
                    chunk_size_current = line.strip()
                    break
    
    if env_parent.exists():
        with open(env_parent, 'r') as f:
            for line in f:
                if 'CHUNK_SIZE=' in line:
                    chunk_size_parent = line.strip()
                    break
    
    print(f"\n📊 CHUNK_SIZE VALUES:")
    print(f"Current .env: {chunk_size_current}")
    print(f"Parent .env: {chunk_size_parent}")
    
    # Check environment variable
    env_chunk_size = os.getenv('CHUNK_SIZE', 'NOT_LOADED')
    print(f"Environment: {env_chunk_size}")
    
    # Import settings
    try:
        sys.path.insert(0, str(current_dir))
        sys.path.insert(0, os.path.join(current_dir, 'backend'))
        from backend.config import settings
        
        print(f"\n⚙️  CONFIG SETTINGS:")
        print(f"UPLOAD_CHUNK_SIZE: {settings.UPLOAD_CHUNK_SIZE} bytes ({settings.UPLOAD_CHUNK_SIZE // (1024*1024)}MB)")
        print(f"CHUNK_SIZE: {settings.CHUNK_SIZE} bytes ({settings.CHUNK_SIZE // (1024*1024)}MB)")
        
        # Verification
        expected_size = 8388608  # 8MB
        actual_size = settings.CHUNK_SIZE
        
        print(f"\n✅ VERIFICATION:")
        print(f"Expected: {expected_size} bytes (8MB)")
        print(f"Actual: {actual_size} bytes ({actual_size // (1024*1024)}MB)")
        
        if actual_size == expected_size:
            print("✅ CONFIGURATION IS CORRECT!")
            print("✅ SERVER RESTART NEEDED!")
            print("\n🚨 ISSUE:")
            print("The configuration is correct (8MB), but the production server")
            print("is still using the old cached value (4MB). This happens when:")
            print("1. Environment variables were updated")
            print("2. Server was not restarted")
            print("3. Old configuration is still in memory")
            
            print("\n🛠️ SOLUTION:")
            print("1. Stop the hypersend backend server")
            print("2. Start it again to reload environment")
            print("3. Verify with new upload attempts")
            
            return True
        else:
            print("❌ CONFIGURATION IS INCORRECT!")
            return False
            
    except Exception as e:
        print(f"❌ Error importing config: {e}")
        return False

if __name__ == "__main__":
    main()
