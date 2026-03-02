#!/usr/bin/env python3
"""
Fix all datetime.utcnow() to datetime.now(timezone.utc) in backend files
"""
import os
import re
from pathlib import Path

def fix_file(filepath):
    """Fix datetime issues in a file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    
    # Fix 1: Replace Field(default_factory=datetime.utcnow) with timezone-aware
    content = content.replace(
        'Field(default_factory=datetime.utcnow)',
        'Field(default_factory=lambda: datetime.now(timezone.utc))'
    )
    
    # Fix 2: Replace int(datetime.utcnow().timestamp()) with ISO format
    content = re.sub(
        r'int\(datetime\.utcnow\(\)\.timestamp\(\)\)',
        'datetime.now(timezone.utc).isoformat()',
        content
    )
    
    # Fix 3: Replace datetime.utcnow() with timezone-aware version
    content = re.sub(
        r'datetime\.utcnow\(',
        'datetime.now(timezone.utc).',
        content
    )
    
    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    backend_dir = Path('backend')
    
    files_to_fix = [
        'backend/models.py',
        'backend/routes/messages.py',
        'backend/redis_cache.py',
        'backend/websocket/delivery_handler.py',
    ]
    
    for filepath in files_to_fix:
        if os.path.exists(filepath):
            print(f"Processing {filepath}...", end=" ")
            if fix_file(filepath):
                print("✓ FIXED")
            else:
                print("- No changes needed")
        else:
            print(f"Skipping {filepath} (not found)")

if __name__ == '__main__':
    main()
