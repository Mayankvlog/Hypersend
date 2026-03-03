#!/usr/bin/env python3
"""Fix duplicate emoji entries in emoji_service.py"""

def fix_duplicate_emojis():
    # Read the file
    with open('backend/services/emoji_service.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find and remove the duplicate "Revolving Hearts" entry with corrupted symbol
    lines = content.split('\n')
    fixed_lines = []
    
    for i, line in enumerate(lines):
        # Skip the duplicate line with corrupted character
        if '"name": "Revolving Hearts", "symbol": "", "unicode": "U+1F49E"' in line:
            print(f"Removing duplicate line {i+1}: {line}")
            continue
        fixed_lines.append(line)
    
    # Write back the fixed content
    fixed_content = '\n'.join(fixed_lines)
    with open('backend/services/emoji_service.py', 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    
    print("Fixed duplicate emoji entries")

if __name__ == "__main__":
    fix_duplicate_emojis()
