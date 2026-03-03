#!/usr/bin/env python3
"""Fix all duplicate emoji entries in emoji_service.py"""

def fix_all_duplicate_emojis():
    # Read the file
    with open('backend/services/emoji_service.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Track symbols we've seen
    seen_symbols = {}
    fixed_lines = []
    
    for i, line in enumerate(lines):
        # Look for emoji entries
        if '"symbol":' in line and '"unicode":' in line:
            # Extract the symbol
            import re
            symbol_match = re.search(r'"symbol":\s*"([^"]+)"', line)
            if symbol_match:
                symbol = symbol_match.group(1)
                
                # Check if we've seen this symbol before
                if symbol in seen_symbols:
                    print(f"Removing duplicate symbol '{symbol}' at line {i+1}: {line.strip()}")
                    continue  # Skip this line
                
                seen_symbols[symbol] = i + 1
        
        fixed_lines.append(line)
    
    # Write back the fixed content
    with open('backend/services/emoji_service.py', 'w', encoding='utf-8') as f:
        f.writelines(fixed_lines)
    
    print(f"Fixed all duplicate emoji entries. Removed {len(lines) - len(fixed_lines)} duplicates.")

if __name__ == "__main__":
    fix_all_duplicate_emojis()
