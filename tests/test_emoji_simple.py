#!/usr/bin/env python3
"""Simple emoji test without backend dependencies"""

# Direct emoji count from file
import re

def count_emojis():
    try:
        with open('backend/services/emoji_service.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Count emoji entries
        emoji_entries = re.findall(r'\{"name":', content)
        print(f'Total emoji entries: {len(emoji_entries)}')
        
        # Check for complex emojis
        complex_emojis = ['👋🏻', '👨‍👩‍👧‍👦', '🏳️‍🌈', '🇺🇸']
        for emoji in complex_emojis:
            if emoji in content:
                print(f'✓ Found complex emoji: {emoji}')
            else:
                print(f'✗ Missing complex emoji: {emoji}')
                
        return len(emoji_entries)
    except Exception as e:
        print(f'Error: {e}')
        return 0

if __name__ == "__main__":
    count = count_emojis()
    print(f'Final count: {count}')
