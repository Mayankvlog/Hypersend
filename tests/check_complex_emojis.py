#!/usr/bin/env python3
"""Check which complex emojis are available"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Mock the imports to avoid database issues
class MockEmojiService:
    def __init__(self):
        # Load the actual emoji data from file
        with open('backend/services/emoji_service.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract emoji data using regex
        import re
        emoji_pattern = r'\{"name":\s*"([^"]+)",\s*"symbol":\s*"([^"]+)",\s*"unicode":\s*"([^"]+)"\}'
        matches = re.findall(emoji_pattern, content)
        
        self._emoji_index = {}
        for name, symbol, unicode in matches:
            self._emoji_index[symbol] = {
                "name": name,
                "category": "Symbols",  # Default category
                "unicode": unicode
            }
    
    def validate_emoji(self, symbol):
        return symbol in self._emoji_index
    
    def get_emoji_info(self, symbol):
        return self._emoji_index.get(symbol)

# Test the complex emojis
emoji_service = MockEmojiService()
complex_emojis = ["👋🏻", "👨‍👩‍👧‍👦", "🏳️‍🌈", "🇺🇸"]

print("Checking complex emojis:")
for emoji in complex_emojis:
    is_valid = emoji_service.validate_emoji(emoji)
    info = emoji_service.get_emoji_info(emoji)
    print(f"{emoji}: valid={is_valid}, info={info}")

print(f"\nTotal emojis in index: {len(emoji_service._emoji_index)}")

# Show some sample emojis from the index
print("\nSample emojis from index:")
for i, (symbol, info) in enumerate(list(emoji_service._emoji_index.items())[:10]):
    print(f"{symbol}: {info['name']}")
