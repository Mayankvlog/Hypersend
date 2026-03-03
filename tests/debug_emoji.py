#!/usr/bin/env python3
"""Debug emoji name preservation issue"""

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
    
    def get_all_emojis(self):
        # Return mock structure
        return [{"category": "Symbols", "emojis": [{"name": info["name"], "symbol": symbol, "unicode": info["unicode"]} for symbol, info in self._emoji_index.items()]}]
    
    def get_emoji_info(self, symbol):
        return self._emoji_index.get(symbol)

# Test the issue
emoji_service = MockEmojiService()
all_emojis = emoji_service.get_all_emojis()

print(f"Total emojis: {len(all_emojis[0]['emojis'])}")

# Check for the specific issue
for category in all_emojis:
    for emoji in category["emojis"]:
        if emoji["symbol"] == "💝":
            print(f"Found 💝: {emoji}")
            info = emoji_service.get_emoji_info(emoji["symbol"])
            print(f"Info from get_emoji_info: {info}")
            break
