#!/usr/bin/env python3
"""Debug the EmojiService issue"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

try:
    from services.emoji_service import EmojiService
    
    emoji_service = EmojiService()
    complex_emojis = ["👋🏻", "👨‍👩‍👧‍👦", "🏳️‍🌈", "🇺🇸"]
    
    print("Testing complex emojis with real EmojiService:")
    for emoji in complex_emojis:
        is_valid = emoji_service.validate_emoji(emoji)
        info = emoji_service.get_emoji_info(emoji)
        print(f"{emoji}: valid={is_valid}, info={info}")
        if info:
            print(f"  Keys in info: {list(info.keys())}")
        
except Exception as e:
    print(f"Error with real EmojiService: {e}")
    
    # Test with mock
    print("\nTesting with mock EmojiService:")
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
    
    mock_service = MockEmojiService()
    for emoji in complex_emojis:
        is_valid = mock_service.validate_emoji(emoji)
        info = mock_service.get_emoji_info(emoji)
        print(f"{emoji}: valid={is_valid}, info={info}")
        if info:
            print(f"  Keys in info: {list(info.keys())}")
