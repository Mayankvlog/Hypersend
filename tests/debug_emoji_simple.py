#!/usr/bin/env python3
"""Debug the emoji test issue without backend imports"""

# Simulate the mock EmojiService from the test
class EmojiService:
    def __init__(self):
        # Load actual emoji data for testing
        try:
            with open('backend/services/emoji_service.py', 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract emoji data using regex
            import re
            emoji_pattern = r'\{"name":\s*"([^"]+)",\s*"symbol":\s*"([^"]+)",\s*"unicode":\s*"([^"]+)"\}'
            matches = re.findall(emoji_pattern, content)
            
            self._emoji_index = {}
            self.categories = {"Symbols": []}
            
            for name, symbol, unicode in matches:
                self._emoji_index[symbol] = {
                    "name": name,
                    "category": "Symbols",
                    "unicode": unicode
                }
                self.categories["Symbols"].append({
                    "name": name,
                    "symbol": symbol,
                    "unicode": unicode
                })
        except Exception as e:
            print(f"Error loading emojis: {e}")
            self._emoji_index = {}
            self.categories = {}
    
    def get_all_emojis(self): 
        return [{"category": cat, "emojis": emojis} for cat, emojis in self.categories.items()]
    
    def validate_emoji(self, emoji): 
        return emoji in self._emoji_index
    
    def get_emoji_info(self, emoji): 
        return self._emoji_index.get(emoji)

# Test the complex emojis
emoji_service = EmojiService()
complex_emojis = ["👋🏻", "👨‍👩‍👧‍👦", "🏳️‍🌈", "🇺🇸"]

print("Testing complex emojis:")
for emoji in complex_emojis:
    is_valid = emoji_service.validate_emoji(emoji)
    info = emoji_service.get_emoji_info(emoji)
    print(f"{emoji}: valid={is_valid}, info={info}")
    
    if info:
        print(f"  Type of info: {type(info)}")
        print(f"  Keys in info: {list(info.keys()) if isinstance(info, dict) else 'Not a dict'}")
        if isinstance(info, dict) and 'symbol' in info:
            print(f"  Symbol matches: {info['symbol'] == emoji}")
        else:
            print(f"  Symbol key missing or info not a dict")
