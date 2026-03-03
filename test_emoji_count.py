#!/usr/bin/env python3
"""Test emoji count and validation"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

try:
    from services.emoji_service import EmojiService
    
    emoji_service = EmojiService()
    all_emojis = emoji_service.get_all_emojis()
    total_emojis = sum(len(category['emojis']) for category in all_emojis)
    
    print(f'Total emojis: {total_emojis}')
    
    # Test complex emojis
    complex_emojis = ['👋🏻', '👨‍👩‍👧‍👦', '🏳️‍🌈', '🇺🇸']
    for emoji in complex_emojis:
        is_valid = emoji_service.validate_emoji(emoji)
        info = emoji_service.get_emoji_info(emoji)
        print(f'{emoji}: valid={is_valid}, info={info is not None}')
        
except Exception as e:
    print(f'Error: {e}')
