import sys
sys.path.insert(0, '.')
from backend.services.emoji_service import EmojiService

emoji_service = EmojiService()
all_emojis = emoji_service.get_all_emojis()

# Check for mismatches
for category in all_emojis:
    cat_name = category['category']
    for emoji in category['emojis']:
        emoji_info = emoji_service.get_emoji_info(emoji['symbol'])
        if emoji_info and emoji_info['name'] != emoji['name']:
            sym = emoji['symbol']
            list_name = emoji['name']
            index_name = emoji_info['name']
            print(f'MISMATCH in {cat_name}: {sym}')
            print(f'  List: {list_name}')
            print(f'  Index: {index_name}')
            exit(0)

print('No mismatches found!')
