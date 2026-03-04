/// WhatsApp-style Emoji Picker with 8 Categories
class EmojiCategory {
  final String name;
  final String icon;
  final List<String> emojis;
  
  EmojiCategory({
    required this.name,
    required this.icon,
    required this.emojis,
  });
}

class EmojiUtils {
  /// All emoji categories with proper categorization
  static final List<EmojiCategory> categories = [
    EmojiCategory(
      name: 'Smileys & People',
      icon: '😀',
      emojis: [
        '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂',
        '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍', '🤩',
        '😘', '😗', '😚', '😙', '🥲', '😋', '😛', '😜',
        '🤪', '😌', '😔', '😑', '😐', '😶', '🤐', '🤨',
        '😏', '😒', '🙁', '😲', '☹️', '🥺', '😦', '😧',
        '😨', '😰', '😥', '😢', '😭', '😱', '😖', '😣',
        '😞', '😓', '😩', '😫', '🥱', '😤', '😡', '😠',
        '🤬', '😈', '👿', '💀', '☠️', '💩', '🤡', '👹',
        '👺', '👻', '👽', '👾', '🤖', '😺', '😸', '😹',
        '😻', '😼', '😽', '🙀', '😿', '😾', '🙈', '🙉',
        '🙊', '💋', '💌', '💘', '💝', '💖', '💗', '💓',
        '💞', '💕', '💘', '💟', '❣️', '💔', '❤️', '🧡',
        '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎',
      ],
    ),
    EmojiCategory(
      name: 'Animals & Nature',
      icon: '🐶',
      emojis: [
        '🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼',
        '🐨', '🐯', '🦁', '🐮', '🐷', '🐽', '🐸', '🐵',
        '🙈', '🙉', '🙊', '🐒', '🐔', '🐧', '🐦', '🐤',
        '🐣', '🐥', '🦆', '🦅', '🦉', '🦇', '🐺', '🐗',
        '🐴', '🦄', '🐝', '🪱', '🐛', '🦋', '🐌', '🐞',
        '🐜', '🪰', '🪲', '🦗', '🕷️', '🦂', '🐢', '🐍',
        '🐙', '🦑', '🦐', '🦞', '🦟', '🦠', '🐡', '🐠',
        '🐟', '🐬', '🐳', '🐋', '🦈', '⛵', '🐊', '🐅',
        '🐆', '🦓', '🦍', '🦧', '🐘', '🦛', '🦏', '🐪',
        '🐫', '🦒', '🦘', '🐃', '🐂', '🐄', '🐎', '🐖',
        '🐏', '🐑', '🦉', '🐐', '🦌', '🐕', '🐩', '🦮',
        '🐈', '🐓', '🦃', '🦚', '🦜', '🦢', '🦗', '🥚',
        '🍎', '🍊', '🍋', '🍌', '🍉', '🍇', '🍓', '🍈',
      ],
    ),
    EmojiCategory(
      name: 'Food & Drink',
      icon: '🍕',
      emojis: [
        '🍏', '🍎', '🍐', '🍊', '🍋', '🍌', '🍉', '🍇',
        '🍓', '🍈', '🍒', '🍑', '🥭', '🍍', '🥥', '🥝',
        '🍅', '🍆', '🥑', '🥦', '🥬', '🥒', '🌶️', '🌽',
        '🥕', '🧄', '🧅', '🥔', '🍞', '🥐', '🥯', '🍖',
        '🍗', '🥩', '🌭', '🍔', '🍟', '🍕', '🥪', '🥙',
        '🧆', '🌮', '🌯', '🥗', '🥘', '🥫', '🍝', '🍜',
        '🍲', '🍛', '🍣', '🍱', '🥟', '🦪', '🍤', '🍙',
        '🍚', '🍘', '🍥', '🥠', '🥮', '🍢', '🍡', '🍧',
        '🍨', '🍦', '🍰', '🎂', '🧁', '🍮', '🍭', '🍬',
        '🍫', '🍿', '🍩', '🍪', '🌰', '🍯', '🥛', '🥤',
        '☕', '🍵', '🍶', '🍾', '🍷', '🍸', '🍹', '🍺',
        '🍻', '🥂', '🥃', '🥤', '🧋', '🧃',
      ],
    ),
    EmojiCategory(
      name: 'Activity',
      icon: '⚽',
      emojis: [
        '⚽', '🏀', '🏈', '⚾', '🥎', '🎾', '🏐', '🏉',
        '🥏', '🎳', '🏓', '🏸', '🏒', '🏑', '🥊', '🥋',
        '🥅', '⛳', '⛸️', '🎣', '🎽', '🎿', '⛷️', '🏂',
        '🪂', '🛼', '🛹', '🛺', '🏋️', '🏌️', '🏇', '🧘',
        '🏄', '🏊', '🤽', '🚣', '🧗', '🚴', '🚵', '🤸',
        '⛹️', '🤺', '🤼', '🤾', '🏌️', '🏸', '🎣', '🎿',
        '🎪', '🎨', '🎬', '🎤', '🎧', '🎼', '🎹', '🥁',
        '🎷', '🎺', '🎸', '🎻', '🎲', '♟️', '🎮', '🎯',
      ],
    ),
    EmojiCategory(
      name: 'Travel & Places',
      icon: '✈️',
      emojis: [
        '🌍', '🌎', '🌏', '🌐', '🗺️', '🗿', '🗽', '🗼',
        '⛩️', '🏰', '🏯', '🏟️', '⛲', '⛺', '🏠', '🏡',
        '🏘️', '🏚️', '🏗️', '🏭', '🏢', '🏬', '🏣', '🏤',
        '🏥', '🏦', '🏧', '🏨', '🏪', '🏫', '🏩', '💒',
        '🏛️', '⛪', '🕌', '🕍', '🛕', '🛜', '⌚', '📱',
        '📲', '💻', '⌨️', '🖥️', '🖨️', '🖱️', '🖲️', '🕹️',
        '🗜️', '💽', '💾', '💿', '📀', '📧', '📨', '📩',
        '📤', '📥', '📦', '📫', '📪', '📬', '📭', '📮',
        '✉️', '📚', '📖', '📕', '📗', '📘', '📙', '📓',
        '📔', '📒', '📑', '🧷', '🪑', '🛒', '🛍️', '🎁',
        '✈️', '🚁', '🚂', '🚆', '🚇', '🚈', '🚉', '🚊',
      ],
    ),
    EmojiCategory(
      name: 'Objects',
      icon: '💡',
      emojis: [
        '⌚', '📱', '📲', '💻', '⌨️', '🖥️', '🖨️', '🖱️',
        '🖲️', '🕹️', '🗜️', '💽', '💾', '💿', '📀', '🧮',
        '🎥', '🎬', '📺', '📷', '📸', '📹', '🎞️', '📽️',
        '🎦', '📞', '☎️', '📟', '📠', '📺', '📻', '🎙️',
        '🎚️', '🎛️', '🧭', '⏱️', '⏲️', '⏰', '🕰️', '⌛',
        '⏳', '📡', '🔋', '🔌', '💡', '🔦', '🕯️', '🪔',
        '🧯', '🛢️', '💸', '💵', '💴', '💶', '💷', '💰',
        '💳', '🧾', '✉️', '📩', '📨', '📤', '📥', '📦',
        '🏷️', '🧧', '📪', '📫', '📬', '📭', '📮', '✏️',
        '✒️', '🖋️', '🖊️', '🖌️', '🖍️', '📝', '📁', '📂',
        '📅', '📆', '🗒️', '🗓️', '📇', '📈', '📉', '📊',
        '📋', '📌', '📍', '📎', '🖇️', '📐', '📏', '⌐',
      ],
    ),
    EmojiCategory(
      name: 'Symbols',
      icon: '❤️',
      emojis: [
        '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍',
        '🤎', '🏳️', '🏴', '🏁', '🚩', '🎌', '🏴󠁧󠁢󠁳󠁣󠁴󠁿', '🏴󠁧󠁢󠁷󠁬󠁳󠁿',
        '🏴󠁧󠁢󠁥󠁮󠁧󠁿', '🇺🇸', '🇬🇧', '🇨🇦', '🇦🇺', '🇯🇵', '🇨🇳', '🇮🇳',
        '🇧🇷', '🇲🇽', '🇮🇹', '🇫🇷', '🇩🇪', '🇪🇸', '🇷🇺', '🇰🇷',
        '✅', '❌', '⚠️', '⛔', '🚫', '🚳', '🚭', '🚯',
        '🚱', '🚸', '☢️', '☣️', '⬆️', '↗️', '➡️', '↘️',
        '⬇️', '↙️', '⬅️', '↖️', '↕️', '↔️', '↩️', '↪️',
        '⤴️', '⤵️', '🔃', '🔄', '🔙', '🔚', '🔛', '🔜',
        '🆗', '🆑', '🆒', '🆓', 'Ⓜ️', '🅰️', '🅱️', '🆎',
        '🅾️', '💠', '♻️', '📛', '🔰', '⚛️', '☢️', '☣️',
      ],
    ),
    EmojiCategory(
      name: 'Flags',
      icon: '🇺🇸',
      emojis: [
        '🇺🇸', '🇬🇧', '🇨🇦', '🇦🇺', '🇯🇵', '🇨🇳', '🇮🇳', '🇧🇷',
        '🇲🇽', '🇮🇹', '🇫🇷', '🇩🇪', '🇪🇸', '🇷🇺', '🇰🇷', '🇸🇦',
        '🇬🇷', '🇳🇿', '🇻🇳', '🇹🇭', '🇲🇾', '🇵🇭', '🇮🇩', '🇸🇬',
        '🇵🇰', '🇧🇩', '🇿🇦', '🇳🇬', '🇪🇬', '🇦🇪', '🇦🇹', '🇲🇿',
        '🏴', '🏳️', '🏴󠁧󠁢󠁳󠁣󠁴󠁿', '🏴󠁧󠁢󠁷󠁬󠁳󠁿', '🏴󠁧󠁢󠁥󠁮󠁧󠁿',
      ],
    ),
  ];

  /// Get emoji by category name
  static List<String> getEmojisByCategory(String categoryName) {
    try {
      return categories.firstWhere((cat) => cat.name == categoryName).emojis;
    } catch (e) {
      return categories.first.emojis;
    }
  }

  /// Get all emojis (for backward compatibility)
  static List<String> getEmojiList() {
    return categories.expand((cat) => cat.emojis).toList();
  }

  /// Emoji name mappings for better search functionality
  static const Map<String, List<String>> emojiKeywords = {
    // Smileys
    '😀': ['smile', 'smiley', 'happy', 'grin', 'face', 'grinning'],
    '😃': ['smile', 'smiley', 'happy', 'face', 'grinning', 'open'],
    '😄': ['smile', 'smiley', 'happy', 'laughing', 'face', 'laugh'],
    '😁': ['smile', 'smiley', 'happy', 'grinning', 'face', 'beaming'],
    '😆': ['smile', 'smiley', 'happy', 'laugh', 'face', 'smiling'],
    '😅': ['smile', 'smiley', 'happy', 'laugh', 'face', 'sweat'],
    '🤣': ['laugh', 'lol', 'rofl', 'funny', 'face', 'roll', 'rolling'],
    '😂': ['laugh', 'lol', 'sad', 'cry', 'tears', 'face', 'joy'],
    '🙂': ['smile', 'happy', 'face', 'slightly'],
    '🙃': ['upside', 'smile', 'face', 'down'],
    '😉': ['wink', 'face', 'eye'],
    '😊': ['smile', 'happy', 'blush', 'face', 'kind'],
    '😇': ['angel', 'halo', 'face', 'holy', 'good'],
    '🥰': ['heartface', 'love', 'face', 'dating', 'loving'],
    '😍': ['love', 'heart', 'face', 'kissing', 'eyes'],
    '🤩': ['star', 'amazed', 'face', 'struck', 'impressed'],
    '😘': ['kiss', 'face', 'loving', 'mouth'],
    '😗': ['kiss', 'face', 'mouth'],
    '😚': ['kiss', 'face', 'closed', 'eyes'],
    '😙': ['kiss', 'face', 'smiling', 'eyes'],
    '🥲': ['smile', 'pleased', 'face', 'joy'],
    '😋': ['yum', 'faced', 'savoring', 'delicious'],
    '😛': ['tongue', 'face', 'out', 'silly'],
    '😜': ['tongue', 'wink', 'face', 'silly'],
    '🤪': ['tongue', 'crazy', 'face', 'silly', 'zany'],
    '😌': ['relieved', 'face', 'peaceful', 'content'],
    '😔': ['thoughtful', 'face', 'pensive', 'sad'],
    '😑': ['neutral', 'face', 'expressionless', 'meh'],
    '😐': ['neutral', 'face', 'expressionless'],
    '😶': ['face', 'mouth', 'silence', 'shushing', 'shut'],
    '🤐': ['shushing', 'face', 'zipper', 'secret'],
    '😏': ['smirk', 'face', 'sly', 'smirking'],
    '😒': ['unamused', 'face', 'unimpressed'],
    '🙁': ['frown', 'face', 'sad', 'unhappy'],
    '😲': ['surprised', 'face', 'shock', 'astonished'],
    '☹️': ['frown', 'face', 'sad', 'unhappy', 'angry'],
    '😦': ['surprised', 'mouth', 'open', 'shocked'],
    '😧': ['confused', 'face', 'persevering'],
    '😨': ['surprised', 'scared', 'face', 'fear'],
    '😰': ['worried', 'anxious', 'face', 'fear'],
    '😥': ['sad', 'tearful', 'face', 'cry'],
    '😢': ['crying', 'sad', 'face', 'tear', 'tears'],
    '😭': ['crying', 'sad', 'face', 'tears', 'loudly'],
    '😱': ['scared', 'surprised', 'face', 'shock', 'fear'],
    '😖': ['confounded', 'face', 'struggling'],
    '😣': ['persevering', 'face', 'determined'],
    '😞': ['disappointed', 'sad', 'face', 'sad'],
    '😓': ['downturned', 'face', 'sweat', 'stressed'],
    '😩': ['weary', 'tired', 'face', 'exhausted'],
    '😫': ['tired', 'face', 'frustrated', 'exhausted'],
    '🤬': ['sworn', 'cursing', 'face', 'mad', 'angry'],
    '😤': ['huffing', 'face', 'frustrated', 'angry'],
    '😡': ['pouting', 'angry', 'face', 'mad', 'rage'],
    '😠': ['angry', 'face', 'mad', 'enraged'],
    '🤨': ['raising', 'eyebrow', 'face', 'sceptical'],
    '😈': ['smiling', 'devil', 'face', 'evil', 'horns'],
    '👿': ['angry', 'devil', 'face', 'evil'],
    '💀': ['skull', 'dead', 'skeleton', 'death'],
    '☠️': ['pirate', 'skull', 'poison', 'death'],
    '💩': ['poop', 'shit', 'poo', 'face'],
    '🤡': ['clown', 'face', 'silly'],
    '👹': ['ogre', 'demon', 'monster', 'angry'],
    '👺': ['goblin', 'monster', 'demon'],
    '👻': ['ghost', 'spooky', 'face', 'haunted'],
    '👽': ['alien', 'ufo', 'extraterrestrial'],
    '👾': ['space', 'invader', 'alien', 'arcade'],
    '🤖': ['robot', 'face'],
    '😺': ['smiley', 'cat', 'face', 'animal'],
    '😸': ['grinning', 'cat', 'face', 'animal'],
    '😹': ['cat', 'tears', 'joy', 'face'],
    '😻': ['smiling', 'cat', 'face', 'heart', 'eyes'],
    '😼': ['cat', 'face', 'with', 'mouth'],
    '😽': ['kissing', 'cat', 'face'],
    '🙀': ['weary', 'cat', 'face', 'surprised'],
    '😿': ['crying', 'cat', 'face', 'tear'],
    '😾': ['pouting', 'cat', 'face', 'angry'],
    '🙈': ['see', 'monkey', 'no', 'evil'],
    '🙉': ['hear', 'monkey', 'no', 'evil'],
    '🙊': ['speak', 'monkey', 'no', 'evil'],
    
    // Hearts and Love
    '❤️': ['love', 'heart', 'red', 'symbol', 'romance'],
    '🧡': ['heart', 'orange', 'love', 'symbol'],
    '💛': ['heart', 'yellow', 'love', 'symbol', 'gold'],
    '💚': ['heart', 'green', 'love', 'symbol'],
    '💙': ['heart', 'blue', 'love', 'symbol'],
    '💜': ['heart', 'purple', 'love', 'symbol'],
    '🖤': ['heart', 'black', 'love', 'symbol', 'dark'],
    '🤍': ['heart', 'white', 'love', 'symbol'],
    '🤎': ['heart', 'brown', 'love', 'symbol'],
    '💔': ['broken', 'heart', 'heartbreak', 'love', 'sad'],
    '💕': ['two', 'hearts', 'love', 'romance', 'couple'],
    '💞': ['revolving', 'hearts', 'love', 'romance'],
    '💓': ['beating', 'heart', 'love', 'pulse'],
    '💗': ['growing', 'heart', 'love', 'romance'],
    
    // Animals
    '🐶': ['dog', 'animal', 'pet', 'puppy', 'face'],
    '🐱': ['cat', 'animal', 'pet', 'kitten', 'face'],
    '🐭': ['mouse', 'animal', 'rat', 'rodent'],
    '🐹': ['hamster', 'animal', 'rodent', 'pet'],
    '🐰': ['rabbit', 'bunny', 'animal', 'pet', 'hare'],
    '🦊': ['fox', 'animal', 'nature', 'cute'],
    '🐻': ['bear', 'animal', 'nature'],
    '🐼': ['panda', 'bear', 'animal', 'cute'],
    '🐨': ['koala', 'australian', 'animal', 'cute'],
    '🐯': ['tiger', 'animal', 'cat', 'wild'],
    '🦁': ['lion', 'animal', 'wild', 'big', 'cat'],
    '🐮': ['cow', 'animal', 'farm', 'cattle'],
    '🐷': ['pig', 'animal', 'farm', 'pork'],
    '🐽': ['pig', 'nose', 'animal', 'farm'],
    '🐸': ['frog', 'animal', 'amphibian', 'nature'],
    '🐵': ['monkey', 'primate', 'animal', 'face'],
    '🐒': ['monkey', 'primate', 'animal'],
    '🐔': ['chicken', 'bird', 'farm', 'animal'],
    '🐧': ['penguin', 'bird', 'arctic', 'animal'],
    '🐦': ['bird', 'animal', 'nature', 'sky'],
    '🐤': ['chick', 'baby', 'bird', 'animal'],
    '🐣': ['egg', 'baby', 'birth', 'hatching'],
    '🐥': ['chick', 'baby', 'bird', 'hatching'],
    '🦆': ['duck', 'bird', 'farm', 'animal'],
    '🦅': ['eagle', 'bird', 'hawk', 'animal'],
    '🦉': ['owl', 'bird', 'night', 'animal'],
    '🦇': ['bat', 'animal', 'night', 'flying'],
    
    // Food and Drink
    '🍏': ['apple', 'fruit', 'green', 'food'],
    '🍎': ['apple', 'fruit', 'red', 'food'],
    '🍐': ['pear', 'fruit', 'food'],
    '🍊': ['orange', 'fruit', 'citrus', 'food'],
    '🍋': ['lemon', 'fruit', 'citrus', 'food'],
    '🍌': ['banana', 'fruit', 'yellow', 'food'],
    '🍉': ['watermelon', 'fruit', 'melon', 'food', 'summer'],
    '🍇': ['grapes', 'fruit', 'bunch', 'food'],
    '🍓': ['strawberry', 'fruit', 'sweet', 'food'],
    '🍈': ['melon', 'fruit', 'green', 'food'],
    '🍒': ['cherries', 'fruit', 'red', 'food'],
    '🍑': ['peach', 'fruit', 'orange', 'food'],
    '🍍': ['pineapple', 'fruit', 'tropical', 'food'],
    '🍕': ['pizza', 'food', 'eat', 'italian', 'lunch'],
    '🍔': ['burger', 'hamburger', 'food', 'eat'],
    '🍟': ['french', 'fries', 'food', 'fast'],
    '🌭': ['hotdog', 'food', 'dog', 'eat'],
    '🌮': ['taco', 'food', 'mexican', 'eat'],
    '🌯': ['burrito', 'food', 'mexican'],
    '🥪': ['sandwich', 'food', 'eat'],
    '🥙': ['falafel', 'food', 'pita', 'eat'],
    '🧆': ['falafel', 'food', 'vegetarian'],
    '🍝': ['spaghetti', 'noodles', 'food', 'italian', 'pasta'],
    '🍜': ['ramen', 'noodles', 'food', 'bowl'],
    '🍲': ['pouring', 'bowl', 'soup', 'food'],
    '🍛': ['curry', 'rice', 'food', 'indian', 'asian'],
    '🍣': ['sushi', 'food', 'japanese', 'rice', 'raw'],
    '🍱': ['bento', 'box', 'food', 'japanese', 'lunch'],
    '🥟': ['dumpling', 'food', 'asian', 'chinese'],
    '🦪': ['oyster', 'food', 'seafood'],
    '🍤': ['shrimp', 'prawn', 'seafood', 'food'],
    '🍙': ['rice', 'ball', 'food', 'japanese'],
    '🍚': ['rice', 'bowl', 'food', 'asian'],
    '🍘': ['rice', 'cracker', 'food', 'snack'],
    '🍥': ['fish', 'cake', 'food'],
    '🥠': ['fortune', 'cookie', 'food', 'dessert'],
    '🥮': ['moon', 'cake', 'food', 'dessert', 'chinese'],
    '🍢': ['oden', 'skewer', 'food', 'japanese'],
    '🍡': ['dango', 'food', 'sweet', 'japanese'],
    '🍧': ['shaved', 'ice', 'dessert', 'food', 'summer'],
    '🍨': ['ice', 'cream', 'dessert', 'food', 'sweet', 'cold'],
    '🍦': ['ice', 'cream', 'vanilla', 'dessert', 'food'],
    '🍰': ['cake', 'slice', 'dessert', 'food', 'sweet', 'birthday'],
    '🎂': ['birthday', 'cake', 'dessert', 'food', 'sweet'],
    '🧁': ['cupcake', 'dessert', 'food', 'sweet'],
    '🍮': ['custard', 'dessert', 'food', 'sweet'],
    '🍭': ['candy', 'sweet', 'lollipop', 'food', 'dessert'],
    '🍬': ['candy', 'sweet', 'food', 'dessert'],
    '🍫': ['chocolate', 'bar', 'candy', 'food', 'sweet'],
    '🍿': ['popcorn', 'food', 'movie', 'snack'],
    '🍩': ['donut', 'doughnut', 'dessert', 'food', 'sweet'],
    '🍪': ['cookie', 'biscuit', 'dessert', 'food', 'sweet'],
    '🌰': ['chestnut', 'nut', 'food', 'nature'],
    '🍯': ['honey', 'pot', 'food', 'sweet'],
    '🥛': ['milk', 'glass', 'drink', 'beverage', 'dairy'],
    '☕': ['coffee', 'hot', 'drink', 'beverage', 'morning'],
    '🍵': ['tea', 'hot', 'drink', 'beverage'],
    '🍶': ['sake', 'alcohol', 'drink', 'japan', 'beverage'],
    '🍾': ['bottle', 'champagne', 'wine', 'alcohol', 'drink'],
    '🍷': ['wine', 'glass', 'alcohol', 'drink', 'red'],
    '🍸': ['cocktail', 'drink', 'alcohol', 'glass', 'party'],
    '🍹': ['tropical', 'drink', 'alcohol', 'summer', 'vacation'],
    '🍺': ['beer', 'mug', 'alcohol', 'drink', 'bar'],
    '🍻': ['beers', 'clinking', 'mugs', 'alcohol', 'drink'],
    
    // Sports and Activity
    '⚽': ['soccer', 'football', 'sport', 'ball', 'game', 'futbol'],
    '🏀': ['basketball', 'sport', 'ball', 'game', 'hoop'],
    '🏈': ['american', 'football', 'sport', 'game'],
    '⚾': ['baseball', 'sport', 'ball', 'game'],
    '🥎': ['softball', 'sport', 'ball'],
    '🎾': ['tennis', 'ball', 'sport', 'racket', 'game'],
    '🏐': ['volleyball', 'ball', 'sport', 'net', 'game'],
    '🏉': ['rugby', 'sport', 'ball', 'game'],
    '🥏': ['cricket', 'game', 'ball', 'sport'],
    '🎳': ['bowling', 'sport', 'pins', 'game'],
    '🏓': ['ping', 'pong', 'table', 'sport', 'game'],
    '🏸': ['badminton', 'sport', 'racket', 'game'],
    '🏒': ['ice', 'hockey', 'sport', 'game'],
    '🏑': ['field', 'hockey', 'sport', 'game'],
    '🥊': ['boxing', 'sport', 'glove', 'punch', 'fight'],
    '🥋': ['karate', 'martial', 'arts', 'sport', 'judo'],
    
    // Travel and Places
    '✈️': ['airplane', 'plane', 'travel', 'flight', 'aviation'],
    '🚁': ['helicopter', 'travel', 'aviation'],
    '🚂': ['train', 'railway', 'travel', 'transport'],
    '🚆': ['train', 'railway', 'travel', 'transport'],
    '🚇': ['subway', 'underground', 'metro', 'travel', 'transport'],
    '🚈': ['train', 'light', 'rail', 'travel'],
    '🚉': ['station', 'railway', 'train', 'travel'],
    '🚊': ['tram', 'streetcar', 'travel', 'transport'],
    '🚝': ['mountain', 'cableway', 'rope', 'travel'],
    '🚞': ['mountain', 'railway', 'train', 'travel'],
    '🚋': ['tram', 'car', 'travel', 'transport'],
    '🚌': ['bus', 'vehicle', 'travel', 'transport', 'public'],
    '🚍': ['bus', 'oncoming', 'travel', 'transport'],
    '🚎': ['trolleybus', 'bus', 'travel', 'transport'],
    '🚐': ['minibus', 'bus', 'van', 'travel'],
    '🚑': ['ambulance', 'emergency', 'hospital', 'medical'],
    '🚒': ['fire', 'engine', 'truck', 'emergency'],
    '🚓': ['police', 'car', 'law', 'patrol', 'emergency'],
    '🚔': ['police', 'car', 'oncoming', 'law'],
    '🚕': ['taxi', 'car', 'travel', 'yellow'],
    '🚖': ['taxi', 'oncoming', 'car', 'travel'],
    '🚗': ['car', 'automobile', 'vehicle', 'travel'],
    '🚘': ['oncoming', 'automobile', 'car', 'travel'],
    '🚙': ['sport', 'utility', 'vehicle', 'suv', 'car'],
    '🚚': ['delivery', 'truck', 'vehicle', 'shipping'],
    '🚛': ['truck', 'articulated', 'vehicle', 'cargo'],
    '🚜': ['tractor', 'vehicle', 'farm'],
    '🏎️': ['racing', 'car', 'sports', 'speed'],
    '🏍️': ['motorcycle', 'bike', 'vehicle', 'speed'],
    '🛵': ['motor', 'scooter', 'bike', 'vehicle'],
    '🦯': ['guide', 'dog', 'animal', 'disability'],
    '🦽': ['manual', 'wheelchair', 'disabled', 'accessibility'],
    '🦼': ['motorized', 'wheelchair', 'disability'],
    '🛺': ['auto', 'rickshaw', 'tuk', 'vehicle'],
    '🚲': ['bicycle', 'bike', 'vehicle', 'sport', 'pedal'],
    '🛴': ['kick', 'scooter', 'rider', 'board'],
    '🛹': ['skateboard', 'board', 'sport', 'extreme'],
    '🛼': ['roller', 'skate', 'sport', 'wheeled'],
    '🛸': ['flying', 'saucer', 'ufo', 'alien', 'space'],
    '🛰️': ['satellite', 'space', 'orbit', 'technology'],
    '⛞': ['snowman', 'without', 'snow', 'winter'],
    
    // Objects and Symbols  
    '💡': ['light', 'bulb', 'idea', 'bright', 'invention'],
    '🔦': ['flashlight', 'light', 'torch'],
    '🏮': ['red', 'paper', 'lantern', 'light', 'asian'],
    '📱': ['mobile', 'phone', 'device', 'smartphone', 'technology'],
    '📲': ['phone', 'receiver', 'call', 'device'],
    '💻': ['laptop', 'computer', 'device', 'technology', 'pc'],
    '⌨️': ['keyboard', 'computer', 'typing', 'device'],
    '🖥️': ['desktop', 'computer', 'device', 'technology', 'pc'],
    '🖨️': ['printer', 'device', 'office', 'print'],
    '🖱️': ['computer', 'mouse', 'device', 'click'],
    '🖲️': ['trackball', 'device', 'vintage'],
    '🕹️': ['joystick', 'game', 'controller', 'gaming'],
    '🗜️': ['compression', 'clamp', 'tool', 'vice'],
    '💽': ['computer', 'disk', 'save', 'oldschool'],
    '💾': ['floppy', 'disk', 'save', 'oldschool', 'storage'],
    '💿': ['optical', 'disk', 'cd', 'dvd', 'storage'],
    '📀': ['dvd', 'optical', 'disk', 'technology', 'storage'],
    '🧮': ['abacus', 'calculator', 'counting', 'math'],
    '🎥': ['movie', 'camera', 'film', 'video', 'cinema'],
    '🎬': ['clapper', 'board', 'film', 'movie', 'action'],
    '📺': ['television', 'tv', 'watch', 'news', 'media'],
    '📷': ['camera', 'photo', 'photograph', 'picture'],
    '📸': ['camera', 'photo', 'snapshot', 'picture'],
    '📹': ['video', 'camera', 'film', 'movie'],
    '🎞️': ['film', 'frames', 'movie', 'cinema', 'video'],
    '📽️': ['film', 'projector', 'movie', 'cinema'],
    '🎦': ['cinema', 'film', 'movie', 'theater', 'watch'],
    '📞': ['telephone', 'receiver', 'call', 'phone', 'vintage'],
    '☎️': ['telephone', 'phone', 'call', 'vintage'],
    '📟': ['pager', 'device', 'oldschool', 'vintage'],
    '📠': ['fax', 'machine', 'document', 'office'],
    '': ['radio', 'broadcast', 'listen', 'media'],
    '🎙️': ['studio', 'microphone', 'podcast', 'voice', 'record'],
    '🎚️': ['level', 'slider', 'sound', 'music', 'volume'],
    '🎛️': ['control', 'knobs', 'dj', 'music', 'sound'],
    '⏱️': ['stopwatch', 'timer', 'time', 'watch', 'sport'],
    '⏲️': ['timer', 'stopwatch', 'time', 'clock'],
    '⏰': ['alarm', 'clock', 'bell', 'reminder', 'time'],
    '🕰️': ['mantelpiece', 'clock', 'time', 'vintage'],
    '📡': ['satellite', 'antenna', 'signal', 'broadcast'],
    '🔋': ['battery', 'power', 'energy', 'charge'],
    '🔌': ['electric', 'plug', 'power', 'charge', 'outlet'],
    
    // Symbols
    '✅': ['check', 'mark', 'yes', 'ok', 'verified'],
    '❌': ['cross', 'mark', 'no', 'wrong', 'cancel'],
    '⚠️': ['warning', 'alert', 'caution', 'danger'],
    '⛔': ['stop', 'prohibited', 'forbidden', 'no', 'entry'],
    '🚫': ['prohibited', 'forbidden', 'no', 'entry', 'stop'],
  };  

  /// Enhanced search emojis with multiple matching strategies
  static List<String> searchEmojis(String query) {
    if (query.isEmpty) return [];
    
    final searchTerm = query.toLowerCase().trim();
    List<String> results = [];
    Map<String, int> scoreMap = {}; // For ranking results
    
    // Extended category keyword maps
    final categoryMap = {
      'smile': 0, 'smiley': 0, 'happy': 0, 'face': 0, 'grin': 0,
      'laugh': 0, 'lol': 0, 'funny': 0, 'joy': 0, 'cheerful': 0,
      'animal': 1, 'nature': 1, 'dog': 1, 'cat': 1, 'pet': 1, 'wildlife': 1,
      'food': 2, 'drink': 2, 'pizza': 2, 'eat': 2, 'burger': 2, 
      'hamburger': 2, 'meal': 2, 'beverage': 2, 'cake': 2, 'dessert': 2,
      'sport': 3, 'activity': 3, 'ball': 3, 'game': 3, 'soccer': 3,
      'football': 3, 'basketball': 3, 'play': 3, 'exercise': 3,
      'travel': 4, 'place': 4, 'map': 4, 'airplane': 4, 'plane': 4,
      'vehicle': 4, 'car': 4, 'train': 4, 'adventure': 4,
      'object': 5, 'thing': 5, 'lamp': 5, 'computer': 5, 'phone': 5,
      'tech': 5, 'device': 5, 'technology': 5,
      'symbol': 6, 'heart': 6, 'love': 6, 'check': 6, 'mark': 6,
      'flag': 7, 'country': 7, 'world': 7,
    };
    
    // Strategy 1: Check for category keyword matches (highest priority)
    for (var entry in categoryMap.entries) {
      if (searchTerm == entry.key || 
          (searchTerm.length > 2 && entry.key.startsWith(searchTerm))) {
        return categories[entry.value].emojis;
      }
    }
    
    // Strategy 2: Direct emoji keyword matching with scoring
    for (var entry in emojiKeywords.entries) {
      int score = 0;
      for (var keyword in entry.value) {
        // Exact keyword match = 10 points
        if (keyword == searchTerm) {
          score += 10;
        }
        // Keyword starts with search term = 7 points
        else if (keyword.startsWith(searchTerm)) {
          score += 7;
        }
        // Search term is substring of keyword = 5 points
        else if (keyword.contains(searchTerm)) {
          score += 5;
        }
        // Partial match at word start = 3 points
        else if (searchTerm.startsWith(keyword.substring(0, min(3, keyword.length)))) {
          score += 3;
        }
      }
      
      if (score > 0) {
        scoreMap[entry.key] = (scoreMap[entry.key] ?? 0) + score;
      }
    }
    
    // Convert scored results to sorted list
    if (scoreMap.isNotEmpty) {
      final sortedEntries = scoreMap.entries.toList()
        ..sort((a, b) => b.value.compareTo(a.value));
      results = sortedEntries.map((e) => e.key).toList();
      return results;
    }
    
    // Strategy 3: Fuzzy search (search term contained in keywords)
    for (var entry in emojiKeywords.entries) {
      for (var keyword in entry.value) {
        if (keyword.contains(searchTerm) && !results.contains(entry.key)) {
          results.add(entry.key);
        }
      }
    }
    
    return results;
  }
  
  /// Helper function for minimum value
  static int min(int a, int b) => a < b ? a : b;
}
