class EmojiUtils {
  static List<String> getEmojiList() {
    final List<String> emojis = [];
    
    // Emoticons (80)
    for (int i = 0x1F600; i <= 0x1F64F; i++) {
      emojis.add(String.fromCharCode(i));
    }
    
    // Misc Symbols and Pictographs (768)
    for (int i = 0x1F300; i <= 0x1F5FF; i++) {
      emojis.add(String.fromCharCode(i));
    }
    
    // Transport and Map Symbols (128)
    for (int i = 0x1F680; i <= 0x1F6FF; i++) {
      emojis.add(String.fromCharCode(i));
    }
    
    // Supplemental Symbols and Pictographs (256)
    for (int i = 0x1F900; i <= 0x1F9FF; i++) {
      emojis.add(String.fromCharCode(i));
    }
    
    return emojis;
  }
}
