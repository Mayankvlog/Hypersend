enum AppLanguage {
  english('en', 'English'),
  hindi('hi', 'हिंदी'),
  spanish('es', 'Español'),
  french('fr', 'Français'),
  german('de', 'Deutsch'),
  portuguese('pt', 'Português'),
  chinese('zh', '中文'),
  japanese('ja', '日本語'),
  korean('ko', '한국어'),
  russian('ru', 'Русский'),
  italian('it', 'Italiano'),
  turkish('tr', 'Türkçe');

  final String code;
  final String label;
  const AppLanguage(this.code, this.label);
}

class SettingsService {
  AppLanguage _currentLanguage = AppLanguage.english;
  bool _darkMode = true;
  bool _notificationsEnabled = true;
  String _selectedThemeColor = '#00B4FF'; // Cyan

  AppLanguage get currentLanguage => _currentLanguage;
  bool get darkMode => _darkMode;
  bool get notificationsEnabled => _notificationsEnabled;
  String get selectedThemeColor => _selectedThemeColor;

  List<AppLanguage> get availableLanguages => AppLanguage.values.toList();

  SettingsService() {
    _loadSettings();
  }

  // Change language
  Future<void> changeLanguage(AppLanguage language) async {
    try {
      _currentLanguage = language;
      await _saveSettings();
    } catch (e) {
      rethrow;
    }
  }

  // Toggle dark mode
  Future<void> toggleDarkMode() async {
    try {
      _darkMode = !_darkMode;
      await _saveSettings();
    } catch (e) {
      rethrow;
    }
  }

  // Set dark mode explicitly
  Future<void> setDarkMode(bool value) async {
    try {
      _darkMode = value;
      await _saveSettings();
    } catch (e) {
      rethrow;
    }
  }

  // Toggle notifications
  Future<void> toggleNotifications() async {
    try {
      _notificationsEnabled = !_notificationsEnabled;
      await _saveSettings();
    } catch (e) {
      rethrow;
    }
  }

  // Change theme color
  Future<void> changeThemeColor(String colorHex) async {
    try {
      _selectedThemeColor = colorHex;
      await _saveSettings();
    } catch (e) {
      rethrow;
    }
  }

  // Get current settings
  Map<String, dynamic> getSettings() {
    return {
      'language': _currentLanguage.code,
      'darkMode': _darkMode,
      'notificationsEnabled': _notificationsEnabled,
      'themeColor': _selectedThemeColor,
    };
  }

  // Load settings from storage
  Future<void> _loadSettings() async {
    try {
      // In a real app, load from SharedPreferences or local storage
      // For now, use defaults - but keep the in-memory values
      _currentLanguage = AppLanguage.english;
      _darkMode = true;
      _notificationsEnabled = true;
      _selectedThemeColor = '#00B4FF';
    } catch (e) {
      // Use defaults on error
    }
  }

  // Save settings to storage
  Future<void> _saveSettings() async {
    try {
      // In a real app, save to SharedPreferences or local storage
      // For now, just store in memory (persists during app session)
    } catch (e) {
      rethrow;
    }
  }

  // Reset to defaults
  Future<void> resetToDefaults() async {
    try {
      _currentLanguage = AppLanguage.english;
      _darkMode = true;
      _notificationsEnabled = true;
      _selectedThemeColor = '#00B4FF';
      await _saveSettings();
    } catch (e) {
      rethrow;
    }
  }
}
