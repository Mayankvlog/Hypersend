class ApiConstants {
  // Backend API Base URL - const String.fromEnvironment MUST be in const context only
// Set at build time via: flutter build web --release --dart-define=API_BASE_URL=http://localhost:8000/api/v1
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://localhost:8000/api/v1',
  );
  
  // Server base URL (without /api/v1) - for avatar images and static files
  static String get serverBaseUrl {
    final uri = Uri.tryParse(baseUrl);
    if (uri == null) return 'http://localhost:8000';
    
    // Logic: Extract scheme, host, and port only (no /api/v1 path)
    final scheme = uri.scheme;
    final host = uri.host;
    
    // Build URL: scheme://host:port (no trailing slash, no path)
    if (uri.hasPort) {
      return '$scheme://$host:${uri.port}';
    }
    return '$scheme://$host';
  }
  
  // Effective base URL - uses const baseUrl value with runtime safety
  static String get effectiveBaseUrl {
    try {
      return baseUrl;
    } catch (e) {
// Fallback for any runtime issues
      return 'http://localhost:8000/api/v1';
    }
  }
  
  // API Endpoints
  static const String authEndpoint = 'auth';
  static const String chatsEndpoint = 'chats';
  static const String messagesEndpoint = 'messages';
  static const String usersEndpoint = 'users';
  static const String filesEndpoint = 'files';
  
  // Timeouts
  static const Duration connectTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);
  
  // File size limits
  static const int maxFileSizeBytes = 40 * 1024 * 1024 * 1024; // 40GB in bytes
  static const int maxFileSizeMB = 40 * 1024; // 40GB in MB
  static const Duration uploadTimeout = Duration(minutes: 30); // 30 minutes for large files
  static const List<String> allowedImageTypes = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'];
  static const List<String> restrictedImageTypes = ['.exe', '.bat', '.cmd', '.scr', '.msi', '.dll', '.php', '.asp', '.jsp', '.js', '.zip', '.rar', '.tar', '.7z'];
  
  // Security: Validate SSL certificates in production
  static const bool validateCertificates = bool.fromEnvironment(
    'VALIDATE_CERTIFICATES',
    defaultValue: true, // CRITICAL: Always validate SSL in production
  );
}
