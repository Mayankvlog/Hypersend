class ApiConstants {
  // Backend API Base URL
  // SECURITY: Use environment variable or build flavor
  // For production, use HTTPS with your domain
  // IMPORTANT: This should be the FULL API base URL including /api/v1
  // Examples: 'https://zaply.in.net/api/v1' or 'http://localhost:8000/api/v1'
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    // Default to zaply.in.net production backend with HTTPS
    // Override with build flag: --dart-define=API_BASE_URL=https://your-domain.com/api/v1
    defaultValue: 'https://zaply.in.net/api/v1',  // Production backend
  );
  
  // Server base URL (without /api/v1) - for avatar images and static files
  static String get serverBaseUrl {
    final uri = Uri.tryParse(baseUrl);
    if (uri == null) return 'https://zaply.in.net';  // Production fallback
    
    // Reconstruct URL without the path
    final port = uri.hasPort ? uri.port : null;
    return Uri(
      scheme: uri.scheme,
      host: uri.host,
      port: port,
    ).toString();
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
  static const int maxFileSizeBytes = 5 * 1024 * 1024; // 5MB in bytes
  static const int maxFileSizeMB = 5;
  static const Duration uploadTimeout = Duration(seconds: 60); // 1 minute for large files
  static const String allowedImageTypes = '.jpg,.jpeg,.png,.gif,.webp,.bmp,.svg';
  static const List<String> restrictedImageTypes = ['.exe', '.bat', '.cmd', '.scr', '.msi', '.dll', '.php', '.asp', '.jsp', '.js', '.zip', '.rar', '.tar', '.7z'];
  
  // Security: Validate SSL certificates in production
  static const bool validateCertificates = bool.fromEnvironment(
    'VALIDATE_CERTIFICATES',
    defaultValue: true,
  );
}