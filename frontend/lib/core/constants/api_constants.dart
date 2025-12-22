class ApiConstants {
  // Backend API Base URL
  // SECURITY: Use environment variable or build flavor
  // For production, use HTTPS with your domain
  // IMPORTANT: This should be the FULL API base URL including /api/v1
  // Examples: 'https://zaply.in.net/api/v1' or 'http://localhost:8000/api/v1'
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    // Default to production URL with /api/v1 path
    // Override with build flag: --dart-define=API_BASE_URL=https://your-domain.com/api/v1
    defaultValue: 'https://zaply.in.net/api/v1',
  );
  
  // API Endpoints
  static const String authEndpoint = 'auth';
  static const String chatsEndpoint = 'chats';
  static const String messagesEndpoint = 'messages';
  static const String usersEndpoint = 'users';
  static const String filesEndpoint = 'files';
  
  // Timeouts
  static const Duration connectTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);
  
  // Security: Validate SSL certificates in production
  static const bool validateCertificates = bool.fromEnvironment(
    'VALIDATE_CERTIFICATES',
    defaultValue: true,
  );
}