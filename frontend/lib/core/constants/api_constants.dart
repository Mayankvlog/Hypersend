class ApiConstants {
  // Backend API Base URL
  // SECURITY: Use environment variable or build flavor
  // For production, use HTTPS with your domain
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    // Default to VPS Nginx HTTPS endpoint that fronts the FastAPI backend.
    // FastAPI routers are mounted under /api/v1, and Nginx proxies /api/ to the backend.
    defaultValue: 'https://zaply.in.net/api/v1/',
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