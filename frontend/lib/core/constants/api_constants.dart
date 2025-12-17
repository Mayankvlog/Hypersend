class ApiConstants {
  // Backend API Base URL
  // SECURITY: Use environment variable or build flavor
  // For production, use HTTPS with your domain
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    // Default to VPS Nginx HTTPS endpoint that fronts the FastAPI backend.
    // FastAPI routers are mounted under /api/v1, and Nginx proxies /api/ to the backend.
    defaultValue: 'https://139.59.82.105/api/v1',
  );
  
  // API Endpoints
  static const String authEndpoint = '/api/v1/auth';
  static const String chatsEndpoint = '/api/v1/chats';
  static const String messagesEndpoint = '/api/v1/messages';
  static const String usersEndpoint = '/api/v1/users';
  static const String filesEndpoint = '/api/v1/files';
  
  // Timeouts
  static const Duration connectTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);
  
  // Security: Validate SSL certificates in production
  static const bool validateCertificates = bool.fromEnvironment(
    'VALIDATE_CERTIFICATES',
    defaultValue: true,
  );
}