class ApiConstants {
  // Backend API Base URL
  // SECURITY: Use environment variable or build flavor
  // For production, use HTTPS with your domain
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    // TODO: Replace with your HTTPS domain before production
    // Example: defaultValue: 'https://api.yourdomain.com'
    defaultValue: 'http://139.59.82.105:8000', // Development only
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