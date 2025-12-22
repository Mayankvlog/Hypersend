class ApiConstants {
  // Backend API Base URL
  // SECURITY: Use environment variable or build flavor
  // For production, use HTTPS with your domain
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    // Default to relative API path so the frontend works behind nginx proxy in most setups.
    // Use environment variable `API_BASE_URL` to override for specific deployments.
    defaultValue: '/api/v1/',
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