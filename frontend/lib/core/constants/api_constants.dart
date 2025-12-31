import 'package:flutter/foundation.dart';

class ApiConstants {
  // Backend API Base URL
  // SECURITY: Use environment variable or build flavor
  // For production, use HTTPS with your domain
  // IMPORTANT: This should be FULL API base URL including /api/v1
  // Examples: 'https://zaply.in.net/api/v1' or 'http://localhost:8000/api/v1'
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    // Default to production domain with fallback to localhost for development
    // Override with build flag: --dart-define=API_BASE_URL=http://localhost:8000/api/v1
    defaultValue: 'https://zaply.in.net/api/v1',
  );
  
  // Development fallback URL
  static String get effectiveBaseUrl {
    final envUrl = String.fromEnvironment('API_BASE_URL', defaultValue: '');
    if (envUrl.isNotEmpty) return envUrl;
    
    // If production URL is unreachable and we're in debug mode, use localhost
    if (kDebugMode) {
      return 'http://localhost:8080/api/v1';
    }
    
    return baseUrl;
  }
  
  // Server base URL (without /api/v1) - for avatar images and static files
  static String get serverBaseUrl {
    final uri = Uri.tryParse(effectiveBaseUrl);
    if (uri == null) return 'https://zaply.in.net';
    
    // Reconstruct URL without path
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