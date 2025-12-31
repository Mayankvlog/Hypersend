import 'package:flutter/foundation.dart';

class ApiConstants {
  // Backend API Base URL - Use hardcoded const value for Flutter web compatibility
  // In production, this is set at build time via --dart-define=API_BASE_URL
  // For Flutter web, we must avoid String.fromEnvironment runtime evaluation
  static const String baseUrl = 'https://zaply.in.net/api/v1';
  
  // Server base URL (without /api/v1) - for avatar images and static files
  static String get serverBaseUrl {
    final uri = Uri.tryParse(baseUrl);
    if (uri == null) return 'https://zaply.in.net';
    
    // Reconstruct URL without /api/v1 path
    final pathSegments = uri.pathSegments;
    // Remove 'api' and 'v1' from path if present
    final cleanPath = pathSegments
        .where((segment) => segment.isNotEmpty && segment != 'api' && segment != 'v1')
        .toList();
    
    return Uri(
      scheme: uri.scheme,
      host: uri.host,
      port: uri.hasPort ? uri.port : null,
      pathSegments: cleanPath,
    ).toString();
  }
  
  // Effective base URL - uses const baseUrl value
  static String get effectiveBaseUrl => baseUrl;
  
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