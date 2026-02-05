class ApiConstants {
  // Backend API Base URL - const String.fromEnvironment MUST be in const context only
// Set at build time via: flutter build web --release --dart-define=API_BASE_URL=https://zaply.in.net/api/v1
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'https://zaply.in.net/api/v1',
  );
  
  // Server base URL (without /api/v1) - for avatar images and static files
  static String get serverBaseUrl {
    final uri = Uri.tryParse(baseUrl);
    if (uri == null) return 'https://zaply.in.net';
    
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
      return 'https://zaply.in.net/api/v1';
    }
  }
  
  // WhatsApp Storage Model URLs (Relay-only - files are not stored on server)
  static String get filesUrl => '$serverBaseUrl/files';  // Temporary relay URLs
  static String get mediaUrl => '$serverBaseUrl/media';  // Temporary relay URLs
  static String get imagesUrl => '$serverBaseUrl/images';  // Temporary relay URLs
  static String get videosUrl => '$serverBaseUrl/videos';  // Temporary relay URLs
  static String get audioUrl => '$serverBaseUrl/audio';  // Temporary relay URLs
  static String get documentsUrl => '$serverBaseUrl/documents';  // Temporary relay URLs
  static String get userFilesUrl => '$serverBaseUrl/user-files';  // Temporary relay URLs
  static String get chatFilesUrl => '$serverBaseUrl/chat-files';  // Temporary relay URLs
  static String get thumbnailsUrl => '$serverBaseUrl/thumbnails';  // Temporary relay URLs
  static String get uploadsUrl => '$serverBaseUrl/uploads';  // Temporary relay URLs
  
  // WhatsApp Storage Model File URL Generators (Relay-only)
  static String getFileUrl(String filePath, [String fileType = 'files']) {
    // In WhatsApp model, files are relayed directly and not stored permanently
    // URLs are temporary and will expire after relay
    switch (fileType.toLowerCase()) {
      case 'image':
        return '$imagesUrl/$filePath';
      case 'video':
        return '$videosUrl/$filePath';
      case 'audio':
        return '$audioUrl/$filePath';
      case 'document':
        return '$documentsUrl/$filePath';
      case 'user_file':
        return '$userFilesUrl/$filePath';
      case 'chat_file':
        return '$chatFilesUrl/$filePath';
      case 'thumbnail':
        return '$thumbnailsUrl/$filePath';
      case 'media':
        return '$mediaUrl/$filePath';
      case 'upload':
        return '$uploadsUrl/$filePath';
      default:
        return '$filesUrl/$filePath';
    }
  }
  
  // WhatsApp Storage Model Configuration
  static const bool isUserDeviceStorage = true;  // Files permanent on user device
  static const bool isS3TempStorage = true;  // 24h temp S3 storage
  static const int fileTtlHours = 24;  // 24h temp only like WhatsApp
  static const int serverStorageBytes = 0;  // 0 bytes stored on server
  static const String costModel = "free";  // No server storage cost
  static const String s3Bucket = "hypersend-temp";  // S3 bucket name
  
  // API Endpoints
  static const String authEndpoint = 'auth';
  static const String chatsEndpoint = 'chats';
  static const String messagesEndpoint = 'messages';
  static const String usersEndpoint = 'users';
  static const String filesEndpoint = 'files';
  
  // Timeouts
  static const Duration connectTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);
  
  // WhatsApp Storage Model File size limits (15GB Support - matching backend)
  static const int maxFileSizeBytes = 15 * 1024 * 1024 * 1024; // 15GB in bytes
  static const int maxFileSizeMB = 15 * 1024; // 15GB in MB
  static const Duration uploadTimeout = Duration(hours: 2); // 2 hours for 15GB files
  
  // WhatsApp Storage Model File type limits (15GB Support)
  static const int maxImageSizeMB = 4096; // 4GB for high-res images
  static const int maxVideoSizeMB = 15360; // 15GB for videos
  static const int maxAudioSizeMB = 2048; // 2GB for audio
  static const int maxDocumentSizeMB = 15360; // 15GB for documents
  
  // Convert to bytes
  static const int maxImageSizeBytes = maxImageSizeMB * 1024 * 1024;
  static const int maxVideoSizeBytes = maxVideoSizeMB * 1024 * 1024;
  static const int maxAudioSizeBytes = maxAudioSizeMB * 1024 * 1024;
  static const int maxDocumentSizeBytes = maxDocumentSizeMB * 1024 * 1024;
  
  // Large file threshold (1GB)
  static const int largeFileThresholdMB = 1024;
  static const int largeFileThresholdBytes = largeFileThresholdMB * 1024 * 1024;
  
  // WhatsApp Storage Model Supported file types
  static const List<String> allowedImageTypes = [
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.heic', '.heif'
  ];
  static const List<String> allowedVideoTypes = [
    '.mp4', '.mov', '.avi', '.mkv', '.webm', '.3gp', '.m4v'
  ];
  static const List<String> allowedAudioTypes = [
    '.mp3', '.wav', '.aac', '.m4a', '.ogg', '.flac', '.amr'
  ];
  static const List<String> allowedDocumentTypes = [
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.zip', '.rar'
  ];
  
  static const List<String> restrictedImageTypes = [
    '.exe', '.bat', '.cmd', '.scr', '.msi', '.dll', '.php', '.asp', '.jsp', '.js'
  ];
  
  // Security: Validate SSL certificates in production
  static const bool validateCertificates = bool.fromEnvironment(
    'VALIDATE_CERTIFICATES',
    defaultValue: true, // CRITICAL: Always validate SSL in production
  );
}
