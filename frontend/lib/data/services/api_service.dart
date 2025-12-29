import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart' show kIsWeb, debugPrint, kDebugMode;
import 'package:file_picker/file_picker.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:async';
import 'dart:math';

// Conditional import: dart:io only available on mobile/desktop platforms
import 'dart:io' as io;
import '../../core/constants/api_constants.dart';

class ApiService {
  late final Dio _dio;
  
  // Debug flag - set to false in production
  static const bool _debug = kDebugMode;
  
  void _log(String message) {
    if (_debug) {
      debugPrint(message);
    }
  }

  ApiService() {
    String url = ApiConstants.baseUrl;
    if (!url.endsWith('/')) {
      url += '/';
    }
    
    _log('[API_INIT] Base URL: $url');
    _log('[API_INIT] Server Base URL: ${ApiConstants.serverBaseUrl}');
    _log('[API_INIT] Auth endpoint: ${ApiConstants.authEndpoint}');
    _log('[API_INIT] Users endpoint: ${ApiConstants.usersEndpoint}');
    _log('[API_INIT] Full avatar URL: ${url}${ApiConstants.usersEndpoint}/avatar');
    _log('[API_INIT] SSL validation: ${ApiConstants.validateCertificates}');

    _dio = Dio(
      BaseOptions(
        baseUrl: url,
        connectTimeout: const Duration(seconds: 15),
        receiveTimeout: const Duration(seconds: 15),
        sendTimeout: const Duration(seconds: 15),
        contentType: 'application/json',
        // Allow all status codes to be handled by interceptors for proper 4xx error handling
        validateStatus: (status) => status != null && status < 500,
        headers: {
          'User-Agent': 'Zaply-Flutter-Web/1.0',
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
      ),
    );

    // SSL validation - platform-specific handling
    if (!ApiConstants.validateCertificates && kDebugMode) {
      // Only mobile platforms support onHttpClientCreate
      if (!kIsWeb) {
        (_dio.httpClientAdapter as dynamic).onHttpClientCreate = (client) {
          client.badCertificateCallback = (cert, host, port) => true;
          return client;
        };
        _log('[API_SECURITY] ⚠️ SSL validation disabled - DEBUG MODE ONLY');
      } else {
        // Flutter Web: SSL validation cannot be disabled programmatically
        _log('[API_SECURITY] ⚠️ SSL validation forced on - Flutter Web limitation');
        _log('[API_SECURITY] 🔒 Browser controls SSL certificates');
      }
    } else {
      _log('[API_SECURITY] 🔒 SSL validation enabled - SECURE');
    }

    // Add interceptor for logging (disabled print to avoid leaking secrets)
    _dio.interceptors.add(LogInterceptor(
      requestBody: false,
      responseBody: false,
      logPrint: (obj) {},
    ));
    
    // Add request interceptor to ensure auth tokens are sent
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          // Ensure Content-Type is set for all requests if not already set
          if (!options.headers.containsKey('Content-Type')) {
            options.headers['Content-Type'] = 'application/json';
          }
          // Log auth header for debugging
          final authHeader = options.headers['Authorization'];
          if (authHeader != null) {
            _log('[API_REQ] ${options.method} ${options.uri.path} - Auth: present');
          } else {
            _log('[API_REQ_WARN] ${options.method} ${options.uri.path} - Auth: MISSING!');
          }
          return handler.next(options);
        },
        onError: (error, handler) {
          // Log network errors with detailed info
          if (error.response?.statusCode == null) {
            _log('[API_ERROR] Network/Connection error: ${error.message}');
            _log('[API_ERROR] URL: ${error.requestOptions.uri}');
            _log('[API_ERROR] Method: ${error.requestOptions.method}');
            _log('[API_ERROR] Type: ${error.type}');
            _log('[API_ERROR] Backend unreachable - ensure server is running');
          } else {
            _log('[API_ERROR] HTTP ${error.response?.statusCode}: ${error.message}');
            // Log 401 specifically with headers info for debugging
            if (error.response?.statusCode == 401) {
              _log('[API_ERROR] 401 Unauthorized on ${error.requestOptions.uri}');
              _log('[API_ERROR] Auth header present: ${error.requestOptions.headers.containsKey("Authorization")}');
            }
          }
          return handler.next(error);
        },
      ),
    );
  }

  // Helper method to get user-friendly error message
  static String getErrorMessage(DioException error) {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
        return 'Connection timeout. Please check if the server is running at ${ApiConstants.serverBaseUrl}';
      case DioExceptionType.receiveTimeout:
        return 'Server took too long to respond. Server at ${ApiConstants.serverBaseUrl} may be overloaded. Please try again.';
      case DioExceptionType.badResponse:
        if (error.response?.statusCode == 422) {
          return 'Invalid data format. Please check your inputs.';
        } else if (error.response?.statusCode == 409) {
          return 'Email already in use.';
        } else if (error.response?.statusCode == 401) {
          return 'Unauthorized. Please login again.';
        } else if (error.response?.statusCode == 404) {
          return 'API endpoint not found at ${ApiConstants.serverBaseUrl}';
        }
        return 'Server error: ${error.response?.statusCode}';
      case DioExceptionType.connectionError:
        return 'Cannot connect to server. Please check:\n'
            '1. ✓ Internet connection is active\n'
            '2. Server is running: ${ApiConstants.serverBaseUrl}\n'
            '3. API endpoint (${ApiConstants.baseUrl}) is reachable\n'
            '4. SSL certificates are valid (${ApiConstants.validateCertificates ? "enabled" : "disabled"})\n'
            '5. Security mode: ${ApiConstants.validateCertificates ? "SECURE 🔒" : "DEBUG MODE ⚠️"}\n'
            '6. Platform: ${kIsWeb ? "Flutter Web (browser controls SSL)" : "Mobile"}\n\n'
            'Debug info: ${error.message}\n\n'
            'If you continue seeing this error:\n'
            '• Verify: https://zaply.in.net/health\n'
            '• Check backend container logs: docker compose logs backend\n'
            '• Ensure nginx is proxying requests correctly';
      case DioExceptionType.unknown:
        if (error.message?.contains('SocketException') == true) {
          return 'Network error. Please check internet connection and ensure ${ApiConstants.serverBaseUrl} is accessible.';
        } else if (error.message?.contains('Connection refused') == true) {
          return 'Server at ${ApiConstants.serverBaseUrl} refused connection. Backend may be down.';
        } else if (error.message?.contains('Connection timeout') == true) {
          return 'Connection timeout. Server at ${ApiConstants.serverBaseUrl} is not responding.';
        } else if (error.message?.contains('HandshakeException') == true) {
          return 'SSL/TLS certificate error. The server\'s security certificate may be invalid.';
        }
        return 'Connection error. Please check if ${ApiConstants.serverBaseUrl} is accessible.';
      default:
        return 'An error occurred: ${error.message}';
    }
  }

  // Auth endpoints
  Future<Map<String, dynamic>> register({
    required String email,
    required String password,
    required String name,
  }) async {
    try {
      final response = await _dio.post('${ApiConstants.authEndpoint}/register', data: {
        'email': email,
        'password': password,
        'name': name,
      });
      return response.data ?? {};
    } catch (e) {
      rethrow;
    }
  }

  Future<Map<String, dynamic>> login({
    required String email,
    required String password,
  }) async {
    try {
      final loginUrl = '${ApiConstants.authEndpoint}/login';
      _log('[API_LOGIN] Full URL: ${_dio.options.baseUrl}$loginUrl');
      final response = await _dio.post(loginUrl, data: {
        'email': email,
        'password': password,
      });
      return response.data ?? {};
    } catch (e) {
      rethrow;
    }
  }

  Future<Map<String, dynamic>> logout({required String refreshToken}) async {
    final response = await _dio.post(
      '${ApiConstants.authEndpoint}/logout',
      data: {'refresh_token': refreshToken},
    );
    return response.data;
  }

  // User endpoints
  Future<Map<String, dynamic>> getMe() async {
    try {
      _log('[API_ME] Fetching current user profile');
      final response = await _dio.get('${ApiConstants.usersEndpoint}/me');
      _log('[API_ME] Success: ${response.data}');
      return response.data ?? {};
    } catch (e) {
      _log('[API_ME_ERROR] Failed: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> updateProfile(Map<String, dynamic> data) async {
    try {
      _log('[API_PROFILE] Updating profile with fields: ${data.keys.toList()}');
      _log('[API_PROFILE] Payload: $data');
      _log('[API_PROFILE] Endpoint: ${ApiConstants.usersEndpoint}/profile');
      final response = await _dio.put('${ApiConstants.usersEndpoint}/profile', data: data);
      _log('[API_PROFILE] Response status: ${response.statusCode}');
      _log('[API_PROFILE] Response data: ${response.data}');
      return response.data ?? {};
    } on DioException catch (e) {
      _log('[API_PROFILE_ERROR] Dio error: ${e.message}');
      _log('[API_PROFILE_ERROR] Status code: ${e.response?.statusCode}');
      _log('[API_PROFILE_ERROR] Response data: ${e.response?.data}');
      rethrow;
    } catch (e) {
      _log('[API_PROFILE_ERROR] Failed to update profile: $e');
      rethrow;
    }
  }

Future<Map<String, dynamic>> uploadAvatar(Uint8List bytes, String filename) async {
    try {
      debugPrint('[API_SERVICE] Uploading avatar: $filename (${bytes.length} bytes)');
      
      final formData = FormData.fromMap({
        'file': MultipartFile.fromBytes(bytes, filename: filename),
      });
      
      // Remove Content-Type header to let Dio set it automatically with correct boundary
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/avatar', 
        data: formData,
        options: Options(
          method: 'POST',
          sendTimeout: const Duration(seconds: 30),
          receiveTimeout: const Duration(seconds: 30),
          headers: {
            'Accept': 'application/json',
            // Remove Content-Type to let Dio handle multipart/form-data with proper boundary
          },
        ),
      );
      
      debugPrint('[API_SERVICE] Avatar upload status: ${response.statusCode}');
      debugPrint('[API_SERVICE] Avatar upload response: ${response.data}');
      debugPrint('[API_SERVICE] Response data type: ${response.data.runtimeType}');
      debugPrint('[API_SERVICE] Response headers: ${response.headers}');
      
      // Try to manually parse if it's a string
      if (response.data is String) {
        debugPrint('[API_SERVICE] Response is String, attempting to parse JSON...');
        try {
          final parsed = jsonDecode(response.data as String);
          debugPrint('[API_SERVICE] Parsed JSON successfully: $parsed');
          debugPrint('[API_SERVICE] Parsed type: ${parsed.runtimeType}');
        } catch (e) {
          debugPrint('[API_SERVICE] JSON parsing failed: $e');
        }
      }
      
      if (response.data == null) {
        throw Exception('Empty response from server');
      }
      
      // Handle different response formats
      if (response.data is Map<String, dynamic>) {
        return response.data as Map<String, dynamic>;
      } else if (response.data is Map) {
        // Convert generic Map to Map<String, dynamic>
        return Map<String, dynamic>.from(response.data as Map);
      } else if (response.data is String) {
        // Try to parse JSON string
        try {
          final parsed = jsonDecode(response.data as String);
          if (parsed is Map) {
            return Map<String, dynamic>.from(parsed);
          }
        } catch (e) {
          debugPrint('[API_SERVICE] Failed to parse JSON string: $e');
        }
        debugPrint('[API_SERVICE] Response is not a Map: ${response.data}');
        throw Exception('Invalid response format from server: expected JSON object');
      } else {
        debugPrint('[API_SERVICE] Response is not a Map: ${response.data}');
        debugPrint('[API_SERVICE] Response type: ${response.data.runtimeType}');
        throw Exception('Invalid response format from server: expected JSON object');
      }
    } on DioException catch (e) {
      debugPrint('[API_SERVICE] DioException during avatar upload: ${e.type} - ${e.message}');
      debugPrint('[API_SERVICE] Response status: ${e.response?.statusCode}');
      debugPrint('[API_SERVICE] Response data: ${e.response?.data}');
      
      String errorMessage = 'Failed to upload avatar';
      if (e.response?.data is Map) {
        final data = e.response!.data as Map;
        errorMessage = data['detail'] ?? errorMessage;
      } else if (e.type == DioExceptionType.sendTimeout) {
        errorMessage = 'Upload timeout - please check your connection and try again';
      } else if (e.type == DioExceptionType.receiveTimeout) {
        errorMessage = 'Server timeout - please try again';
      }
      
      throw Exception(errorMessage);
    } catch (e) {
      debugPrint('[API_SERVICE] Error during avatar upload: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> getFileInfo(String fileId) async {
    try {
      debugPrint('[API_SERVICE] Getting file info for: $fileId');
      final response = await _dio.get('${ApiConstants.filesEndpoint}/$fileId/info');
      debugPrint('[API_SERVICE] File info response: ${response.data}');
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error getting file info: $e');
      rethrow;
    }
  }



  Future<Map<String, dynamic>> getSavedChat() async {
    try {
      final response = await _dio.get('${ApiConstants.chatsEndpoint}/saved');
      return response.data ?? {};
    } catch (e) {
      rethrow;
    }
  }

  // Chat endpoints
  Future<List<Map<String, dynamic>>> getChats() async {
    try {
      _log('[API_CHATS] Fetching chats from ${ApiConstants.chatsEndpoint}');
      final response = await _dio.get(ApiConstants.chatsEndpoint);
      _log('[API_CHATS] Success: received ${response.data?['chats']?.length ?? 0} chats');
      return List<Map<String, dynamic>>.from(response.data?['chats'] ?? const []);
    } catch (e) {
      _log('[API_CHATS_ERROR] Failed to fetch chats: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> getChatMessages(String chatId) async {
    try {
      final response = await _dio.get('${ApiConstants.chatsEndpoint}/$chatId/messages');
      return response.data ?? {};
    } catch (e) {
      rethrow;
    }
  }

  Future<List<Map<String, dynamic>>> searchMessages(String query, {String? chatId}) async {
    final response = await _dio.get(
      '${ApiConstants.messagesEndpoint}/search', 
      queryParameters: {
        'q': query,
        if (chatId != null) 'chat_id': chatId,
      },
    );
    return List<Map<String, dynamic>>.from(response.data?['messages'] ?? []);
  }

  Future<List<Map<String, dynamic>>> searchUsers(String query) async {
    final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/search',
        queryParameters: {'q': query},
    );
    return List<Map<String, dynamic>>.from(response.data?['users'] ?? []);
  }

  Future<List<Map<String, dynamic>>> searchUsersByEmail(String email) async {
    final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/search',
        queryParameters: {'q': email, 'search_type': 'email'},
    );
    return List<Map<String, dynamic>>.from(response.data?['users'] ?? []);
  }

  Future<List<Map<String, dynamic>>> searchUsersByUsername(String username) async {
    // Remove @ if user included it
    final cleanUsername = username.startsWith('@') ? username.substring(1) : username;
    final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/search',
        queryParameters: {'q': cleanUsername, 'search_type': 'username'},
    );
    return List<Map<String, dynamic>>.from(response.data?['users'] ?? []);
  }

  Future<Map<String, dynamic>> sendMessage({
    required String chatId,
    String? content,
    String? fileId,
  }) async {
    try {
      final response = await _dio.post('${ApiConstants.chatsEndpoint}/$chatId/messages', data: {
        'text': content,
        'file_id': fileId,
      });
      return response.data ?? {};
    } catch (e) {
      rethrow;
    }
  }

  // Message actions
  Future<Map<String, dynamic>> editMessage(String messageId, String text) async {
    final response = await _dio.put(
      '${ApiConstants.messagesEndpoint}/$messageId',
      data: {'text': text},
    );
    return response.data;
  }

  Future<Map<String, dynamic>> deleteMessage(String messageId, {bool hardDelete = false}) async {
    final response = await _dio.delete(
      '${ApiConstants.messagesEndpoint}/$messageId',
      queryParameters: {'hard_delete': hardDelete},
    );
    return response.data;
  }

  Future<Map<String, dynamic>> toggleReaction(String messageId, String emoji) async {
    final response = await _dio.post(
      '${ApiConstants.messagesEndpoint}/$messageId/reactions',
      data: {'emoji': emoji},
    );
    return response.data;
  }

  Future<Map<String, dynamic>> pinMessage(String messageId) async {
    final response = await _dio.post('${ApiConstants.messagesEndpoint}/$messageId/pin');
    return response.data;
  }

  Future<Map<String, dynamic>> unpinMessage(String messageId) async {
    final response = await _dio.post('${ApiConstants.messagesEndpoint}/$messageId/unpin');
    return response.data;
  }

  Future<Map<String, dynamic>> markRead(String messageId) async {
    final response = await _dio.post('${ApiConstants.messagesEndpoint}/$messageId/read');
    return response.data;
  }

  Future<void> pinChat(String chatId) async {
    await _dio.post('${ApiConstants.chatsEndpoint}/$chatId/pin_chat');
  }

  Future<void> unpinChat(String chatId) async {
    await _dio.post('${ApiConstants.chatsEndpoint}/$chatId/unpin_chat');
  }



  Future<Map<String, dynamic>> getChannel(String channelId) async {
    final response = await _dio.get('channels/$channelId');
    return response.data;
  }

  Future<void> subscribeChannel(String channelId) async {
    await _dio.post('channels/$channelId/subscribe');
  }

Future<void> postToChannel(String channelId, String text) async {
    await _dio.post(
      'channels/$channelId/posts',
      data: {
        'text': text 
        // Note: Backend might expect MessageCreate format, keeping it simple for now
      },
    );
  }

  Future<void> removeChannel(String channelId) async {
    await _dio.post('channels/$channelId/remove');
  }

  Future<Map<String, dynamic>> createChat({
    required String targetUserId,
    String type = 'direct',
  }) async {
    final response = await _dio.post(
      ApiConstants.chatsEndpoint,
      data: {
        'type': type,
        'member_ids': [targetUserId],
      },
    );
    return response.data;
  }

  Future<Map<String, dynamic>> createGroup({
    required String name,
    String description = '',
    String? avatarUrl,
    required List<String> memberIds,
  }) async {
    final response = await _dio.post(
      'groups',
      data: {
        'name': name,
        'description': description,
        'avatar_url': avatarUrl,
        'member_ids': memberIds,
      },
    );
    return response.data;
  }

  Future<Map<String, dynamic>> getGroup(String groupId) async {
    final response = await _dio.get('groups/$groupId');
    return response.data;
  }

  Future<Map<String, dynamic>> updateGroup(String groupId, Map<String, dynamic> data) async {
    final response = await _dio.put('groups/$groupId', data: data);
    return response.data;
  }

  Future<Map<String, dynamic>> addGroupMembers(String groupId, List<String> userIds) async {
    final response = await _dio.post('groups/$groupId/members', data: {'user_ids': userIds});
    return response.data;
  }

  Future<Map<String, dynamic>> removeGroupMember(String groupId, String memberId) async {
    final response = await _dio.delete('groups/$groupId/members/$memberId');
    return response.data;
  }

  Future<Map<String, dynamic>> updateGroupMemberRole(String groupId, String memberId, String role) async {
    final response = await _dio.put('groups/$groupId/members/$memberId/role', data: {'role': role});
    return response.data;
  }

  Future<Map<String, dynamic>> leaveGroup(String groupId) async {
    final response = await _dio.post('groups/$groupId/leave');
    return response.data;
  }

  Future<Map<String, dynamic>> deleteGroup(String groupId) async {
    final response = await _dio.delete('groups/$groupId');
    return response.data;
  }

  Future<Map<String, dynamic>> muteGroup(String groupId, {required bool mute}) async {
    final response = await _dio.post('groups/$groupId/mute', queryParameters: {'mute': mute});
    return response.data;
  }

  Future<Map<String, dynamic>> getGroupActivity(String groupId, {int limit = 50}) async {
    final response = await _dio.get('groups/$groupId/activity', queryParameters: {'limit': limit});
    return response.data;
  }

  Future<Map<String, dynamic>> getPinnedMessages(String groupId, {int limit = 20}) async {
    final response = await _dio.get('groups/$groupId/pinned', queryParameters: {'limit': limit});
    return response.data;
  }

  // Files (resumable upload)
  Future<Map<String, dynamic>> initUpload({
    required String filename,
    required int size,
    required String mime,
    required String chatId,
    String? checksum,
  }) async {
    final response = await _dio.post(
      '${ApiConstants.filesEndpoint}/init',
      data: {
        'filename': filename,
        'size': size,
        'mime': mime,
        'chat_id': chatId,
        if (checksum != null) 'checksum': checksum,
      },
    );
    return response.data;
  }

  Future<void> uploadChunk({
    required String uploadId,
    required int chunkIndex,
    required Uint8List bytes,
    String? chunkChecksum,
  }) async {
    await _dio.put(
      '${ApiConstants.filesEndpoint}/$uploadId/chunk',
      data: bytes,
      options: Options(
        contentType: 'application/octet-stream',
        sendTimeout: const Duration(minutes: 10),
        headers: {
          if (chunkChecksum != null) 'x-chunk-checksum': chunkChecksum,
        },
      ),
      queryParameters: {'chunk_index': chunkIndex},
    );
  }

  Future<Map<String, dynamic>> completeUpload({required String uploadId}) async {
    final response = await _dio.post('${ApiConstants.filesEndpoint}/$uploadId/complete');
    return response.data;
  }

  Future<void> downloadFileToPath({
    required String fileId,
    required String savePath,
    void Function(int, int)? onReceiveProgress,
  }) async {
    await _dio.download(
      '${ApiConstants.filesEndpoint}/$fileId/download',
      savePath,
      onReceiveProgress: onReceiveProgress,
    );
  }

  Future<Response<Uint8List>> downloadFileBytes(String fileId) async {
    return await _dio.get<Uint8List>(
      '${ApiConstants.filesEndpoint}/$fileId/download',
      options: Options(
        responseType: ResponseType.bytes,
        followRedirects: false,
      ),
    );
  }

  // Settings endpoints
  Future<Map<String, dynamic>> getSettings() async {
    // Not implemented in backend yet (reserved for future)
    return {};
  }

  Future<Map<String, dynamic>> updateSettings(Map<String, dynamic> settings) async {
    // Not implemented in backend yet (reserved for future)
    return {};
  }

  // Additional user endpoints
  Future<bool> changePassword({
    required String oldPassword,
    required String newPassword,
  }) async {
    try {
      _log('[API_CHANGE_PASSWORD] Sending password change request');
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/change-password',
        data: {
          'old_password': oldPassword,
          'new_password': newPassword,
        },
      );
      _log('[API_CHANGE_PASSWORD] Success: ${response.statusCode}');
      return response.statusCode == 200;
    } on DioException catch (e) {
      _log('[API_CHANGE_PASSWORD_ERROR] Dio error: ${e.message}');
      _log('[API_CHANGE_PASSWORD_ERROR] Status code: ${e.response?.statusCode}');
      _log('[API_CHANGE_PASSWORD_ERROR] Response data: ${e.response?.data}');
      rethrow;
    } catch (e) {
      _log('[API_CHANGE_PASSWORD_ERROR] Failed: $e');
      rethrow;
    }
  }

  Future<bool> resetPassword({required String email}) async {
    try {
      _log('[API_RESET_PASSWORD] Sending forgot-password request for: $email');
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/forgot-password',
        data: {'email': email},
      );
      _log('[API_RESET_PASSWORD] Success: ${response.statusCode}');
      return response.statusCode == 200 || response.statusCode == 201;
    } on DioException catch (e) {
      _log('[API_RESET_PASSWORD_ERROR] Dio error: ${e.message}');
      _log('[API_RESET_PASSWORD_ERROR] Status code: ${e.response?.statusCode}');
      _log('[API_RESET_PASSWORD_ERROR] Response: ${e.response?.data}');
      rethrow;
    } catch (e) {
      _log('[API_RESET_PASSWORD_ERROR] Failed: $e');
      rethrow;
    }
  }

  Future<bool> changeEmail({
    required String newEmail,
    required String password,
  }) async {
    try {
      _log('[API_CHANGE_EMAIL] Sending change email request for: $newEmail');
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/change-email',
        data: {
          'email': newEmail,
          'password': password,
        },
      );
      _log('[API_CHANGE_EMAIL] Success: ${response.statusCode}');
      return response.statusCode == 200;
    } on DioException catch (e) {
      _log('[API_CHANGE_EMAIL_ERROR] Dio error: ${e.message}');
      _log('[API_CHANGE_EMAIL_ERROR] Status code: ${e.response?.statusCode}');
      rethrow;
    } catch (e) {
      _log('[API_CHANGE_EMAIL_ERROR] Failed: $e');
      rethrow;
    }
  }

  void setAuthToken(String token) {
    final authHeader = 'Bearer $token';
    _dio.options.headers['Authorization'] = authHeader;
    _log('[API_AUTH] Token set (Bearer token), length: ${token.length}');
  }

  void clearAuthToken() {
    _dio.options.headers.remove('Authorization');
    _log('[API_AUTH] Token cleared from headers');
  }

  Future<FilePickerResult?> pickFile() async {
    return await FilePicker.platform.pickFiles(
      withData: true,
      allowMultiple: false,
    );
  }

  // Test connectivity to API endpoints
  Future<Map<String, dynamic>> testConnectivity() async {
    try {
      _log('[API_CONNECTIVITY] Testing connection to ${_dio.options.baseUrl}');
      
      // Test health endpoint
      final healthResponse = await _dio.get('/health');
      _log('[API_CONNECTIVITY] Health endpoint: ${healthResponse.statusCode}');
      
      // Test auth endpoint availability
      try {
        await _dio.head('${ApiConstants.authEndpoint}/login');
        _log('[API_CONNECTIVITY] Auth endpoint: Available');
      } catch (e) {
        _log('[API_CONNECTIVITY] Auth endpoint error: $e');
      }
      
      return {
        'connected': true,
        'baseUrl': _dio.options.baseUrl,
        'authEndpoint': '${ApiConstants.authEndpoint}/login',
        'healthStatus': healthResponse.statusCode,
      };
    } catch (e) {
      _log('[API_CONNECTIVITY] Connection failed: $e');
      return {
        'connected': false,
        'error': e.toString(),
        'baseUrl': _dio.options.baseUrl,
        'serverUrl': ApiConstants.serverBaseUrl,
      };
    }
  }

  // Contact Management Methods
  


  // Location and People Nearby endpoints
  Future<Map<String, dynamic>> updateLocation({
    required double latitude,
    required double longitude,
  }) async {
    try {
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/location/update',
        queryParameters: {
          'lat': latitude,
          'lng': longitude,
        },
      );
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error updating location: $e');
      rethrow;
    }
  }

  Future<void> clearLocation() async {
    try {
      await _dio.post('${ApiConstants.usersEndpoint}/location/clear');
    } catch (e) {
      debugPrint('[API_SERVICE] Error clearing location: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> getNearbyUsers({
    required double latitude,
    required double longitude,
    double radiusMeters = 1000,
  }) async {
    try {
      final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/nearby',
        queryParameters: {
          'lat': latitude,
          'lng': longitude,
          'radius': radiusMeters,
        },
      );
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error fetching nearby users: $e');
      rethrow;
    }
  }

  // ============ LOCAL FILE STORAGE FUNCTIONS ============
  
  // Maximum file size: 40GB
  static const int maxFileSizeBytes = 40 * 1024 * 1024 * 1024; // 40GB in bytes
  
  /// Validates if a file can be stored locally based on size
  /// Returns true if file size is within 40GB limit
  bool isFileSizeValid(int fileSizeBytes) {
    if (fileSizeBytes <= 0) {
      _log('[LOCAL_STORAGE] Invalid file size: $fileSizeBytes');
      return false;
    }
    
    if (fileSizeBytes > maxFileSizeBytes) {
      _log('[LOCAL_STORAGE] File size exceeds 40GB limit: ${(fileSizeBytes / (1024 * 1024 * 1024)).toStringAsFixed(2)}GB');
      return false;
    }
    
    _log('[LOCAL_STORAGE] File size valid: ${(fileSizeBytes / (1024 * 1024)).toStringAsFixed(2)}MB');
    return true;
  }
  
  /// Saves file data to local storage with validation
  /// Returns the file path where saved
  Future<String> saveFileLocally({
    required String fileName,
    required Uint8List fileData,
    required String localStoragePath,
  }) async {
    try {
      _log('[LOCAL_STORAGE] Saving file: $fileName');
      
      // Validate file size
      if (!isFileSizeValid(fileData.length)) {
        throw Exception('File size exceeds 40GB limit');
      }
      
// Ensure directory exists (web: uses IndexedDB/LocalStorage, mobile: uses file system)
      if (!kIsWeb) {
        // Mobile platform - use actual file system
        final directory = io.Directory(localStoragePath);
        // Fix: Use path string instead of Directory object
        final filePath = io.Platform.isWindows ? '$localStoragePath\\$fileName' : '$localStoragePath/$fileName';
        final file = io.File(filePath);
        
        // Create directory if needed
        await file.parent.create(recursive: true);
        
        // Write file
        await file.writeAsBytes(fileData);
        
        _log('[LOCAL_STORAGE] File saved successfully at: ${file.path}');
        _log('[LOCAL_STORAGE] File size: ${(fileData.length / (1024 * 1024)).toStringAsFixed(2)}MB');
        
        return file.path;
      } else {
        // Web platform - file storage not supported
        _log('[LOCAL_STORAGE] Web platform: File storage not supported');
        return '';
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to save file: $e');
      rethrow;
    }
  }
  
/// Retrieves file data from local storage
  /// Returns the file data as Uint8List
  Future<Uint8List> getFileLocally({
    required String fileName,
    required String localStoragePath,
  }) async {
    try {
      _log('[LOCAL_STORAGE] Retrieving file: $fileName');
      
      if (!kIsWeb) {
        // Mobile platform
        final directory = io.Directory(localStoragePath);
        
        if (!await directory.exists()) {
          _log('[LOCAL_STORAGE] Directory does not exist: $localStoragePath');
          return Uint8List(0);
        }
        
        // Fix: Use path string instead of Directory object
        final filePath = io.Platform.isWindows ? '$localStoragePath\\$fileName' : '$localStoragePath/$fileName';
        final file = io.File(filePath);
        if (!await file.exists()) {
          _log('[LOCAL_STORAGE] File does not exist: $fileName');
          return Uint8List(0);
        }
        
        final fileData = await file.readAsBytes();
        _log('[LOCAL_STORAGE] File retrieved successfully: $fileName');
        return fileData;
      } else {
        // Web platform - not supported for direct file access
        _log('[LOCAL_STORAGE] Web platform: Direct file access not supported');
        return Uint8List(0);
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to get file: $e');
      return Uint8List(0);
    }
  }
  
  /// Gets total size of all files in local storage
  /// Returns size in bytes
  Future<int> getTotalLocalStorageSize(String localStoragePath) async {
    try {
      _log('[LOCAL_STORAGE] Calculating total storage size');
      
if (!kIsWeb) {
        // Mobile platform
        final directory = io.Directory(localStoragePath);
        
        if (!await directory.exists()) {
          return 0;
        }
        
        int totalSize = 0;
        final files = await directory.list(recursive: true).toList();
        
        for (var file in files) {
          if (file is io.File) {
            totalSize += await file.length();
          }
        }
        
        _log('[LOCAL_STORAGE] Total size: ${(totalSize / (1024 * 1024 * 1024)).toStringAsFixed(2)}GB / 40GB');
        return totalSize;
      } else {
        return 0;
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to calculate storage size: $e');
      return 0;
    }
  }
  
  /// Checks if there is enough space to store a new file
  /// Returns true if enough space available
  Future<bool> hasEnoughStorageSpace({
    required int requiredBytes,
    required String localStoragePath,
  }) async {
    try {
      final totalUsed = await getTotalLocalStorageSize(localStoragePath);
      final totalAvailable = maxFileSizeBytes;
      
      if (totalUsed + requiredBytes > totalAvailable) {
        _log('[LOCAL_STORAGE] Insufficient storage: ${(totalUsed / (1024 * 1024 * 1024)).toStringAsFixed(2)}GB used + ${(requiredBytes / (1024 * 1024)).toStringAsFixed(2)}MB required > 40GB limit');
        return false;
      }
      
      _log('[LOCAL_STORAGE] Sufficient storage available');
      return true;
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to check storage space: $e');
      return false;
    }
  }
  
  /// Clears all files from local storage directory
  /// Returns number of files deleted
  Future<int> clearLocalStorage(String localStoragePath) async {
    try {
      _log('[LOCAL_STORAGE] Clearing all files from: $localStoragePath');
      
if (!kIsWeb) {
        // Mobile platform
        final directory = io.Directory(localStoragePath);
        
        if (!await directory.exists()) {
          return 0;
        }
        
        int deletedCount = 0;
        final files = await directory.list().toList();
        
        for (var file in files) {
          if (file is io.File) {
            await file.delete();
            deletedCount++;
          }
        }
        
        _log('[LOCAL_STORAGE] Cleared $deletedCount files');
        return deletedCount;
      } else {
        return 0;
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to clear storage: $e');
      rethrow;
    }
  }

  // ============ QR CODE CROSS-PLATFORM LINKING FUNCTIONS ============
  
  /// Generates a QR code for connecting same account across multiple platforms
  /// Works for: Mobile APK, Web Page, Desktop App
  /// Device types: 'mobile', 'web', 'desktop'
  /// Returns session ID, session code, and QR code data
  Future<Map<String, dynamic>> generateQRCodeForSameAccount({
    required String deviceType, // 'mobile', 'web', 'desktop'
    String? deviceName,
  }) async {
    try {
      _log('[QR_CODE_SAME_ACCOUNT] Generating QR code for same account connection');
      _log('[QR_CODE_SAME_ACCOUNT] Device Type: $deviceType');
      
      // Validate device type
      const validDevices = ['mobile', 'web', 'desktop'];
      if (!validDevices.contains(deviceType.toLowerCase())) {
        throw Exception('Invalid device type. Must be one of: ${validDevices.join(", ")}');
      }
      
      // Call backend to generate QR code
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/qrcode/generate',
        data: {
          'device_type': deviceType.toLowerCase(),
          'device_name': deviceName ?? _getDeviceName(),
        },
      );
      
      final result = response.data ?? {};
      
      _log('[QR_CODE_SAME_ACCOUNT] QR code generated successfully');
      _log('[QR_CODE_SAME_ACCOUNT] Session ID: ${result['session_id']}');
      _log('[QR_CODE_SAME_ACCOUNT] Device: $deviceType');
      
      return {
        'session_id': result['session_id'],
        'session_code': result['session_code'],
        'qr_code_data': result['qr_code_data'],
        'device_type': deviceType.toLowerCase(),
        'device_name': deviceName ?? _getDeviceName(),
        'expiry_seconds': result['expires_in_seconds'] ?? 300,
        'verification_url': result['verification_url'],
      };
    } catch (e) {
      _log('[QR_CODE_SAME_ACCOUNT_ERROR] Failed to generate QR code: $e');
      rethrow;
    }
  }
  
  /// Verifies QR code with session code for same account connection
  /// Returns authentication tokens for the new device
  Future<Map<String, dynamic>> verifyQRCodeForSameAccount({
    required String sessionId,
    required String sessionCode,
  }) async {
    try {
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT] Verifying QR code');
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT] Session ID: $sessionId');
      
      // Call backend to verify QR code
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/qrcode/verify',
        data: {
          'session_id': sessionId,
          'session_code': sessionCode,
        },
      );
      
      final result = response.data ?? {};
      
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT] QR code verified successfully');
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT] Access token received');
      
      return {
        'access_token': result['access_token'],
        'refresh_token': result['refresh_token'],
        'token_type': result['token_type'] ?? 'bearer',
        'user_id': result['user_id'],
        'user_name': result['user_name'],
        'device_id': result['device_id'],
        'device_type': result['device_type'],
        'expires_in': result['expires_in'],
      };
    } catch (e) {
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT_ERROR] Failed to verify QR code: $e');
      rethrow;
    }
  }
  
  /// Gets list of all devices connected to same account
  /// Shows device info: name, type, last seen, status
  Future<List<Map<String, dynamic>>> getConnectedDevices() async {
    try {
      _log('[QR_CODE_DEVICES] Fetching connected devices for same account');
      
      final response = await _dio.get('${ApiConstants.usersEndpoint}/devices');
      
      final devices = (response.data as List?)?.cast<Map<String, dynamic>>() ?? [];
      
      _log('[QR_CODE_DEVICES] Found ${devices.length} connected devices');
      
      return devices;
    } catch (e) {
      _log('[QR_CODE_DEVICES_ERROR] Failed to fetch connected devices: $e');
      return [];
    }
  }
  
  /// Disconnects a device from same account
  /// Revokes access tokens for that device
  Future<bool> disconnectDevice(String deviceId) async {
    try {
      _log('[QR_CODE_DISCONNECT] Disconnecting device: $deviceId');
      
      final response = await _dio.delete(
        '${ApiConstants.usersEndpoint}/devices/$deviceId',
      );
      
      _log('[QR_CODE_DISCONNECT] Device disconnected successfully');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_DISCONNECT_ERROR] Failed to disconnect device: $e');
      rethrow;
    }
  }
  
  /// Syncs account data across all connected devices
  /// Ensures messages and settings are consistent
  Future<Map<String, dynamic>> syncAccountDataAcrossDevices({
    required String dataType, // 'chats', 'messages', 'settings'
    Map<String, dynamic>? additionalData,
  }) async {
    try {
      _log('[QR_CODE_SYNC] Syncing $dataType across all connected devices');
      
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/sync',
        data: {
          'data_type': dataType,
          'timestamp': DateTime.now().millisecondsSinceEpoch,
          ...?additionalData,
        },
      );
      
      _log('[QR_CODE_SYNC] Data sync completed for: $dataType');
      
      return response.data ?? {};
    } catch (e) {
      _log('[QR_CODE_SYNC_ERROR] Failed to sync $dataType: $e');
      rethrow;
    }
  }
  
  /// Gets synchronization status for all connected devices
  /// Shows which devices are online/offline and last sync time
  Future<Map<String, dynamic>> getDeviceSyncStatus() async {
    try {
      _log('[QR_CODE_SYNC_STATUS] Fetching device synchronization status');
      
      final response = await _dio.get('${ApiConstants.usersEndpoint}/sync-status');
      
      final data = response.data ?? {};
      
      _log('[QR_CODE_SYNC_STATUS] Sync status retrieved');
      _log('[QR_CODE_SYNC_STATUS] Devices online: ${data['devices_online']}');
      _log('[QR_CODE_SYNC_STATUS] Last sync: ${data['last_sync']}');
      
      return data;
    } catch (e) {
      _log('[QR_CODE_SYNC_STATUS_ERROR] Failed to fetch sync status: $e');
      return {};
    }
  }
  
  /// Enables real-time synchronization across all devices
  /// When enabled, changes on one device instantly reflect on others
  Future<bool> enableCrossDeviceSync() async {
    try {
      _log('[QR_CODE_ENABLE_SYNC] Enabling cross-device synchronization');
      
      final response = await _dio.put(
        '${ApiConstants.usersEndpoint}/settings/sync',
        data: {'enabled': true},
      );
      
      _log('[QR_CODE_ENABLE_SYNC] Cross-device sync enabled');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_ENABLE_SYNC_ERROR] Failed to enable sync: $e');
      rethrow;
    }
  }
  
  /// Disables real-time synchronization across devices
  Future<bool> disableCrossDeviceSync() async {
    try {
      _log('[QR_CODE_DISABLE_SYNC] Disabling cross-device synchronization');
      
      final response = await _dio.put(
        '${ApiConstants.usersEndpoint}/settings/sync',
        data: {'enabled': false},
      );
      
      _log('[QR_CODE_DISABLE_SYNC] Cross-device sync disabled');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_DISABLE_SYNC_ERROR] Failed to disable sync: $e');
      rethrow;
    }
  }
  
  /// Checks if current device is the primary device for the account
  /// Primary device can manage other connected devices
  Future<bool> isPrimaryDevice() async {
    try {
      _log('[QR_CODE_PRIMARY] Checking if current device is primary');
      
      final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/device-status/is-primary',
      );
      
      final isPrimary = response.data?['is_primary'] ?? false;
      
      _log('[QR_CODE_PRIMARY] Primary device: $isPrimary');
      
      return isPrimary;
    } catch (e) {
      _log('[QR_CODE_PRIMARY_ERROR] Failed to check primary device: $e');
      return false;
    }
  }
  
  /// Gets complete account connection info for same account setup
  /// Returns user, all devices, and sync settings
  Future<Map<String, dynamic>> getAccountConnectionInfo() async {
    try {
      _log('[QR_CODE_ACCOUNT_INFO] Fetching account connection information');
      
      // Get user info
      final userInfo = await getMe();
      
      // Get connected devices
      final devices = await getConnectedDevices();
      
      // Get sync status
      final syncStatus = await getDeviceSyncStatus();
      
      _log('[QR_CODE_ACCOUNT_INFO] Account info retrieved successfully');
      
      return {
        'user': userInfo,
        'devices': devices,
        'sync_status': syncStatus,
        'total_devices': devices.length,
        'timestamp': DateTime.now().toIso8601String(),
      };
    } catch (e) {
      _log('[QR_CODE_ACCOUNT_INFO_ERROR] Failed to get account connection info: $e');
      rethrow;
    }
  }
  
  /// Generates a QR code for cross-platform account linking (Legacy - use generateQRCodeForSameAccount)
  /// Works for: Mobile APK, Web Page, Desktop App
  /// Returns QR code data string and pairing token
  Future<Map<String, dynamic>> generateQRCodeForPairing({
    required String userId,
    required String userName,
    String? deviceName,
  }) async {
    try {
      _log('[QR_CODE] Generating QR code for cross-platform pairing');
      
      // Generate unique pairing session token
      final pairingToken = _generatePairingToken();
      final sessionId = _generateSessionId();
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      
      // Create pairing data object
      final pairingData = {
        'type': 'account_linking',
        'session_id': sessionId,
        'pairing_token': pairingToken,
        'user_id': userId,
        'user_name': userName,
        'device_name': deviceName ?? _getDeviceName(),
        'timestamp': timestamp,
        'expiry': timestamp + (15 * 60 * 1000), // Expires in 15 minutes
        'server_url': ApiConstants.baseUrl,
      };
      
      // Encode as JSON string
      final qrCodeData = jsonEncode(pairingData);
      
      _log('[QR_CODE] QR code generated successfully');
      _log('[QR_CODE] Session ID: $sessionId');
      _log('[QR_CODE] Expiry: 15 minutes');
      
      return {
        'qr_data': qrCodeData,
        'session_id': sessionId,
        'pairing_token': pairingToken,
        'expiry_seconds': 900,
        'device_name': pairingData['device_name'],
      };
    } catch (e) {
      _log('[QR_CODE_ERROR] Failed to generate QR code: $e');
      rethrow;
    }
  }
  
  /// Validates and processes scanned QR code for account linking
  /// Returns paired account information (Legacy - decodes local QR data)
  Future<Map<String, dynamic>> validateQRCodeScan(String qrCodeData) async {
    try {
      _log('[QR_CODE_VALIDATE] Validating scanned QR code');
      
      // Decode QR data
      final pairingData = jsonDecode(qrCodeData) as Map<String, dynamic>;
      
      // Validate required fields
      _validateQRCodeFields(pairingData);
      
      // Check expiry
      final currentTime = DateTime.now().millisecondsSinceEpoch;
      final expiryTime = pairingData['expiry'] as int;
      
      if (currentTime > expiryTime) {
        throw Exception('QR code has expired. Please generate a new one.');
      }
      
      _log('[QR_CODE_VALIDATE] QR code validation successful');
      _log('[QR_CODE_VALIDATE] User: ${pairingData['user_name']}');
      _log('[QR_CODE_VALIDATE] Source Device: ${pairingData['device_name']}');
      
      return pairingData;
    } catch (e) {
      _log('[QR_CODE_VALIDATE_ERROR] Failed to validate QR code: $e');
      rethrow;
    }
  }
  
  /// Links a new device/platform to existing account using pairing token
  /// Returns success status and session information (Legacy function)
  Future<Map<String, dynamic>> linkDeviceWithPairingToken({
    required String pairingToken,
    required String sessionId,
    required String targetDeviceType, // 'mobile', 'web', 'desktop'
    required String targetDeviceName,
  }) async {
    try {
      _log('[QR_CODE_LINK_LEGACY] Linking device: $targetDeviceName ($targetDeviceType)');
      
      // Send pairing request to backend
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/link-device',
        data: {
          'pairing_token': pairingToken,
          'session_id': sessionId,
          'device_type': targetDeviceType,
          'device_name': targetDeviceName,
          'timestamp': DateTime.now().millisecondsSinceEpoch,
        },
      );
      
      final result = response.data ?? {};
      
      _log('[QR_CODE_LINK_LEGACY] Device linked successfully');
      _log('[QR_CODE_LINK_LEGACY] Device ID: ${result['device_id']}');
      
      return result;
    } catch (e) {
      _log('[QR_CODE_LINK_LEGACY_ERROR] Failed to link device: $e');
      rethrow;
    }
  }
  
  /// Gets list of all linked devices for current account
  /// Returns list of device information (Legacy - use getConnectedDevices)
  Future<List<Map<String, dynamic>>> getLinkedDevices() async {
    try {
      _log('[QR_CODE_LEGACY] Fetching linked devices');
      
      final response = await _dio.get('${ApiConstants.usersEndpoint}/devices');
      
      final devices = (response.data as List?)?.cast<Map<String, dynamic>>() ?? [];
      
      _log('[QR_CODE_LEGACY] Found ${devices.length} linked devices');
      
      return devices;
    } catch (e) {
      _log('[QR_CODE_LEGACY_ERROR] Failed to fetch linked devices: $e');
      return [];
    }
  }
  
  /// Unlinks a device from account
  /// Returns success status (Legacy - use disconnectDevice)
  Future<bool> unlinkDevice(String deviceId) async {
    try {
      _log('[QR_CODE_UNLINK_LEGACY] Unlinking device: $deviceId');
      
      final response = await _dio.delete(
        '${ApiConstants.usersEndpoint}/devices/$deviceId',
      );
      
      _log('[QR_CODE_UNLINK_LEGACY] Device unlinked successfully');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_UNLINK_LEGACY_ERROR] Failed to unlink device: $e');
      rethrow;
    }
  }
  
  /// Syncs data across all linked devices (Legacy - use syncAccountDataAcrossDevices)
  /// Used to keep accounts synchronized
  Future<Map<String, dynamic>> syncAcrossDevices({
    required String dataType, // 'chats', 'messages', 'settings'
    Map<String, dynamic>? additionalData,
  }) async {
    try {
      _log('[QR_CODE_SYNC_LEGACY] Syncing $dataType across all devices');
      
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/sync',
        data: {
          'data_type': dataType,
          'timestamp': DateTime.now().millisecondsSinceEpoch,
          ...?additionalData,
        },
      );
      
      _log('[QR_CODE_SYNC_LEGACY] Sync completed successfully');
      
      return response.data ?? {};
    } catch (e) {
      _log('[QR_CODE_SYNC_LEGACY_ERROR] Failed to sync data: $e');
      rethrow;
    }
  }
  
  /// Enables or disables cross-device notifications
  /// When enabled, notifications sync across all linked devices (Legacy)
  Future<bool> setCrossDeviceNotifications(bool enabled) async {
    try {
      _log('[QR_CODE_NOTIFICATIONS_LEGACY] Setting cross-device notifications: $enabled');
      
      final response = await _dio.put(
        '${ApiConstants.usersEndpoint}/settings/cross-device-notifications',
        data: {'enabled': enabled},
      );
      
      _log('[QR_CODE_NOTIFICATIONS_LEGACY] Cross-device notifications updated');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_NOTIFICATIONS_LEGACY_ERROR] Failed to update notifications: $e');
      rethrow;
    }
  }
  
  /// Verifies a device login from another platform using pairing token
  /// Prevents unauthorized access attempts (Legacy)
  Future<Map<String, dynamic>> verifyDeviceLogin({
    required String pairingToken,
    required String deviceId,
    required String deviceType,
  }) async {
    try {
      _log('[QR_CODE_VERIFY_LOGIN_LEGACY] Verifying device login: $deviceId');
      
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/verify-device-login',
        data: {
          'pairing_token': pairingToken,
          'device_id': deviceId,
          'device_type': deviceType,
          'verification_time': DateTime.now().millisecondsSinceEpoch,
        },
      );
      
      _log('[QR_CODE_VERIFY_LOGIN_LEGACY] Device login verified');
      
      return response.data ?? {};
    } catch (e) {
      _log('[QR_CODE_VERIFY_LOGIN_LEGACY_ERROR] Failed to verify device login: $e');
      rethrow;
    }
  }
  
  // ============ PRIVATE HELPER FUNCTIONS FOR QR CODE ============
  
  /// Generates a cryptographically secure pairing token
  String _generatePairingToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    final random = Random.secure();
    final token = List<String>.generate(32, (index) => chars[random.nextInt(chars.length)]).join();
    return token;
  }
  
  /// Generates a unique session ID for pairing
  String _generateSessionId() {
    return 'session_${DateTime.now().millisecondsSinceEpoch}_${Random().nextInt(10000)}';
  }
  
/// Gets device name based on platform
  String _getDeviceName() {
    if (kIsWeb) {
      return 'Web Browser';
    } else if (io.Platform.isAndroid) {
      return 'Android Device';
    } else if (io.Platform.isIOS) {
      return 'iOS Device';
    } else if (io.Platform.isWindows) {
      return 'Windows Desktop';
    } else if (io.Platform.isMacOS) {
      return 'macOS Device';
    } else if (io.Platform.isLinux) {
      return 'Linux Device';
    } else {
      return 'Unknown Device';
    }
  }
  
  /// Validates required fields in QR code data
  void _validateQRCodeFields(Map<String, dynamic> data) {
    final requiredFields = [
      'type',
      'session_id',
      'pairing_token',
      'user_id',
      'user_name',
      'device_name',
      'timestamp',
      'expiry',
    ];
    
    for (final field in requiredFields) {
      if (!data.containsKey(field) || data[field] == null) {
        throw Exception('Invalid QR code: Missing required field "$field"');
      }
    }
    
    if (data['type'] != 'account_linking') {
      throw Exception('Invalid QR code: Incorrect type');
    }
  }
}
