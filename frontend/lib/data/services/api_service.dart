import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart' show kIsWeb, debugPrint, kDebugMode;
import 'package:file_picker/file_picker.dart';
import 'dart:typed_data';
import 'dart:io';
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
    _log('[API_INIT] Auth endpoint: ${ApiConstants.authEndpoint}');
    _log('[API_INIT] SSL validation: ${ApiConstants.validateCertificates}');

    _dio = Dio(
      BaseOptions(
        baseUrl: url,
        connectTimeout: const Duration(seconds: 15),
        receiveTimeout: const Duration(seconds: 15),
        sendTimeout: const Duration(seconds: 15),
        contentType: 'application/json',
        // CRITICAL: Remove validateStatus to properly handle 4xx errors
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
      
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/avatar', 
        data: formData,
        options: Options(
          sendTimeout: const Duration(seconds: 30),
          receiveTimeout: const Duration(seconds: 30),
        ),
      );
      
      debugPrint('[API_SERVICE] Avatar upload response: ${response.data}');
      
      if (response.data == null) {
        throw Exception('Empty response from server');
      }
      
      return response.data ?? {};
    } on DioException catch (e) {
      debugPrint('[API_SERVICE] DioException during avatar upload: ${e.type} - ${e.message}');
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

  Future<List<Map<String, dynamic>>> getContacts({int limit = 50}) async {
    final response = await _dio.get('${ApiConstants.usersEndpoint}/contacts', queryParameters: {'limit': limit});
    return List<Map<String, dynamic>>.from(response.data?['users'] ?? const []);
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
  
  Future<Map<String, dynamic>> getContactsList({int limit = 100, int offset = 0}) async {
    try {
      final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/contacts/list',
        queryParameters: {'limit': limit, 'offset': offset}
      );
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error getting contacts list: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> addContact({
    required String userId,
    required String displayName,
  }) async {
    try {
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/contacts/add',
        data: {
          'user_id': userId,
          'display_name': displayName,
        }
      );
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error adding contact: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> deleteContact(String userId) async {
    try {
      final response = await _dio.delete('${ApiConstants.usersEndpoint}/contacts/$userId');
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error deleting contact: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> syncContacts(List<Map<String, String>> contacts) async {
    try {
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/contacts/sync',
        data: {'contacts': contacts}
      );
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error syncing contacts: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> searchContacts(String query, {int limit = 20}) async {
    try {
      final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/contacts/search',
        queryParameters: {'q': query, 'limit': limit}
      );
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error searching contacts: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> blockUser(String userId) async {
    try {
      final response = await _dio.post('${ApiConstants.usersEndpoint}/contacts/block/$userId');
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error blocking user: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> unblockUser(String userId) async {
    try {
      final response = await _dio.delete('${ApiConstants.usersEndpoint}/contacts/block/$userId');
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error unblocking user: $e');
      rethrow;
    }
  }

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
        final directory = localStoragePath;
        final file = File('$directory/$fileName');
        
        // Create directory if needed
        await file.parent.create(recursive: true);
        
        // Write file
        await file.writeAsBytes(fileData);
        
        _log('[LOCAL_STORAGE] File saved successfully at: ${file.path}');
        _log('[LOCAL_STORAGE] File size: ${(fileData.length / (1024 * 1024)).toStringAsFixed(2)}MB');
        
        return file.path;
      } else {
        // Web platform - use localStorage/IndexedDB via json encoding
        // Note: Web browsers have ~50MB limit per origin, so we use a reference system
        _log('[LOCAL_STORAGE] Web platform: Using in-memory storage (IndexedDB recommended for larger files)');
        return '$localStoragePath/$fileName';
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
        final file = File('$localStoragePath/$fileName');
        
        if (!await file.exists()) {
          throw Exception('File not found: $fileName');
        }
        
        final fileData = await file.readAsBytes();
        _log('[LOCAL_STORAGE] File retrieved successfully: ${(fileData.length / (1024 * 1024)).toStringAsFixed(2)}MB');
        
        return fileData;
      } else {
        // Web platform
        throw Exception('Web file retrieval requires IndexedDB implementation');
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to retrieve file: $e');
      rethrow;
    }
  }
  
  /// Deletes a file from local storage
  /// Returns true if deletion successful
  Future<bool> deleteFileLocally({
    required String fileName,
    required String localStoragePath,
  }) async {
    try {
      _log('[LOCAL_STORAGE] Deleting file: $fileName');
      
      if (!kIsWeb) {
        // Mobile platform
        final file = File('$localStoragePath/$fileName');
        
        if (await file.exists()) {
          await file.delete();
          _log('[LOCAL_STORAGE] File deleted successfully: $fileName');
          return true;
        } else {
          _log('[LOCAL_STORAGE] File not found for deletion: $fileName');
          return false;
        }
      } else {
        // Web platform
        _log('[LOCAL_STORAGE] Web platform file deletion');
        return true;
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to delete file: $e');
      rethrow;
    }
  }
  
  /// Gets list of files in local storage directory
  /// Returns list of file names
  Future<List<String>> listFilesLocally(String localStoragePath) async {
    try {
      _log('[LOCAL_STORAGE] Listing files in: $localStoragePath');
      
      if (!kIsWeb) {
        // Mobile platform
        final directory = Directory(localStoragePath);
        
        if (!await directory.exists()) {
          _log('[LOCAL_STORAGE] Directory does not exist: $localStoragePath');
          return [];
        }
        
        final files = await directory.list().toList();
        final fileNames = files
            .whereType<File>()
            .map((file) => file.path.split('/').last)
            .toList();
        
        _log('[LOCAL_STORAGE] Found ${fileNames.length} files');
        return fileNames;
      } else {
        // Web platform
        return [];
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to list files: $e');
      return [];
    }
  }
  
  /// Gets total size of all files in local storage
  /// Returns size in bytes
  Future<int> getTotalLocalStorageSize(String localStoragePath) async {
    try {
      _log('[LOCAL_STORAGE] Calculating total storage size');
      
      if (!kIsWeb) {
        // Mobile platform
        final directory = Directory(localStoragePath);
        
        if (!await directory.exists()) {
          return 0;
        }
        
        int totalSize = 0;
        final files = await directory.list(recursive: true).toList();
        
        for (var file in files) {
          if (file is File) {
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
        final directory = Directory(localStoragePath);
        
        if (!await directory.exists()) {
          return 0;
        }
        
        int deletedCount = 0;
        final files = await directory.list().toList();
        
        for (var file in files) {
          if (file is File) {
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
}


