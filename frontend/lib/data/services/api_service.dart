import 'dart:typed_data';
import 'package:dio/dio.dart';
import '../../core/constants/api_constants.dart';

class ApiService {
  late final Dio _dio;

  ApiService() {
    String url = ApiConstants.baseUrl;
    if (!url.endsWith('/')) {
      url += '/';
    }

    _dio = Dio(
      BaseOptions(
        baseUrl: url,
        connectTimeout: ApiConstants.connectTimeout,
        receiveTimeout: ApiConstants.receiveTimeout,
        contentType: 'application/json',
      ),
    );

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
            print('[API_REQ] ${options.method} ${options.uri.path} - Auth: present');
          } else {
            print('[API_REQ_WARN] ${options.method} ${options.uri.path} - Auth: MISSING!');
          }
          return handler.next(options);
        },
        onError: (error, handler) {
          // Log network errors with detailed info
          if (error.response?.statusCode == null) {
            print('[API_ERROR] Network/Connection error: ${error.message}');
            print('[API_ERROR] URL: ${error.requestOptions.uri}');
            print('[API_ERROR] Method: ${error.requestOptions.method}');
            print('[API_ERROR] Type: ${error.type}');
          } else {
            print('[API_ERROR] HTTP ${error.response?.statusCode}: ${error.message}');
            // Log 401 specifically with headers info for debugging
            if (error.response?.statusCode == 401) {
              print('[API_ERROR] 401 Unauthorized on ${error.requestOptions.uri}');
              print('[API_ERROR] Auth header present: ${error.requestOptions.headers.containsKey("Authorization")}');
            }
          }
          return handler.next(error);
        },
      ),
    );
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
      return response.data;
    } catch (e) {
      rethrow;
    }
  }

  Future<Map<String, dynamic>> login({
    required String email,
    required String password,
  }) async {
    try {
      final response = await _dio.post('${ApiConstants.authEndpoint}/login', data: {
        'email': email,
        'password': password,
      });
      return response.data;
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
      final response = await _dio.get('${ApiConstants.usersEndpoint}/me');
      return response.data;
    } catch (e) {
      rethrow;
    }
  }

  Future<Map<String, dynamic>> updateProfile(Map<String, dynamic> data) async {
    try {
      final response = await _dio.put('${ApiConstants.usersEndpoint}/profile', data: data);
      return response.data;
    } catch (e) {
      rethrow;
    }
  }

  Future<List<Map<String, dynamic>>> getContacts({int limit = 50}) async {
    final response = await _dio.get('${ApiConstants.usersEndpoint}/contacts', queryParameters: {'limit': limit});
    return List<Map<String, dynamic>>.from(response.data['users'] ?? const []);
  }

  // Chat endpoints
  Future<List<Map<String, dynamic>>> getChats() async {
    try {
      print('[API_CHATS] Fetching chats from ${ApiConstants.chatsEndpoint}');
      final response = await _dio.get('${ApiConstants.chatsEndpoint}');
      print('[API_CHATS] Success: received ${response.data['chats']?.length ?? 0} chats');
      return List<Map<String, dynamic>>.from(response.data['chats'] ?? const []);
    } catch (e) {
      print('[API_CHATS_ERROR] Failed to fetch chats: $e');
      rethrow;
    }
  }
    } catch (e) {
      rethrow;
    }
  }

  Future<Map<String, dynamic>> getChatMessages(String chatId) async {
    try {
      final response = await _dio.get('${ApiConstants.chatsEndpoint}/$chatId/messages');
      return response.data;
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
    return List<Map<String, dynamic>>.from(response.data['messages'] ?? []);
  }

  Future<List<Map<String, dynamic>>> searchUsers(String query) async {
    final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/search',
        queryParameters: {'q': query},
    );
    return List<Map<String, dynamic>>.from(response.data['users'] ?? []);
  }

  Future<Map<String, dynamic>> sendMessage({
    required String chatId,
    required String content,
  }) async {
    try {
      final response = await _dio.post('${ApiConstants.chatsEndpoint}/$chatId/messages', data: {
        'text': content,
      });
      return response.data;
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

  // Channel endpoints
  Future<Map<String, dynamic>> createChannel({
    required String name,
    String description = '',
    String? avatarUrl,
    String? username,
  }) async {
    final response = await _dio.post(
      'channels',
      data: {
        'name': name,
        'description': description,
        'avatar_url': avatarUrl,
        'username': username,
      },
    );
    // Return compatible chat object (backend returns {channel_id, channel})
    return {
      ...response.data['channel'],
      '_id': response.data['channel_id'],
      'type': 'channel'
    };
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

  Future<Map<String, dynamic>> createSecretChat({
    required String targetUserId,
  }) async {
    final response = await _dio.post(
      '${ApiConstants.chatsEndpoint}',
      data: {
        'type': 'secret',
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
      data: Stream.value(bytes),
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
  }) async {
    await _dio.download('${ApiConstants.filesEndpoint}/$fileId/download', savePath);
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
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/change-password',
        data: {
          'old_password': oldPassword,
          'new_password': newPassword,
        },
      );
      return response.statusCode == 200;
    } catch (e) {
      rethrow;
    }
  }

  Future<bool> resetPassword({required String email}) async {
    try {
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/reset-password',
        data: {'email': email},
      );
      return response.statusCode == 200;
    } catch (e) {
      rethrow;
    }
  }

  Future<bool> changeEmail({
    required String newEmail,
    required String password,
  }) async {
    try {
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/change-email',
        data: {
          'email': newEmail,
          'password': password,
        },
      );
      return response.statusCode == 200;
    } catch (e) {
      rethrow;
    }
  }

  void setAuthToken(String token) {
    final authHeader = 'Bearer $token';
    _dio.options.headers['Authorization'] = authHeader;
    print('[API_AUTH] Token set (Bearer token), length: ${token.length}');
  }

  void clearAuthToken() {
    _dio.options.headers.remove('Authorization');
    print('[API_AUTH] Token cleared from headers');
  }
}
