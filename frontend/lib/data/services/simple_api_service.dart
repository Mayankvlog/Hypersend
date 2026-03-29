import 'dart:convert';
import 'package:flutter/foundation.dart' show debugPrint;
import 'package:http/http.dart' as http;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SimpleApiService {
  static const String _baseUrl = 'http://zaply.in.net/api/v1';
  final FlutterSecureStorage _secureStorage = FlutterSecureStorage();

  // 1️⃣ Get stored JWT token securely (matches user's getAuthToken() requirement)
  Future<String?> getAuthToken() async {
    try {
      final token = await _secureStorage.read(key: 'access_token');
      debugPrint('[AUTH_TOKEN] Token retrieved: ${token != null ? "✅ Present" : "❌ Missing"}');
      return token;
    } catch (e) {
      debugPrint('Error getting auth token: $e');
      return null;
    }
  }

  // 2️⃣ Generic GET request with Authorization
  Future<http.Response> get(String endpoint) async {
    final token = await getAuthToken();
    final headers = token != null 
        ? <String, String>{'Authorization': 'Bearer $token'} 
        : <String, String>{};
    return await http.get(Uri.parse('$_baseUrl$endpoint'), headers: headers);
  }

  // 3️⃣ Generic POST request with Authorization
  Future<http.Response> post(String endpoint, {Map<String, String>? body}) async {
    final token = await getAuthToken();
    final headers = token != null
        ? <String, String>{'Authorization': 'Bearer $token', 'Content-Type': 'application/json'}
        : <String, String>{'Content-Type': 'application/json'};
    return await http.post(
      Uri.parse('$_baseUrl$endpoint'), 
      headers: headers, 
      body: body != null ? jsonEncode(body) : null
    );
  }

  // 4️⃣ File download with Authorization token (CRITICAL for private files)
  Future<http.Response> downloadFile(String fileId) async {
    final token = await getAuthToken();
    final headers = token != null ? <String, String>{'Authorization': 'Bearer $token'} : <String, String>{};
    
    debugPrint('[DOWNLOAD] Authorization header: ${token != null ? "✅ Present" : "❌ Missing"}');
    
    final response = await http.get(
      Uri.parse('$_baseUrl/files/download/$fileId'), 
      headers: headers
    );
    
    debugPrint('[DOWNLOAD] Status: ${response.statusCode} for file: $fileId');
    
    return response;
  }

  // 5️⃣ PUT request for updates
  Future<http.Response> put(String endpoint, {Map<String, String>? body}) async {
    final token = await getAuthToken();
    final headers = token != null
        ? <String, String>{'Authorization': 'Bearer $token', 'Content-Type': 'application/json'}
        : <String, String>{'Content-Type': 'application/json'};
    return await http.put(
      Uri.parse('$_baseUrl$endpoint'), 
      headers: headers, 
      body: body != null ? jsonEncode(body) : null
    );
  }

  // 6️⃣ DELETE request
  Future<http.Response> delete(String endpoint) async {
    final token = await getAuthToken();
    final headers = token != null ? <String, String>{'Authorization': 'Bearer $token'} : <String, String>{};
    return await http.delete(Uri.parse('$_baseUrl$endpoint'), headers: headers);
  }

  // 7️⃣ PATCH request for partial updates
  Future<http.Response> patch(String endpoint, {Map<String, String>? body}) async {
    final token = await getAuthToken();
    final headers = token != null
        ? <String, String>{'Authorization': 'Bearer $token', 'Content-Type': 'application/json'}
        : <String, String>{'Content-Type': 'application/json'};
    return await http.patch(
      Uri.parse('$_baseUrl$endpoint'), 
      headers: headers, 
      body: body != null ? jsonEncode(body) : null
    );
  }

  // 8️⃣ Store token securely
  Future<void> storeToken(String token) async {
    try {
      await _secureStorage.write(key: 'access_token', value: token);
      debugPrint('✅ Token stored securely');
    } catch (e) {
      debugPrint('❌ Error storing token: $e');
    }
  }

  // 9️⃣ Clear token (logout)
  Future<void> clearToken() async {
    try {
      await _secureStorage.delete(key: 'access_token');
      debugPrint('✅ Token cleared');
    } catch (e) {
      debugPrint('❌ Error clearing token: $e');
    }
  }

  // 🔟 Check if user is logged in
  Future<bool> isLoggedIn() async {
    final token = await getAuthToken();
    return token != null && token.isNotEmpty;
  }

  // 1️⃣1️⃣ Example usage with JWT authentication for file downloads
  void example() async {
    try {
      // Get user data
      final userResponse = await get('/users/me');
      if (userResponse.statusCode == 200) {
        debugPrint('✅ User data: ${userResponse.body}');
      }

      // 🔥 CRITICAL: File download with JWT authentication (matches user's pseudo code)
      String? token = await getAuthToken(); // Get logged-in user's token
      var response = await http.get(
        Uri.parse('$_baseUrl/files/download/69c10401b5df2a45a00227db'),
        headers: {
          'Authorization': 'Bearer $token',
        },
      );
      
      if (response.statusCode == 200) {
        debugPrint('✅ Download OK - JWT authentication successful');
        debugPrint('[INFO] [DOWNLOAD] Authorization header found ✅');
        debugPrint('[INFO] Generated S3 presigned download URL');
      } else if (response.statusCode == 404) {
        debugPrint('❌ File not found - may have been deleted');
      } else {
        debugPrint('❌ Download Failed: ${response.statusCode}');
      }

      // POST request example
      final postResponse = await post('/chats', body: {
        'name': 'New Chat',
        'type': 'group'
      });
      debugPrint('POST Status: ${postResponse.statusCode}');

    } catch (e) {
      debugPrint('❌ Error: $e');
    }
  }

  // 1️⃣2️⃣ Health check
  Future<bool> checkHealth() async {
    try {
      final response = await http.get(
        Uri.parse('http://localhost:8000/health'),
        headers: {'User-Agent': 'Hypersend-Flutter/1.0'}
      );
      return response.statusCode == 200;
    } catch (e) {
      debugPrint('❌ Health check failed: $e');
      return false;
    }
  }
}
