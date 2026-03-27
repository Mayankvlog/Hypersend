import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SimpleApiService {
  static const String _baseUrl = 'https://zaply.in.net/api/v1';
  final FlutterSecureStorage _secureStorage = FlutterSecureStorage();

  // 1️⃣ Get stored JWT token securely (matches user's getAuthToken() requirement)
  Future<String?> getAuthToken() async {
    try {
      final token = await _secureStorage.read(key: 'access_token');
      print('[AUTH_TOKEN] Token retrieved: ${token != null ? "✅ Present" : "❌ Missing"}');
      return token;
    } catch (e) {
      print('Error getting auth token: $e');
      return null;
    }
  }

  // 2️⃣ Generic GET request with Authorization
  Future<http.Response> get(String endpoint) async {
    final token = await getAuthToken();
    final headers = token != null 
        ? {'Authorization': 'Bearer $token'} 
        : {};
    return await http.get(Uri.parse('$_baseUrl$endpoint'), headers: headers);
  }

  // 3️⃣ Generic POST request with Authorization
  Future<http.Response> post(String endpoint, {Map<String, String>? body}) async {
    final token = await getAuthToken();
    final headers = token != null
        ? {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'}
        : {'Content-Type': 'application/json'};
    return await http.post(
      Uri.parse('$_baseUrl$endpoint'), 
      headers: headers, 
      body: body != null ? jsonEncode(body) : null
    );
  }

  // 4️⃣ File download with Authorization token (CRITICAL for private files)
  Future<http.Response> downloadFile(String fileId) async {
    final token = await getAuthToken();
    final headers = token != null ? {'Authorization': 'Bearer $token'} : {};
    
    print('[DOWNLOAD] Authorization header: ${token != null ? "✅ Present" : "❌ Missing"}');
    
    final response = await http.get(
      Uri.parse('$_baseUrl/files/download/$fileId'), 
      headers: headers
    );
    
    print('[DOWNLOAD] Status: ${response.statusCode} for file: $fileId');
    
    return response;
  }

  // 5️⃣ PUT request for updates
  Future<http.Response> put(String endpoint, {Map<String, String>? body}) async {
    final token = await getAuthToken();
    final headers = token != null
        ? {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'}
        : {'Content-Type': 'application/json'};
    return await http.put(
      Uri.parse('$_baseUrl$endpoint'), 
      headers: headers, 
      body: body != null ? jsonEncode(body) : null
    );
  }

  // 6️⃣ DELETE request
  Future<http.Response> delete(String endpoint) async {
    final token = await getAuthToken();
    final headers = token != null ? {'Authorization': 'Bearer $token'} : {};
    return await http.delete(Uri.parse('$_baseUrl$endpoint'), headers: headers);
  }

  // 7️⃣ PATCH request for partial updates
  Future<http.Response> patch(String endpoint, {Map<String, String>? body}) async {
    final token = await getAuthToken();
    final headers = token != null
        ? {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'}
        : {'Content-Type': 'application/json'};
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
      print('✅ Token stored securely');
    } catch (e) {
      print('❌ Error storing token: $e');
    }
  }

  // 9️⃣ Clear token (logout)
  Future<void> clearToken() async {
    try {
      await _secureStorage.delete(key: 'access_token');
      print('✅ Token cleared');
    } catch (e) {
      print('❌ Error clearing token: $e');
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
        print('✅ User data: ${userResponse.body}');
      }

      // 🔥 CRITICAL: File download with JWT authentication (matches user's pseudo code)
      String token = await getAuthToken(); // Get logged-in user's token
      var response = await http.get(
        Uri.parse('$_baseUrl/files/download/69c10401b5df2a45a00227db'),
        headers: {
          'Authorization': 'Bearer $token',
        },
      );
      
      if (response.statusCode == 200) {
        print('✅ Download OK - JWT authentication successful');
        print('[INFO] [DOWNLOAD] Authorization header found ✅');
        print('[INFO] Generated S3 presigned download URL');
      } else if (response.statusCode == 404) {
        print('❌ File not found - may have been deleted');
      } else {
        print('❌ Download Failed: ${response.statusCode}');
      }

      // POST request example
      final postResponse = await post('/chats', body: {
        'name': 'New Chat',
        'type': 'group'
      });
      print('POST Status: ${postResponse.statusCode}');

    } catch (e) {
      print('❌ Error: $e');
    }
  }

  // 1️⃣2️⃣ Health check
  Future<bool> checkHealth() async {
    try {
      final response = await http.get(
        Uri.parse('https://zaply.in.net/health'),
        headers: {'User-Agent': 'Hypersend-Flutter/1.0'}
      );
      return response.statusCode == 200;
    } catch (e) {
      print('❌ Health check failed: $e');
      return false;
    }
  }
}
