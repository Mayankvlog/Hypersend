import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SimpleApiService {
  static const String _baseUrl = 'https://zaply.in.net/api/v1';
  final FlutterSecureStorage _secureStorage = FlutterSecureStorage();

  // 1️⃣ Get stored JWT token securely
  Future<String?> _getToken() async {
    try {
      return await _secureStorage.read(key: 'access_token');
    } catch (e) {
      print('Error getting token: $e');
      return null;
    }
  }

  // 2️⃣ Generic GET request with Authorization
  Future<http.Response> get(String endpoint) async {
    final token = await _getToken();
    final headers = token != null 
        ? {'Authorization': 'Bearer $token'} 
        : {};
    return await http.get(Uri.parse('$_baseUrl$endpoint'), headers: headers);
  }

  // 3️⃣ Generic POST request with Authorization
  Future<http.Response> post(String endpoint, {Map<String, String>? body}) async {
    final token = await _getToken();
    final headers = token != null
        ? {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'}
        : {'Content-Type': 'application/json'};
    return await http.post(
      Uri.parse('$_baseUrl$endpoint'), 
      headers: headers, 
      body: body != null ? jsonEncode(body) : null
    );
  }

  // 4️⃣ File download with Authorization token
  Future<http.Response> downloadFile(String fileId) async {
    final token = await _getToken();
    final headers = token != null ? {'Authorization': 'Bearer $token'} : {};
    return await http.get(
      Uri.parse('$_baseUrl/files/download/$fileId'), 
      headers: headers
    );
  }

  // 5️⃣ PUT request for updates
  Future<http.Response> put(String endpoint, {Map<String, String>? body}) async {
    final token = await _getToken();
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
    final token = await _getToken();
    final headers = token != null ? {'Authorization': 'Bearer $token'} : {};
    return await http.delete(Uri.parse('$_baseUrl$endpoint'), headers: headers);
  }

  // 7️⃣ PATCH request for partial updates
  Future<http.Response> patch(String endpoint, {Map<String, String>? body}) async {
    final token = await _getToken();
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
    final token = await _getToken();
    return token != null && token.isNotEmpty;
  }

  // 1️⃣1️⃣ Example usage
  void example() async {
    try {
      // Get user data
      final userResponse = await get('/users/me');
      if (userResponse.statusCode == 200) {
        print('✅ User data: ${userResponse.body}');
      }

      // Download file
      final fileResponse = await downloadFile('69c10401b5df2a45a00227db');
      if (fileResponse.statusCode == 200) {
        print('✅ Download OK');
      } else {
        print('❌ Download Failed: ${fileResponse.statusCode}');
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
