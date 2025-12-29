import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'api_service.dart';

class AuthService {
  static const _kAccessTokenKey = 'auth.accessToken';
  static const _kRefreshTokenKey = 'auth.refreshToken';

  final ApiService _api;

  String? _accessToken;
  String? _refreshToken;

  AuthService(this._api);

  bool get isLoggedIn => _isTokenValid(_accessToken);

  bool _isTokenValid(String? token) {
    if (token == null || token.isEmpty) return false;
    
    // Basic JWT token validation (should have 3 parts separated by dots)
    final parts = token.split('.');
    if (parts.length != 3) {
      debugPrint('[AUTH_TOKEN] Invalid token format: expected 3 parts, got ${parts.length}');
      return false;
    }
    
    // Check if token seems reasonable length
    if (token.length < 50) {
      debugPrint('[AUTH_TOKEN] Token too short: ${token.length} characters');
      return false;
    }
    
    return true;
  }
  String? get accessToken => _accessToken;
  String? get refreshToken => _refreshToken;

  Future<void> init() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      _accessToken = prefs.getString(_kAccessTokenKey);
      _refreshToken = prefs.getString(_kRefreshTokenKey);
      debugPrint('[AUTH_INIT] Access token: ${_accessToken != null ? '${_accessToken!.substring(0, 20)}...' : 'null'}');
      debugPrint('[AUTH_INIT] Refresh token: ${_refreshToken != null ? '${_refreshToken!.substring(0, 20)}...' : 'null'}');
      
      // Validate token formats
      if (!_isTokenValid(_accessToken)) {
        debugPrint('[AUTH_INIT] Invalid access token format, clearing');
        _accessToken = null;
      }
      
      if (!_isTokenValid(_refreshToken)) {
        debugPrint('[AUTH_INIT] Invalid refresh token format, clearing');
        _refreshToken = null;
      }
      
      if (_isTokenValid(_accessToken)) {
        _api.setAuthToken(_accessToken!);
        debugPrint('[AUTH_INIT] Valid token loaded from SharedPreferences and set in API service');
      } else {
        debugPrint('[AUTH_INIT] No valid stored token found, user not logged in');
        _api.clearAuthToken();
        // Clear corrupted tokens from storage
        if (_accessToken == null || _refreshToken == null) {
          await _clearTokens();
        }
      }
    } catch (e) {
      debugPrint('[AUTH_INIT_ERROR] Failed to initialize auth: $e');
      _accessToken = null;
      _refreshToken = null;
      _api.clearAuthToken();
      await _clearTokens();
    }
  }

  // Method to clear auth state for troubleshooting
  Future<void> clearAuthState() async {
    debugPrint('[AUTH_CLEAR] Clearing authentication state');
    _accessToken = null;
    _refreshToken = null;
    _api.clearAuthToken();
    await _clearTokens();
  }

  Future<void> login({
    required String email,
    required String password,
  }) async {
    debugPrint('[AUTH_LOGIN] Attempting login for: $email');
    try {
      // Use retry logic to handle rate limiting
      final result = await _api.loginWithRetry(email: email, password: password);
      debugPrint('[AUTH_LOGIN] Login response received');
      
      // Check if response contains error indicators
      if (result.containsKey('detail') || result.containsKey('error')) {
        final errorDetail = result['detail'] as String? ?? result['error'] as String? ?? 'Unknown error';
        debugPrint('[AUTH_LOGIN_ERROR] Server returned error: $errorDetail');
        throw Exception(errorDetail);
      }
      
      final access = result['access_token'] as String?;
      final refresh = result['refresh_token'] as String?;
      if ((access ?? '').isEmpty || (refresh ?? '').isEmpty) {
        debugPrint('[AUTH_LOGIN_ERROR] Invalid response - missing tokens');
        debugPrint('[AUTH_LOGIN_ERROR] Response keys: ${result.keys.toList()}');
        debugPrint('[AUTH_LOGIN_ERROR] Full response: $result');
        throw Exception('Invalid login response - missing authentication tokens');
      }
      await _persistTokens(accessToken: access!, refreshToken: refresh!);
      debugPrint('[AUTH_LOGIN] Login successful - tokens persisted');
    } catch (e) {
      debugPrint('[AUTH_LOGIN_ERROR] Login failed: $e');
      rethrow;
    }
  }

  Future<void> registerAndLogin({
    required String name,
    required String email,
    required String password,
  }) async {
    await _api.register(email: email, password: password, name: name);
    await login(email: email, password: password);
  }

  Future<void> resetPassword({required String email}) async {
    await _api.resetPassword(email: email);
  }

  Future<void> logout() async {
    try {
      final refresh = _refreshToken;
      if ((refresh ?? '').isNotEmpty) {
        await _api.logout(refreshToken: refresh!);
      }
    } finally {
      await _clearTokens();
    }
  }

  Future<void> _persistTokens({
    required String accessToken,
    required String refreshToken,
  }) async {
    try {
      _accessToken = accessToken;
      _refreshToken = refreshToken;
      _api.setAuthToken(accessToken);
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_kAccessTokenKey, accessToken);
      await prefs.setString(_kRefreshTokenKey, refreshToken);
      debugPrint('[AUTH_PERSIST] Tokens saved to SharedPreferences and API service');
      debugPrint('[AUTH_PERSIST] Token valid: ${_accessToken!.isNotEmpty}');
    } catch (e) {
      debugPrint('[AUTH_PERSIST_ERROR] Failed to persist tokens: $e');
      rethrow;
    }
  }

  Future<void> _clearTokens() async {
    _accessToken = null;
    _refreshToken = null;
    _api.clearAuthToken();
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_kAccessTokenKey);
    await prefs.remove(_kRefreshTokenKey);
  }
}



