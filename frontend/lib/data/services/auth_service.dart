import 'package:shared_preferences/shared_preferences.dart';
import 'api_service.dart';

class AuthService {
  static const _kAccessTokenKey = 'auth.accessToken';
  static const _kRefreshTokenKey = 'auth.refreshToken';

  final ApiService _api;

  String? _accessToken;
  String? _refreshToken;

  AuthService(this._api);

  bool get isLoggedIn => (_accessToken ?? '').isNotEmpty;
  String? get accessToken => _accessToken;
  String? get refreshToken => _refreshToken;

  Future<void> init() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      _accessToken = prefs.getString(_kAccessTokenKey);
      _refreshToken = prefs.getString(_kRefreshTokenKey);
      print('[AUTH_INIT] Access token: ${_accessToken != null ? _accessToken!.substring(0, 20) + "..." : "null"}');
      print('[AUTH_INIT] Refresh token: ${_refreshToken != null ? _refreshToken!.substring(0, 20) + "..." : "null"}');
      
      if ((_accessToken ?? '').isNotEmpty) {
        _api.setAuthToken(_accessToken!);
        print('[AUTH_INIT] Token loaded from SharedPreferences and set in API service');
      } else {
        print('[AUTH_INIT] No stored token found, user not logged in');
        _api.clearAuthToken();
      }
    } catch (e) {
      print('[AUTH_INIT_ERROR] Failed to initialize auth: $e');
      _accessToken = null;
      _refreshToken = null;
      _api.clearAuthToken();
    }
  }

  Future<void> login({
    required String email,
    required String password,
  }) async {
    print('[AUTH_LOGIN] Attempting login for: $email');
    try {
      final result = await _api.login(email: email, password: password);
      print('[AUTH_LOGIN] Login response received');
      final access = result['access_token'] as String?;
      final refresh = result['refresh_token'] as String?;
      if ((access ?? '').isEmpty || (refresh ?? '').isEmpty) {
        print('[AUTH_LOGIN_ERROR] Invalid response - missing tokens');
        throw Exception('Invalid login response');
      }
      await _persistTokens(accessToken: access!, refreshToken: refresh!);
      print('[AUTH_LOGIN] Login successful - tokens persisted');
    } catch (e) {
      print('[AUTH_LOGIN_ERROR] Login failed: $e');
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
      print('[AUTH_PERSIST] Tokens saved to SharedPreferences and API service');
      print('[AUTH_PERSIST] Token valid: ${_accessToken!.isNotEmpty}');
    } catch (e) {
      print('[AUTH_PERSIST_ERROR] Failed to persist tokens: $e');
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



