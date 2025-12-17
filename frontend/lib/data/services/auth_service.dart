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
    final prefs = await SharedPreferences.getInstance();
    _accessToken = prefs.getString(_kAccessTokenKey);
    _refreshToken = prefs.getString(_kRefreshTokenKey);
    if ((_accessToken ?? '').isNotEmpty) {
      _api.setAuthToken(_accessToken!);
    }
  }

  Future<void> login({
    required String email,
    required String password,
  }) async {
    final result = await _api.login(email: email, password: password);
    final access = result['access_token'] as String?;
    final refresh = result['refresh_token'] as String?;
    if ((access ?? '').isEmpty || (refresh ?? '').isEmpty) {
      throw Exception('Invalid login response');
    }
    await _persistTokens(accessToken: access!, refreshToken: refresh!);
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
    _accessToken = accessToken;
    _refreshToken = refreshToken;
    _api.setAuthToken(accessToken);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_kAccessTokenKey, accessToken);
    await prefs.setString(_kRefreshTokenKey, refreshToken);
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



