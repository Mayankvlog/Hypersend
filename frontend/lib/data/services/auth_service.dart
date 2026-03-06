import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'api_service.dart';
import 'dart:async';

class AuthService {
  static const _kLastLoginAttemptKey = 'auth.lastLoginAttempt';
  static const _kFailedAttemptsKey = 'auth.failedAttempts';

  final ApiService _api;

  int _failedAttempts = 0;
  DateTime? _lastLoginAttempt;
  Timer? _loginCooldownTimer;
  bool _isAuthenticated = false;

  AuthService(this._api);

  bool get isLoggedIn => _isAuthenticated;
  bool get isLoginBlocked => _loginCooldownTimer?.isActive ?? false;
  Duration? get loginBlockTimeRemaining {
    if (!isLoginBlocked || _lastLoginAttempt == null) return null;
    final elapsed = DateTime.now().difference(_lastLoginAttempt!);
    final totalCooldown = Duration(seconds: _calculateCooldownSeconds());
    final remaining = totalCooldown - elapsed;
    return remaining.isNegative ? null : remaining;
  }

  // Calculate progressive cooldown based on failed attempts
  int _calculateCooldownSeconds() {
    if (_failedAttempts == 1) return 30;      // 30 seconds after 1st fail
    if (_failedAttempts == 2) return 60;      // 1 minute after 2nd fail
    if (_failedAttempts == 3) return 120;     // 2 minutes after 3rd fail
    if (_failedAttempts == 4) return 300;     // 5 minutes after 4th fail
    return 600; // 10 minutes for 5+ failures
  }

  // Get user-friendly status for UI display
  String getLoginStatusMessage() {
    if (!isLoginBlocked) return '';
    
    final remaining = loginBlockTimeRemaining;
    if (remaining == null) return '';
    
    if (remaining.inHours >= 1) {
      return 'Account temporarily locked. Please wait ${remaining.inHours} hour${remaining.inHours > 1 ? 's' : ''} before trying again.';
    } else if (remaining.inMinutes >= 1) {
      return 'Too many failed attempts. Please wait ${remaining.inMinutes} minute${remaining.inMinutes > 1 ? 's' : ''} before trying again.';
    } else {
      return 'Too many failed attempts. Please wait ${remaining.inSeconds} seconds before trying again.';
    }
  }

  // Enhanced error classification for better user feedback
  String classifyLoginError(dynamic error) {
    final errorString = error.toString().toLowerCase();
    
    // Network and connection errors
    if (errorString.contains('connection') || errorString.contains('network') || errorString.contains('socket')) {
      return 'network';
    }
    
    // Authentication and credential errors
    if (errorString.contains('unauthorized') || errorString.contains('401') || errorString.contains('invalid email or password')) {
      return 'credentials';
    }
    
    // Rate limiting errors
    if (errorString.contains('too many requests') || errorString.contains('429') || errorString.contains('rate limit')) {
      return 'rate_limit';
    }
    
    // Server errors
    if (errorString.contains('server error') || errorString.contains('500') || errorString.contains('502') || errorString.contains('503')) {
      return 'server';
    }
    
    // Account lock/security errors
    if (errorString.contains('forbidden') || errorString.contains('locked') || errorString.contains('403') || errorString.contains('423')) {
      return 'security';
    }
    
    // Data validation errors
    if (errorString.contains('invalid data') || errorString.contains('400') || errorString.contains('422')) {
      return 'validation';
    }
    
    return 'unknown';
  }

  // Get appropriate retry strategy based on error type
  bool shouldRetryImmediately(String errorType) {
    switch (errorType) {
      case 'network':
        return true; // Network issues might resolve quickly
      case 'validation':
        return true; // User can fix validation errors immediately
      case 'rate_limit':
        return false; // Must wait for cooldown
      case 'security':
        return false; // Security issues require manual intervention
      case 'server':
        return true; // Server issues might be temporary
      default:
        return false;
    }
  }

  // DEPRECATED: _isCookieValid() is no longer used - use _isAuthenticated instead
  // bool _isCookieValid() {
  //   // In a cookie-based auth system, we can't directly validate tokens from JavaScript
  //   // We rely on the server to validate cookies and return appropriate errors
  //   // This is a security feature of HTTPOnly cookies
  //   return true; // Assume valid if server hasn't rejected
  // }

  Future<void> init() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      
      // Load failure tracking data (keep existing functionality)
      _failedAttempts = prefs.getInt(_kFailedAttemptsKey) ?? 0;
      final lastAttemptStr = prefs.getString(_kLastLoginAttemptKey);
      if (lastAttemptStr != null) {
        _lastLoginAttempt = DateTime.tryParse(lastAttemptStr);
      }
      
      debugPrint('[AUTH_INIT] Failed attempts: $_failedAttempts');
      debugPrint('[AUTH_INIT] Last attempt: $_lastLoginAttempt');
      
      // Check if cooldown period is still active
      if (_lastLoginAttempt != null && _failedAttempts > 0) {
        final elapsed = DateTime.now().difference(_lastLoginAttempt!);
        final cooldownDuration = Duration(seconds: _calculateCooldownSeconds());
        
        if (elapsed < cooldownDuration) {
          final remaining = cooldownDuration - elapsed;
          debugPrint('[AUTH_INIT] Cooldown still active: ${remaining.inSeconds}s remaining');
          
          // Restart timer for remaining cooldown
          _loginCooldownTimer = Timer(remaining, () {
            debugPrint('[AUTH_INIT] Cooldown period ended');
            _loginCooldownTimer = null;
          });
        } else {
          debugPrint('[AUTH_INIT] Cooldown period expired, resetting');
          await _handleLoginSuccess();
        }
      }
      
      // With HTTPOnly cookies, we don't need to validate tokens here
      // The server will validate cookies and return errors if needed
      debugPrint('[AUTH_INIT] HTTPOnly cookie-based authentication initialized');
    } catch (e) {
      debugPrint('[AUTH_INIT_ERROR] Failed to initialize auth: $e');
      _failedAttempts = 0;
      _lastLoginAttempt = null;
      _loginCooldownTimer?.cancel();
    }
  }

  // Method to clear auth state for troubleshooting
  Future<void> clearAuthState() async {
    debugPrint('[AUTH_CLEAR] Clearing authentication state');
    _accessToken = null;
    _refreshToken = null;
    _failedAttempts = 0;
    _lastLoginAttempt = null;
    _loginCooldownTimer?.cancel();
    _isAuthenticated = false; // Set authentication state to false
    _api.clearAuthToken();
    await _clearTokens();
  }

  // Method to handle authentication failure (401 responses when refresh fails)
  void handleAuthenticationFailure() {
    debugPrint('[AUTH_FAILURE] Handling authentication failure - clearing auth state');
    _isAuthenticated = false;
    _accessToken = null;
    _refreshToken = null;
    _api.clearAuthToken();
  }

  Future<void> login({
    required String email,
    required String password,
  }) async {
    debugPrint('[AUTH_LOGIN] Attempting login for: $email');
    
    // Check if login is currently blocked
    if (isLoginBlocked) {
      final remaining = loginBlockTimeRemaining;
      if (remaining != null) {
        debugPrint('[AUTH_LOGIN_BLOCKED] Login blocked. Wait ${remaining.inSeconds}s');
        throw Exception('Too many failed attempts. Please wait ${remaining.inSeconds} seconds before trying again.');
      }
    }
    
    try {
      // Update login attempt tracking
      _lastLoginAttempt = DateTime.now();
      
      // Use API login without retry logic - we handle rate limiting here
      final result = await _api.login(email: email, password: password);
      debugPrint('[AUTH_LOGIN] Login response received');
      
      // Check if response contains error indicators
      if (result.containsKey('detail') || result.containsKey('error')) {
        await _handleLoginFailure();
        final errorDetail = result['detail'] as String? ?? result['error'] as String? ?? 'Unknown error';
        debugPrint('[AUTH_LOGIN_ERROR] Server returned error: $errorDetail');
        throw Exception(errorDetail);
      }
      
      // With HTTPOnly cookies, we don't need to handle tokens manually
      // The server sets cookies automatically and they're sent with subsequent requests
      debugPrint('[AUTH_LOGIN] Login successful - HTTPOnly cookies set by server');
      
      // Reset failure tracking on successful login
      await _handleLoginSuccess();
    } catch (e) {
      debugPrint('[AUTH_LOGIN_ERROR] Login failed: $e');
      rethrow;
    }
  }

  // Handle successful login - reset failure tracking
  Future<void> _handleLoginSuccess() async {
    debugPrint('[AUTH_SUCCESS] Resetting failure tracking');
    _failedAttempts = 0;
    _lastLoginAttempt = null;
    _loginCooldownTimer?.cancel();
    _isAuthenticated = true; // Set authentication state to true
    
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_kFailedAttemptsKey);
    await prefs.remove(_kLastLoginAttemptKey);
  }

  // Handle login failure - increment counter and apply cooldown
  Future<void> _handleLoginFailure() async {
    _failedAttempts++;
    _lastLoginAttempt = DateTime.now();
    
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_kFailedAttemptsKey, _failedAttempts);
    await prefs.setString(_kLastLoginAttemptKey, _lastLoginAttempt!.toIso8601String());
    
    debugPrint('[AUTH_FAILURE] Failed attempts: $_failedAttempts');
    
    // Start cooldown timer
    _loginCooldownTimer?.cancel();
    final cooldownSeconds = _calculateCooldownSeconds();
    
    _loginCooldownTimer = Timer(Duration(seconds: cooldownSeconds), () {
      debugPrint('[AUTH_COOLDOWN] Cooldown period ended');
      _loginCooldownTimer = null;
    });
    
    debugPrint('[AUTH_COOLDOWN] Started ${cooldownSeconds}s cooldown');
  }



  Future<void> registerAndLogin({
    required String name,
    required String email,
    required String password,
  }) async {
    await _api.register(email: email, password: password, name: name);
    await login(email: email, password: password);
  }

  Future<Map<String, dynamic>> requestPasswordReset(String email) async {
    try {
      debugPrint('[AUTH_REQUEST_PASSWORD_RESET] Requesting password reset for: $email');
      final result = await _api.requestPasswordReset(email);
      debugPrint('[AUTH_REQUEST_PASSWORD_RESET] Result: $result');

      if (result.containsKey('detail') || result.containsKey('error')) {
        final errorDetail = result['detail'] as String? ?? result['error'] as String? ?? 'Unknown error';
        throw Exception(errorDetail);
      }

      return result;
    } catch (e) {
      debugPrint('[AUTH_REQUEST_PASSWORD_RESET_ERROR] Failed: $e');
      rethrow;
    }
  }

  Future<void> resetPasswordWithToken({
    required String token,
    required String newPassword,
  }) async {
    try {
      final result = await _api.resetPasswordWithToken(token: token, newPassword: newPassword);
      debugPrint('[AUTH_RESET_PASSWORD_WITH_TOKEN] Result: $result');

      if (result.containsKey('detail') || result.containsKey('error')) {
        final errorDetail = result['detail'] as String? ?? result['error'] as String? ?? 'Unknown error';
        throw Exception(errorDetail);
      }
    } catch (e) {
      debugPrint('[AUTH_RESET_PASSWORD_WITH_TOKEN_ERROR] Failed: $e');
      rethrow;
    }
  }

  Future<void> logout() async {
    try {
      // Call logout endpoint - server will clear HTTPOnly cookies
      await _api.logout();
      debugPrint('[AUTH_LOGOUT] Logout successful - HTTPOnly cookies cleared by server');
    } catch (e) {
      debugPrint('[AUTH_LOGOUT_ERROR] Logout failed: $e');
      rethrow;
    }
    
    // Reset local auth state
    _isAuthenticated = false; // Set authentication state to false
    await _handleLoginSuccess();
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
      debugPrint('[AUTH_TOKENS] Tokens persisted - access: ${accessToken.substring(0, 20)}..., refresh: ${refreshToken.substring(0, 20)}...');
    } catch (e) {
      debugPrint('[AUTH_TOKENS] Error persisting tokens: $e');
      // Re-throw as auth exception to maintain error type consistency
      throw Exception('Failed to save authentication tokens: ${e.toString()}');
    }
  }

  // New method to refresh session using HTTPOnly cookies
  Future<bool> refreshSession() async {
    try {
      debugPrint('[AUTH_REFRESH] Attempting to refresh session...');
      
      // Call session refresh endpoint - server will read refresh token cookie and set new access token cookie
      final response = await _api.refreshSession();
      
      if (response.containsKey('message') && response['message'] == 'Session refreshed') {
        debugPrint('[AUTH_REFRESH] Session refreshed successfully');
        return true;
      } else {
        debugPrint('[AUTH_REFRESH] Session refresh failed: $response');
        return false;
      }
    } catch (e) {
      debugPrint('[AUTH_REFRESH] Session refresh error: $e');
      return false;
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
  
  void dispose() {
    _loginCooldownTimer?.cancel();
    _loginCooldownTimer = null;
  }
}



