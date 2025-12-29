import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'api_service.dart';
import 'dart:async';

class AuthService {
  static const _kAccessTokenKey = 'auth.accessToken';
  static const _kRefreshTokenKey = 'auth.refreshToken';
  static const _kLastLoginAttemptKey = 'auth.lastLoginAttempt';
  static const _kFailedAttemptsKey = 'auth.failedAttempts';

  final ApiService _api;

  String? _accessToken;
  String? _refreshToken;
  Timer? _loginCooldownTimer;
  int _failedAttempts = 0;
  DateTime? _lastLoginAttempt;

  AuthService(this._api);

  bool get isLoggedIn => _isTokenValid(_accessToken);
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
      
      // Load failure tracking data
      _failedAttempts = prefs.getInt(_kFailedAttemptsKey) ?? 0;
      final lastAttemptStr = prefs.getString(_kLastLoginAttemptKey);
      if (lastAttemptStr != null) {
        _lastLoginAttempt = DateTime.tryParse(lastAttemptStr);
      }
      
      debugPrint('[AUTH_INIT] Access token: ${_accessToken != null ? '${_accessToken!.substring(0, 20)}...' : 'null'}');
      debugPrint('[AUTH_INIT] Refresh token: ${_refreshToken != null ? '${_refreshToken!.substring(0, 20)}...' : 'null'}');
      debugPrint('[AUTH_INIT] Failed attempts: $_failedAttempts');
      debugPrint('[AUTH_INIT] Last attempt: $_lastLoginAttempt');
      
      // Validate token formats
      if (!_isTokenValid(_accessToken)) {
        debugPrint('[AUTH_INIT] Invalid access token format, clearing');
        _accessToken = null;
      }
      
      if (!_isTokenValid(_refreshToken)) {
        debugPrint('[AUTH_INIT] Invalid refresh token format, clearing');
        _refreshToken = null;
      }
      
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
    _failedAttempts = 0;
    _lastLoginAttempt = null;
    _loginCooldownTimer?.cancel();
    _api.clearAuthToken();
    await _clearTokens();
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
      
      final access = result['access_token'] as String?;
      final refresh = result['refresh_token'] as String?;
      if ((access ?? '').isEmpty || (refresh ?? '').isEmpty) {
        await _handleLoginFailure();
        debugPrint('[AUTH_LOGIN_ERROR] Invalid response - missing tokens');
        debugPrint('[AUTH_LOGIN_ERROR] Response keys: ${result.keys.toList()}');
        debugPrint('[AUTH_LOGIN_ERROR] Full response: $result');
        throw Exception('Invalid login response - missing authentication tokens');
      }
      
      // Success - reset failure tracking and persist tokens
      await _handleLoginSuccess();
      await _persistTokens(accessToken: access!, refreshToken: refresh!);
      debugPrint('[AUTH_LOGIN] Login successful - tokens persisted');
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

Future<void> resetPassword({required String email}) async {
    try {
      final result = await _api.resetPasswordWithDetails(email: email);
      debugPrint('[AUTH_RESET_PASSWORD] Result: $result');
      
      // Log detailed information for debugging
      if (result['email_service_configured'] == false) {
        debugPrint('[AUTH_RESET_PASSWORD] Email service not configured');
      }
      
      if (result['debug_info'] != null) {
        debugPrint('[AUTH_RESET_PASSWORD] Debug info available');
        if (result['debug_info']['reset_token'] != null) {
          debugPrint('[AUTH_RESET_PASSWORD] Reset token available for testing');
        }
      }
    } catch (e) {
      debugPrint('[AUTH_RESET_PASSWORD_ERROR] Failed: $e');
      rethrow;
    }
  }

  // Get detailed password reset status
  Future<Map<String, dynamic>> getPasswordResetStatus({required String email}) async {
    try {
      final result = await _api.resetPasswordWithDetails(email: email);
      
      return {
        'success': result['success'],
        'message': result['message'],
        'email_sent': result['email_sent'],
        'email_service_configured': result['email_service_configured'],
        'needs_manual_token': !result['email_sent'] && result['debug_info']?['reset_token'] != null,
        'manual_token': result['debug_info']?['reset_token'],
        'recommendations': _getPasswordResetRecommendations(result),
      };
    } catch (e) {
      debugPrint('[AUTH_RESET_STATUS_ERROR] Failed: $e');
      return {
        'success': false,
        'message': e.toString(),
        'email_sent': false,
        'email_service_configured': false,
        'needs_manual_token': false,
        'manual_token': null,
        'recommendations': ['Please try again later or contact support'],
      };
    }
  }

  // Get enhanced recommendations based on password reset result
  List<String> _getPasswordResetRecommendations(Map<String, dynamic> result) {
    List<String> recommendations = [];
    
    final emailServiceStatus = result['email_service_status'] as String? ?? 'unknown';
    
    // Honest assessment based on actual email service status
    if (emailServiceStatus == 'not_configured') {
      recommendations.addAll([
        '❌ SERVER ISSUE: Email service not configured on backend',
        '📧 Contact server administrator to set up email service',
        '🔑 Required settings: SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM',
        '🧪 Test email: POST /auth/test-email (DEBUG mode only)',
        '🔄 Fallback: In DEBUG mode, check debug info for reset token'
      ]);
    } else if (emailServiceStatus == 'failed') {
      recommendations.addAll([
        '❌ EMAIL SERVICE FAILED: Backend email service has configuration issues',
        '🔍 Check server logs for detailed error information',
        '🌐 Verify network connectivity to SMTP server',
        '🔥 Check firewall rules for outbound SMTP (ports 25, 465, 587)',
        '📧 Contact email provider for correct SMTP settings',
        '⚠️ This is a SERVER CONFIGURATION issue, not user error'
      ]);
      
      // Add specific error-based recommendations
      if (result['debug_info'] != null) {
        final debugInfo = result['debug_info'] as Map<String, dynamic>;
        final emailError = debugInfo['email_error'] as String?;
        
        if (emailError != null) {
          final errorLower = emailError.toLowerCase();
          if (errorLower.contains('authentication')) {
            recommendations.addAll([
              '🔐 SMTP Authentication failed',
              '📱 For Gmail: Use App Password (not regular password)',
              '🔐 Enable 2-factor authentication on email account',
              '⚠️ Enable "Less secure app access" in Gmail settings'
            ]);
          } else if (errorLower.contains('connection')) {
            recommendations.addAll([
              '🌐 Network connectivity issue to SMTP server',
              '🔥 Firewall blocking outbound SMTP connections',
              '🌍 DNS resolution failure - check SMTP_HOST',
              '📡 Test connectivity: telnet smtp.gmail.com 587'
            ]);
          } else if (errorLower.contains('tls')) {
            recommendations.addAll([
              '🔒 TLS/SSL configuration mismatch',
              '📞 Contact email provider for correct SMTP settings',
              '🔄 Try different SMTP port (587 for TLS, 465 for SSL)'
            ]);
          }
        }
      }
    } else if (emailServiceStatus == 'configured' && (result['email_sent'] == true)) {
      recommendations.addAll([
        '✅ Email service is working correctly',
        '📧 Check recipient email address for typos',
        '📱 Check ALL email folders: Inbox, Spam, Junk, Promotions, Social, Updates',
        '⏰ Wait 2-5 minutes for email delivery',
        '🌍 Verify email isn\'t blocked by recipient\'s email provider',
        '📊 Check email service status: POST /auth/test-email'
      ]);
    } else {
      recommendations.addAll([
        '❓ Unknown email service status',
        '📋 Check server configuration',
        '🔧 Contact technical support',
        '📊 Check email service diagnostics'
      ]);
    }
    
    // Always add general troubleshooting steps
    recommendations.addAll([
      '🧪 Test email service: POST /auth/test-email (DEBUG mode)',
      '📋 Verify all environment variables are set correctly',
      '🔄 Restart backend after configuration changes',
      '📖 Check email provider SMTP documentation'
    ]);
    
    return recommendations;
  }

  // Get honest assessment of email service
  String getEmailServiceAssessment(Map<String, dynamic> result) {
    final emailServiceStatus = result['email_service_status'] as String? ?? 'unknown';
    
    switch (emailServiceStatus) {
      case 'not_configured':
        return '❌ Email service NOT configured - Contact administrator';
      case 'failed':
        return '❌ Email service BROKEN - Server configuration issue';
      case 'configured':
        return result['email_sent'] == true 
            ? '✅ Email service WORKING - Check your email'
            : '⚠️ Email service OK but delivery may be delayed';
      default:
        return '❓ Email service status unknown';
    }
  }

  // Get user action based on email status
  String getRequiredUserAction(Map<String, dynamic> result) {
    final emailServiceStatus = result['email_service_status'] as String? ?? 'unknown';
    
    if (emailServiceStatus == 'not_configured') {
      return 'Contact server administrator to configure email service';
    } else if (emailServiceStatus == 'failed') {
      return 'Wait for administrator to fix email service configuration';
    } else if (emailServiceStatus == 'configured') {
      if (result['debug_info'] != null && result['needs_manual_token'] == true) {
        return 'Use the reset token from debug information (DEBUG MODE ONLY)';
      } else {
        return 'Check your email inbox and spam folder';
      }
    } else {
      return 'Contact technical support for assistance';
    }
  }

  // Test email service configuration
  Future<Map<String, dynamic>> testEmailService() async {
    try {
      final result = await _api.testEmailService();
      debugPrint('[AUTH_TEST_EMAIL] Result: $result');
      return result;
    } catch (e) {
      debugPrint('[AUTH_TEST_EMAIL_ERROR] Failed: $e');
      rethrow;
    }
  }

  // Get comprehensive email service status
  Future<Map<String, dynamic>> getEmailServiceStatus() async {
    try {
      final result = await _api.testEmailService();
      debugPrint('[AUTH_EMAIL_STATUS] Email service status: $result');
      
      return {
        'service_configured': result['email_service_test']?['success'] ?? false,
        'smtp_host': result['configuration']?['smtp_host'],
        'smtp_port': result['configuration']?['smtp_port'],
        'smtp_username': result['configuration']?['smtp_username'],
        'email_from': result['configuration']?['email_from'],
        'test_email_sent': result['test_email_sent'],
        'test_email_error': result['test_email_error'],
        'recommendations': result['recommendations'] ?? [],
        'user_action': _getEmailAddressAction(result),
        'status_message': _getEmailAddressStatusMessage(result),
      };
    } catch (e) {
      debugPrint('[AUTH_EMAIL_STATUS_ERROR] Failed: $e');
      return {
        'service_configured': false,
        'smtp_host': null,
        'smtp_port': null,
        'smtp_username': null,
        'email_from': null,
        'test_email_sent': false,
        'test_email_error': e.toString(),
        'recommendations': ['Check email service configuration', 'Contact technical support'],
        'user_action': 'Contact server administrator',
        'status_message': 'Email service status unknown - contact support',
      };
    }
  }

  String _getEmailAddressAction(Map<String, dynamic> result) {
    if (result['service_configured'] == true && result['test_email_sent'] == true) {
      return 'Email service is working - check your inbox for reset email';
    } else if (result['service_configured'] == true && result['test_email_sent'] == false) {
      return 'Email service configured but failing - check server logs';
    } else {
      return 'Email service not configured - contact server administrator';
    }
  }

  String _getEmailAddressStatusMessage(Map<String, dynamic> result) {
    if (result['service_configured'] == true && result['test_email_sent'] == true) {
      return '✅ Email service operational';
    } else if (result['service_configured'] == true) {
      return '⚠️ Email service configured but has issues';
    } else {
      return '❌ Email service not configured';
    }
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



