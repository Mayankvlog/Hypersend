import 'api_service.dart';
import 'auth_service.dart';
import 'profile_service.dart';
import 'settings_service.dart';
import 'file_transfer_service.dart';
import '../models/user.dart';
import 'package:flutter/foundation.dart';
import 'package:firebase_analytics/firebase_analytics.dart';

class ServiceProvider {
  static final ServiceProvider _instance = ServiceProvider._internal();

  late final ApiService apiService;
  late final AuthService authService;
  late final ProfileService profileService;
  late final SettingsService settingsService;
  late final FileTransferService fileTransferService;
  late final FirebaseAnalytics _analytics;

  ServiceProvider._internal() {
    _initialize();
  }

  factory ServiceProvider() {
    return _instance;
  }

  void _initialize() {
    apiService = ApiService();
    authService = AuthService(apiService);
    profileService = ProfileService(apiService);
    settingsService = SettingsService();
    fileTransferService = FileTransferService(apiService);
    _analytics = FirebaseAnalytics.instance;
    // Services initialized successfully
  }

  // Initialize all services
  Future<void> init() async {
    try {
      // Initialize auth service first
      try {
        await authService.init();
      } catch (e) {
        debugPrint('[ServiceProvider] Auth initialization error (non-blocking): $e');
        // Non-blocking - app continues even if auth fails initially
      }

      // If logged in, fetch current user and populate profile service
      if (authService.isLoggedIn) {
        try {
          final me = await apiService.getMe();
          profileService.setUser(User.fromApi(me));
          // Set user property in analytics
          await _setAnalyticsUser(me['id'] ?? '');
        } catch (e) {
          debugPrint('[ServiceProvider] Profile fetch error: $e');
          // User will be prompted to log in again
        }
      }
      debugPrint('[ServiceProvider] Initialization complete');
    } catch (e) {
      debugPrint('[ServiceProvider] Critical initialization error: $e');
      // Allow app to continue - user can retry login
    }
  }

  // Analytics Methods
  Future<void> _setAnalyticsUser(String userId) async {
    try {
      await _analytics.setUserProperty(name: 'user_id', value: userId);
      debugPrint('[Analytics] User ID set: $userId');
    } catch (e) {
      debugPrint('[Analytics] Error setting user ID: $e');
    }
  }

  Future<void> logEvent({
    required String name,
    Map<String, Object>? parameters,
  }) async {
    try {
      await _analytics.logEvent(name: name, parameters: parameters);
      debugPrint('[Analytics] Event logged: $name');
    } catch (e) {
      debugPrint('[Analytics] Error logging event: $e');
    }
  }

  Future<void> logScreenView({
    required String screenName,
    String? screenClass,
  }) async {
    try {
      await _analytics.logScreenView(
        screenName: screenName,
        screenClass: screenClass,
      );
      debugPrint('[Analytics] Screen view logged: $screenName');
    } catch (e) {
      debugPrint('[Analytics] Error logging screen view: $e');
    }
  }

  Future<void> setUserProperty({
    required String name,
    required String value,
  }) async {
    try {
      await _analytics.setUserProperty(name: name, value: value);
      // Log only the property name to avoid exposing PII
      debugPrint('[Analytics] User property set: $name');
    } catch (e) {
      // Log only property name and error, not the value
      debugPrint('[Analytics] Error setting user property $name: $e');
    }
  }

  Future<void> logLogin({
    String? method,
  }) async {
    try {
      // Use logEvent to record login with optional method parameter
      await _analytics.logEvent(
        name: 'login',
        parameters: method != null ? {'login_method': method} : null,
      );
      final methodStr = method ?? 'default';
      debugPrint('[Analytics] Login event logged with method: $methodStr');
    } catch (e) {
      debugPrint('[Analytics] Error logging login: $e');
    }
  }

  Future<void> logSignUp({
    String? method,
  }) async {
    try {
      await _analytics.logEvent(
        name: 'sign_up',
        parameters: method != null ? {'method': method} : null,
      );
      debugPrint('[Analytics] Sign up event logged');
    } catch (e) {
      debugPrint('[Analytics] Error logging sign up: $e');
    }
  }

  Future<void> logCustomEvent(String eventName, Map<String, dynamic>? params) async {
    try {
      // Filter out null values to prevent cast errors
      final sanitizedParams = params == null
          ? null
          : <String, Object>{
              for (final entry in params.entries)
                if (entry.value != null) entry.key: entry.value as Object,
            };
      
      await _analytics.logEvent(
        name: eventName,
        parameters: sanitizedParams,
      );
      debugPrint('[Analytics] Custom event logged: $eventName');
    } catch (e) {
      debugPrint('[Analytics] Error logging custom event $eventName: $e');
    }
  }

  // Dispose all services
  void dispose() {
    authService.dispose();
    fileTransferService.dispose();
    profileService.clearProfile();
  }
}

// Global service provider instance
final serviceProvider = ServiceProvider();
