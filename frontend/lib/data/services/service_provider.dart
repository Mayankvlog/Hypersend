import 'api_service.dart';
import 'auth_service.dart';
import 'profile_service.dart';
import 'settings_service.dart';
import 'file_transfer_service.dart';
import '../models/user.dart';
import 'package:flutter/foundation.dart';

class ServiceProvider {
  static final ServiceProvider _instance = ServiceProvider._internal();

  late final ApiService apiService;
  late final AuthService authService;
  late final ProfileService profileService;
  late final SettingsService settingsService;
  late final FileTransferService fileTransferService;

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

  // Dispose all services
  void dispose() {
    profileService.clearProfile();
    fileTransferService.clearAll();
  }
}

// Global service provider instance
final serviceProvider = ServiceProvider();
