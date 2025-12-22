import 'api_service.dart';
import 'auth_service.dart';
import 'profile_service.dart';
import 'settings_service.dart';
import 'file_transfer_service.dart';
import '../models/user.dart';

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
      await authService.init();
      // If logged in, fetch current user and populate profile service
      if (authService.isLoggedIn) {
        try {
          final me = await apiService.getMe();
          profileService.setUser(User.fromApi(me));
        } catch (e) {
          // Ignore errors fetching profile; user will be prompted to log in again
        }
      }
      // Initialization complete
    } catch (e) {
      // Handle initialization error silently
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
