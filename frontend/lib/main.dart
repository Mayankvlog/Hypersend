import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_analytics/firebase_analytics.dart';
import 'dart:async';
import 'core/router/app_router.dart';
import 'core/theme/app_theme.dart';
import 'core/constants/app_strings.dart';
import 'data/services/service_provider.dart';
import 'l10n/app_localizations.dart';

// Firebase Analytics instance - nullable to safely handle initialization failures
FirebaseAnalytics? analytics;
// Flag to track if Firebase/Analytics is available and collection enabled
bool analyticsEnabled = false;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  debugPrint('[MAIN] Starting app initialization...');
  
  try {
    debugPrint('[MAIN] Initializing Firebase...');
    await Firebase.initializeApp();
    // Initialize analytics after Firebase is ready
    analytics = FirebaseAnalytics.instance;
    
    // PRIVACY: Disable analytics collection by default
    // Users must explicitly opt-in via consent UI before collection is enabled
    var collectionDisabled = false;
    try {
      await analytics!.setAnalyticsCollectionEnabled(false);
      collectionDisabled = true;
      debugPrint('[MAIN] Analytics collection disabled by default (requires user consent)');
    } catch (e) {
      debugPrint('[MAIN] WARNING: Could not disable analytics collection: $e');
      // Continue anyway, but mark analytics as enabled only if disabling succeeded
    }
    
    // Only enable analytics if we successfully disabled collection
    if (collectionDisabled) {
      analyticsEnabled = true;
      // Inform service provider that analytics is available
      serviceProvider.setAnalyticsEnabled(true);
      debugPrint('[MAIN] Firebase initialized successfully');
    } else {
      analyticsEnabled = false;
      serviceProvider.setAnalyticsEnabled(false);
      debugPrint('[MAIN] Firebase initialized but analytics disabled (collection control failed)');
    }
  } catch (e, stackTrace) {
    debugPrint('[MAIN] ERROR during Firebase init: $e');
    debugPrint('[MAIN] Stack trace: $stackTrace');
    // Disable analytics if Firebase fails to initialize
    analytics = null;
    analyticsEnabled = false;
    serviceProvider.setAnalyticsEnabled(false);
  }
  
  try {
    debugPrint('[MAIN] Initializing service provider...');
    await serviceProvider.init();
    debugPrint('[MAIN] Service provider initialized successfully');
  } catch (e, stackTrace) {
    debugPrint('[MAIN] ERROR during service provider init: $e');
    debugPrint('[MAIN] Stack trace: $stackTrace');
    // Continue anyway - app can still load with fallback state
  }
  
  debugPrint('[MAIN] Starting ZaplyApp...');
  runApp(const ZaplyApp());
  debugPrint('[MAIN] ZaplyApp started');
}

class ZaplyApp extends StatefulWidget {
  const ZaplyApp({super.key});

  @override
  State<ZaplyApp> createState() => _ZaplyAppState();
}

class _ZaplyAppState extends State<ZaplyApp> {
  late bool _darkMode;
  String? _initError;
  bool _disposed = false;
  Timer? _themeListenerTimer;

  @override
  void initState() {
    super.initState();
    try {
      _darkMode = serviceProvider.settingsService.darkMode;
      _setupThemeListener();
    } catch (e) {
      debugPrint('[ZaplyApp] Initialization error: $e');
      _initError = e.toString();
      _darkMode = false; // Fallback to light theme
    }
  }

  void _setupThemeListener() {
    debugPrint('[ZaplyApp] Setting up theme listener...');
    
    // Use a periodic timer instead of Future.doWhile to prevent memory leaks
    _themeListenerTimer = Timer.periodic(const Duration(milliseconds: 500), (_) {
      if (!mounted || _disposed) {
        debugPrint('[ZaplyApp] Theme listener stopped');
        _themeListenerTimer?.cancel();
        return;
      }
      
      try {
        final newDarkMode = serviceProvider.settingsService.darkMode;
        if (_darkMode != newDarkMode && mounted && !_disposed) {
          debugPrint('[ZaplyApp] Theme changed: $_darkMode -> $newDarkMode');
          setState(() {
            _darkMode = newDarkMode;
          });
        }
      } catch (e) {
        debugPrint('[ZaplyApp] Theme listener error: $e');
      }
    });
  }

  @override
  void dispose() {
    _disposed = true;
    _themeListenerTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    debugPrint('[ZaplyApp] Building app...');
    
    try {
      // If there's an init error, show error screen
      if (_initError != null) {
        debugPrint('[ZaplyApp] Showing error screen: $_initError');
        return MaterialApp(
          home: Scaffold(
            body: Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.error_outline, size: 64, color: Colors.red),
                  const SizedBox(height: 16),
                  const Text('Initialization Error'),
                  const SizedBox(height: 8),
                  Text(_initError!),
                  const SizedBox(height: 24),
                  ElevatedButton(
                    onPressed: () {
                      setState(() {
                        _initError = null;
                      });
                    },
                    child: const Text('Retry'),
                  ),
                ],
              ),
            ),
          ),
        );
      }

      debugPrint('[ZaplyApp] Creating MaterialApp.router...');
      return MaterialApp.router(
        title: AppStrings.appName,
        debugShowCheckedModeBanner: false,
        theme: _darkMode ? AppTheme.darkTheme : AppTheme.lightTheme,
        routerConfig: appRouter,
        supportedLocales: AppLocalizations.supportedLocales,
        locale: AppLocalizations.fallbackLocale,
        localizationsDelegates: [
          AppLocalizations.delegate,
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
        ],
      );
    } catch (e, stackTrace) {
      debugPrint('[ZaplyApp] Build error: $e');
      debugPrint('[ZaplyApp] Stack trace: $stackTrace');
      
      // Fallback to a simple error screen
      return MaterialApp(
        home: Scaffold(
          body: Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.error_outline, size: 64, color: Colors.red),
                const SizedBox(height: 16),
                const Text('App Build Error'),
                const SizedBox(height: 8),
                Text(e.toString()),
                const SizedBox(height: 24),
                ElevatedButton(
                  onPressed: () {
                    setState(() {});
                  },
                  child: const Text('Retry'),
                ),
              ],
            ),
          ),
        ),
      );
    }
  }
}