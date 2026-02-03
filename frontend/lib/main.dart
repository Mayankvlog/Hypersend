import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'core/router/app_router.dart';
import 'core/theme/app_theme.dart';
import 'core/constants/app_strings.dart';
import 'data/services/service_provider.dart';
import 'l10n/app_localizations.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  try {
    debugPrint('[MAIN] Initializing service provider...');
    await serviceProvider.init();
    debugPrint('[MAIN] Service provider initialized successfully');
  } catch (e) {
    debugPrint('[MAIN] ERROR during service provider init: $e');
    // Continue anyway - app can still load with fallback state
  }
  
  runApp(const ZaplyApp());
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

  @override
  void initState() {
    super.initState();
    try {
      _darkMode = serviceProvider.settingsService.darkMode;
      _setupThemeListener();
    } catch (e) {
      debugPrint('[hypersendApp] Initialization error: $e');
      _initError = e.toString();
      _darkMode = false; // Fallback to light theme
    }
  }

  void _setupThemeListener() {
    Future.doWhile(() async {
      await Future.delayed(const Duration(milliseconds: 500));
      if (mounted && !_disposed) {
        try {
          final newDarkMode = serviceProvider.settingsService.darkMode;
          if (_darkMode != newDarkMode) {
            setState(() {
              _darkMode = newDarkMode;
            });
          }
        } catch (e) {
          debugPrint('[hypersendApp] Theme listener error: $e');
        }
      }
      return mounted && !_disposed;
    });
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // If there's an init error, show error screen
    if (_initError != null) {
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
  }
}