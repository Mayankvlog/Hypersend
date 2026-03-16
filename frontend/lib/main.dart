import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_web_plugins/url_strategy.dart';
import 'dart:async';

import 'core/router/app_router.dart';
import 'core/theme/app_theme.dart';
import 'core/constants/app_strings.dart';
import 'data/services/service_provider.dart';
import 'l10n/app_localizations.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Enable path-based URL strategy for Flutter Web (no hash in URLs)
  usePathUrlStrategy();

  // Using url_strategy package to ensure clean path-based URLs without hash fragments

  debugPrint('[MAIN] Starting app initialization...');

  try {
    debugPrint('[MAIN] Initializing service provider...');
    await serviceProvider.init();
    debugPrint('[MAIN] Service provider initialized successfully');
  } catch (e, stackTrace) {
    debugPrint('[MAIN] ERROR during service provider init: $e');
    debugPrint('[MAIN] Stack trace: $stackTrace');
  }

  debugPrint('[MAIN] Starting ZaplyApp...');
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
      _darkMode = false;
    }
  }

  void _setupThemeListener() {
    debugPrint('[ZaplyApp] Setting up theme listener...');

    _themeListenerTimer =
        Timer.periodic(const Duration(milliseconds: 500), (_) {
      if (!mounted || _disposed) {
        _themeListenerTimer?.cancel();
        return;
      }

      try {
        final newDarkMode = serviceProvider.settingsService.darkMode;

        if (_darkMode != newDarkMode) {
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
      if (_initError != null) {
        return MaterialApp(
          home: Scaffold(
            body: Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.error_outline,
                      size: 64, color: Colors.red),
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
        localizationsDelegates: const [
          AppLocalizations.delegate,
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
        ],
      );
    } catch (e, stackTrace) {
      debugPrint('[ZaplyApp] Build error: $e');
      debugPrint('[ZaplyApp] Stack trace: $stackTrace');

      return MaterialApp(
        home: Scaffold(
          body: Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.error_outline,
                    size: 64, color: Colors.red),
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