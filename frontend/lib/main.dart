import 'package:flutter/material.dart';
import 'core/router/app_router.dart';
import 'core/theme/app_theme.dart';
import 'core/constants/app_strings.dart';
import 'data/services/service_provider.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await serviceProvider.init();
  runApp(const ZaplyApp());
}

class ZaplyApp extends StatefulWidget {
  const ZaplyApp({super.key});

  @override
  State<ZaplyApp> createState() => _ZaplyAppState();
}

class _ZaplyAppState extends State<ZaplyApp> {
  late bool _darkMode;

  @override
  void initState() {
    super.initState();
    _darkMode = serviceProvider.settingsService.darkMode;
    // Listen for theme changes
    _setupThemeListener();
  }

  void _setupThemeListener() {
    // Periodically check for theme changes (in a real app, use a proper state management solution)
    Future.doWhile(() async {
      await Future.delayed(const Duration(milliseconds: 500));
      if (mounted && _darkMode != serviceProvider.settingsService.darkMode) {
        setState(() {
          _darkMode = serviceProvider.settingsService.darkMode;
        });
      }
      return mounted;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      title: AppStrings.appName,
      debugShowCheckedModeBanner: false,
      theme: _darkMode ? AppTheme.darkTheme : AppTheme.lightTheme,
      routerConfig: appRouter,
    );
  }
}