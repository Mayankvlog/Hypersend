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

class ZaplyApp extends StatelessWidget {
  const ZaplyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      title: AppStrings.appName,
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      routerConfig: appRouter,
    );
  }
}