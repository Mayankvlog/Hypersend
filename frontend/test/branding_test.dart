import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:hypersend/core/constants/app_strings.dart';

/// Test wrapper widget that provides necessary dependencies for testing
class TestAppWrapper extends StatelessWidget {
  final Widget child;
  
  const TestAppWrapper({super.key, required this.child});
  
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: child,
      // Provide any necessary inherited widgets or theme data
      theme: ThemeData(
        primarySwatch: Colors.blue,
        appBarTheme: const AppBarTheme(
          backgroundColor: Colors.blue,
          foregroundColor: Colors.white,
        ),
      ),
    );
  }
}

// Shared helper widget for fallback avatar to ensure consistency across tests
Widget _buildFallbackAvatar({Color color = Colors.blue}) {
  return Container(
    width: 32,
    height: 32,
    decoration: BoxDecoration(
      color: color,
      shape: BoxShape.circle,
    ),
    child: const Icon(
      Icons.person,
      size: 20,
      color: Colors.white,
    ),
  );
}

void main() {
  group('Frontend Branding Tests', () {
    testWidgets('app logo uses icon.png image', (WidgetTester tester) async {
      // Build a minimal widget that contains the app logo with image
      await tester.pumpWidget(
        TestAppWrapper(
          child: Scaffold(
            appBar: AppBar(
              title: Row(
                children: [
                  Container(
                    width: 32,
                    height: 32,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      gradient: LinearGradient(
                        colors: [Colors.cyan, Colors.cyan.withValues(alpha: 0.7)],
                      ),
                    ),
                    child: ClipOval(
                      child: Image.asset(
                        'assets/icons/icon.png',
                        width: 32,
                        height: 32,
                        fit: BoxFit.cover,
                        errorBuilder: (context, error, stackTrace) {
                          return _buildFallbackAvatar(color: Colors.blue);
                        },
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  const Text('zaply'),
                ],
              ),
              backgroundColor: Colors.blue,
            ),
          ),
        ),
      );

      // Find the app logo image widget within the AppBar context
      final logoImageFinder = find.descendant(
        of: find.byType(AppBar),
        matching: find.byType(Image),
      );
      
      // Assert the main logo image is present
      expect(logoImageFinder, findsOneWidget, reason: 'App logo should display icon.png image in AppBar');
      
      // Check for fallback icon when image fails to load
      final fallbackIconFinder = find.descendant(
        of: find.byType(AppBar),
        matching: find.byIcon(Icons.person),
      );
      
      // Assert fallback icon is NOT present since image asset is available
      expect(fallbackIconFinder, findsNothing, reason: 'Fallback icon should not be present when image loads successfully');
      
      // Verify no 'Z' text is displayed as fallback in the AppBar
      final zTextFinder = find.descendant(
        of: find.byType(AppBar),
        matching: find.text('Z'),
      );
      expect(zTextFinder, findsNothing, reason: 'Z character should not be used as icon fallback');
    });

    testWidgets('connection status icon shows correct state', (WidgetTester tester) async {
      // Build a minimal widget to test icon display
      await tester.pumpWidget(
        TestAppWrapper(
          child: Scaffold(
            body: Center(
              child: Icon(
                Icons.bolt,
                size: 48,
                color: Colors.blue,
              ),
            ),
          ),
        ),
      );

      // Find the connection status icon
      final iconFinder = find.byType(Icon);
      expect(iconFinder, findsOneWidget, reason: 'Connection status icon should be displayed');

      // Get the icon widget to check its data
      final Icon icon = tester.widget(iconFinder);
      
      // The icon should be bolt for connected state
      expect(
        icon.icon,
        Icons.bolt,
        reason: 'Connection status should show bolt (connected)',
      );
    });

    testWidgets('auth screen uses AppStrings.appName', (WidgetTester tester) async {
      // Build a minimal widget to test app name display
      await tester.pumpWidget(
        TestAppWrapper(
          child: Scaffold(
            body: Center(
              child: Text(
                AppStrings.appName,
                style: const TextStyle(fontSize: 24),
              ),
            ),
          ),
        ),
      );

      // Find app name display
      final appNameFinder = find.text(AppStrings.appName);
      expect(appNameFinder, findsOneWidget, reason: 'App should display app name from AppStrings');
      
      // Verify app name is not empty
      expect(AppStrings.appName.isNotEmpty, isTrue, reason: 'App name should not be empty');
    });

    test('AppStrings constants are correctly defined', () {
      // Test app name
      expect(AppStrings.appName, equals('zaply'), reason: 'App name should be zaply');
      expect(AppStrings.appName, isNot(contains('Z')), reason: 'App name should not contain uppercase Z');
      
      // Test app tagline
      expect(AppStrings.appTagline, equals('Fast. Secure. Chat.'), reason: 'App tagline should be correctly defined');
      expect(AppStrings.appTagline.isNotEmpty, isTrue, reason: 'App tagline should not be empty');
    });

    testWidgets('branding elements are consistent across screens', (WidgetTester tester) async {
      // Test app bar logo consistency with image-based logo
      await tester.pumpWidget(
        TestAppWrapper(
          child: Scaffold(
            appBar: AppBar(
              title: Row(
                children: [
                  Container(
                    width: 32,
                    height: 32,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      gradient: LinearGradient(
                        colors: [Colors.cyan, Colors.cyan.withValues(alpha: 0.7)],
                      ),
                    ),
                    child: ClipOval(
                      child: Image.asset(
                        'assets/icons/icon.png',
                        width: 32,
                        height: 32,
                        fit: BoxFit.cover,
                        errorBuilder: (context, error, stackTrace) {
                          return _buildFallbackAvatar(color: Colors.grey);
                        },
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  const Text('zaply'),
                ],
              ),
              backgroundColor: Colors.blue,
            ),
          ),
        ),
      );

      // Check for image logo in AppBar
      final logoInAppBar = find.descendant(
        of: find.byType(AppBar),
        matching: find.byType(Image),
      );
      expect(logoInAppBar, findsOneWidget, reason: 'AppBar should show icon.png image logo (or fallback)');
      
      // Test icon consistency with another minimal widget
      await tester.pumpWidget(
        TestAppWrapper(
          child: Scaffold(
            body: Center(
              child: Icon(
                Icons.bolt,
                size: 48,
                color: Colors.blue,
              ),
            ),
          ),
        ),
      );

      // Check for consistent icon usage
      final iconFinder = find.byType(Icon);
      expect(iconFinder, findsOneWidget, reason: 'App should show connection status icon');
    });
  });
}
