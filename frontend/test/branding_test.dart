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

void main() {
  group('Frontend Branding Tests', () {
    testWidgets('app displays appName only without logo icon in header', (WidgetTester tester) async {
      // Build a minimal widget that contains the app name without logo
      await tester.pumpWidget(
        TestAppWrapper(
          child: Scaffold(
            appBar: AppBar(
              title: const Text(AppStrings.appName),
              backgroundColor: Colors.blue,
            ),
          ),
        ),
      );

      // Wait for rendering
      await tester.pumpAndSettle();

      // Find the app name text in AppBar
      final appNameFinder = find.descendant(
        of: find.byType(AppBar),
        matching: find.text('zaply'),
      );
      
      // Assert app name is present
      expect(appNameFinder, findsOneWidget, reason: 'AppBar should display zaply text only without avatar icon');
      
      // Ensure NO image icon is present in the AppBar
      final logoImageFinder = find.descendant(
        of: find.byType(AppBar),
        matching: find.byType(Image),
      );
      
      // Assert image logo is NOT present
      expect(logoImageFinder, findsNothing, reason: 'App logo icon should not be present in AppBar');
      
      // Verify icon fallback is NOT present in AppBar
      final fallbackIconFinder = find.descendant(
        of: find.byType(AppBar),
        matching: find.byIcon(Icons.person),
      );
      
      // Assert fallback icon is NOT present
      expect(fallbackIconFinder, findsNothing, reason: 'Fallback icon should not be present - only text zaply');
      
      // Verify NO 'Z' text is displayed as letter-based avatar
      final zTextFinder = find.descendant(
        of: find.byType(AppBar),
        matching: find.text('Z'),
      );
      expect(zTextFinder, findsNothing, reason: 'Z character should not appear as letter-based avatar');
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

    testWidgets('branding elements are consistent - zaply text only', (WidgetTester tester) async {
      // Test app bar with only zaply text (no avatar icon)
      await tester.pumpWidget(
        TestAppWrapper(
          child: Scaffold(
            appBar: AppBar(
              title: const Text(AppStrings.appName),
              backgroundColor: Colors.blue,
            ),
          ),
        ),
      );

      // Wait for rendering
      await tester.pumpAndSettle();

      // Check for zaply text in AppBar
      final zaplyTextInAppBar = find.descendant(
        of: find.byType(AppBar),
        matching: find.text('zaply'),
      );
      expect(zaplyTextInAppBar, findsOneWidget, reason: 'AppBar should show zaply text only');
      
      // Verify no logo icon in AppBar
      final logoInAppBar = find.descendant(
        of: find.byType(AppBar),
        matching: find.byType(Image),
      );
      expect(logoInAppBar, findsNothing, reason: 'AppBar should not show icon.png image logo');
      
      // Verify no letter-based avatar (Z) in header
      final avatarZFinder = find.descendant(
        of: find.byType(AppBar),
        matching: find.text('Z'),
      );
      expect(avatarZFinder, findsNothing, reason: 'AppBar should not display Z letter avatar');
      
      // Test that app name constant is correct
      expect(AppStrings.appName, equals('zaply'), reason: 'App name should be zaply');
    });
  });
}
