// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:hypersend/main.dart';

void main() {
  testWidgets('hypersend app smoke test', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const HypersendApp());

    // Wait for the splash screen to appear
    await tester.pump();
    
    // Verify that the app builds successfully
    expect(tester.takeException(), isNull);
    
    // Check that we have some widgets on screen
    expect(find.byType(Container), findsWidgets);
    
    // Verify that the splash screen shows the hypersend branding
    expect(find.text('hypersend'), findsOneWidget);
    expect(find.text('Fast. Secure. Chat.'), findsOneWidget);
  });
}
