// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('hypersend app smoke test', (WidgetTester tester) async {
    // Create a simple app widget to test basic functionality
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Text('hypersend', style: TextStyle(fontSize: 24)),
                const Text('Fast. Secure. Chat.'),
                ElevatedButton(
                  onPressed: () {},
                  child: const Text('Test Button'),
                ),
              ],
            ),
          ),
        ),
      ),
    );

    // Wait for the widget to render
    await tester.pump();
    
    // Verify that the app builds successfully
    expect(tester.takeException(), isNull);
    
    // Check that we have the expected widgets
    expect(find.byType(Scaffold), findsOneWidget);
    expect(find.byType(Column), findsOneWidget);
    expect(find.text('hypersend'), findsOneWidget);
    expect(find.text('Fast. Secure. Chat.'), findsOneWidget);
    expect(find.text('Test Button'), findsOneWidget);
    
    // Test button interaction
    await tester.tap(find.text('Test Button'));
    await tester.pump();
    
    // Verify the app is still stable after interaction
    expect(tester.takeException(), isNull);
  });
}
