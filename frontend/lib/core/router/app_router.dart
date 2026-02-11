import 'package:go_router/go_router.dart';
import 'package:flutter/material.dart';
import 'package:firebase_analytics/firebase_analytics.dart';
import '../../presentation/screens/splash_screen.dart';
import '../../presentation/screens/auth_screen.dart';
import '../../presentation/screens/chat_list_screen.dart';
import '../../presentation/screens/chat_detail_screen.dart';
import '../../presentation/screens/chat_settings_screen.dart';
import '../../presentation/screens/profile_edit_screen.dart';
import '../../presentation/screens/profile_photo_screen.dart';
import '../../presentation/screens/settings_screen.dart';
import '../../presentation/screens/file_transfer_screen.dart';
import '../../presentation/screens/notification_sound_screen.dart';
import '../../presentation/screens/privacy_settings_screen.dart';
import '../../presentation/screens/blocked_users_screen.dart';
import '../../presentation/screens/storage_manager_screen.dart';
import '../../presentation/screens/help_support_screen.dart';
import '../../presentation/screens/group_creation_screen.dart';

import '../../presentation/screens/group_detail_screen.dart';
import '../../data/mock/mock_data.dart';
import '../../data/services/service_provider.dart';

final FirebaseAnalytics _analytics = FirebaseAnalytics.instance;

/// Sanitize route names to remove PII (user IDs, query strings, etc.)
String? _sanitizeRouteName(RouteSettings settings) {
  if (settings.name == null) return null;
  
  String routeName = settings.name!;
  
  // Remove or replace dynamic segments that contain PII
  // Examples: /chat/:id -> /chat, /user/:query -> /user, /group/:id -> /group
  routeName = routeName.replaceAll(RegExp(r'/:.*'), '');
  
  // Map to generic screen names - keys MUST match actual route paths (after PII sanitization)
  const routeNameMap = {
    '/': 'home',
    '/auth': 'auth',
    '/chats': 'chat_list',
    '/chat': 'chat_detail',      // /chat/:id becomes /chat after sanitization
    '/chat-settings': 'chat_settings',
    '/profile-edit': 'profile_edit',
    '/profile-photo': 'profile_photo',
    '/settings': 'settings',
    '/file-transfer': 'file_transfer',
    '/notification-sound': 'notification_settings',
    '/privacy-settings': 'privacy_settings',
    '/blocked-users': 'blocked_users',
    '/storage-manager': 'storage_manager',
    '/help-support': 'help_support',
    '/group-create': 'group_creation',
    '/group': 'group_detail',    // /group/:id becomes /group after sanitization
    '/user': 'user_profile',     // /user/:query becomes /user after sanitization
  };
  
  // Return mapped name or original (with PII removed) as fallback
  return routeNameMap[routeName] ?? routeName;
}

final appRouter = GoRouter(
  initialLocation: '/',
  observers: [
    FirebaseAnalyticsObserver(
      analytics: _analytics,
      nameExtractor: _sanitizeRouteName,
    ),
  ],
  errorBuilder: (context, state) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 64, color: Colors.red),
            const SizedBox(height: 16),
            const Text('Navigation Error'),
            const SizedBox(height: 8),
            Text(state.error.toString()),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: () => context.go('/'),
              child: const Text('Go Home'),
            ),
          ],
        ),
      ),
    );
  },
  routes: [
    GoRoute(
      path: '/',
      builder: (context, state) => const SplashScreen(),
    ),
    GoRoute(
      path: '/auth',
      builder: (context, state) => const AuthScreen(),
    ),
    GoRoute(
      path: '/chats',
      builder: (context, state) => const ChatListScreen(),
    ),
    GoRoute(
      path: '/chat/:id',
      builder: (context, state) {
        final chatId = state.pathParameters['id']!;
        return ChatDetailScreen(chatId: chatId);
      },
    ),
    GoRoute(
      path: '/chat-settings',
      builder: (context, state) => const ChatSettingsScreen(),
    ),
    GoRoute(
      path: '/profile-edit',
      builder: (context, state) {
        // Get current user from ProfileService, fallback to mock if not available
        final user = serviceProvider.profileService.currentUser ?? MockData.settingsUser;
        return ProfileEditScreen(user: user);
      },
    ),
    GoRoute(
      path: '/profile-photo',
      builder: (context, state) {
        final currentAvatar = state.extra as String? ?? 'AM';
        return ProfilePhotoScreen(currentAvatar: currentAvatar);
      },
    ),
    GoRoute(
      path: '/settings',
      builder: (context, state) => const SettingsScreen(),
    ),
    GoRoute(
      path: '/file-transfer',
      builder: (context, state) => const FileTransferScreen(),
    ),
    GoRoute(
      path: '/notification-sound',
      builder: (context, state) => const NotificationSoundScreen(),
    ),
    GoRoute(
      path: '/privacy-settings',
      builder: (context, state) => const PrivacySettingsScreen(),
    ),
    GoRoute(
      path: '/blocked-users',
      builder: (context, state) => const BlockedUsersScreen(),
    ),
    GoRoute(
      path: '/storage-manager',
      builder: (context, state) => const StorageManagerScreen(),
    ),
    GoRoute(
      path: '/help-support',
      builder: (context, state) => const HelpSupportScreen(),
    ),
    GoRoute(
      path: '/group-create',
      builder: (context, state) => const GroupCreationScreen(),
    ),

    GoRoute(
      path: '/group/:id',
      builder: (context, state) {
        final groupId = state.pathParameters['id']!;
        return GroupDetailScreen(groupId: groupId);
      },
    ),
    GoRoute(
      path: '/user/:query',
      builder: (context, state) {
        // Route to user profile screen that handles search and display
        // Supports @username format
        return ChatListScreen();
      },
    ),
  ],
);