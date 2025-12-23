import 'package:go_router/go_router.dart';
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
import '../../presentation/screens/channel_creation_screen.dart';
import '../../presentation/screens/secret_chat_screen.dart';
import '../../presentation/screens/group_detail_screen.dart';
import '../../data/mock/mock_data.dart';
import '../../data/services/service_provider.dart';

final appRouter = GoRouter(
  initialLocation: '/',
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
      path: '/channel-create',
      builder: (context, state) => const ChannelCreationScreen(),
    ),
    GoRoute(
      path: '/secret-chat',
      builder: (context, state) => const SecretChatScreen(),
    ),
    GoRoute(
      path: '/group/:id',
      builder: (context, state) {
        final groupId = state.pathParameters['id']!;
        return GroupDetailScreen(groupId: groupId);
      },
    ),
  ],
);