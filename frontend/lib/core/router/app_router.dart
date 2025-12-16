import 'package:go_router/go_router.dart';
import '../../presentation/screens/splash_screen.dart';
import '../../presentation/screens/permissions_screen.dart';
import '../../presentation/screens/chat_list_screen.dart';
import '../../presentation/screens/chat_detail_screen.dart';
import '../../presentation/screens/chat_settings_screen.dart';
import '../../presentation/screens/profile_edit_screen.dart';
import '../../presentation/screens/settings_screen.dart';
import '../../presentation/screens/file_transfer_screen.dart';
import '../../data/mock/mock_data.dart';

final appRouter = GoRouter(
  initialLocation: '/',
  routes: [
    GoRoute(
      path: '/',
      builder: (context, state) => const SplashScreen(),
    ),
    GoRoute(
      path: '/permissions',
      builder: (context, state) => const PermissionsScreen(),
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
      builder: (context, state) => ProfileEditScreen(
        user: MockData.settingsUser,
      ),
    ),
    GoRoute(
      path: '/settings',
      builder: (context, state) => const SettingsScreen(),
    ),
    GoRoute(
      path: '/file-transfer',
      builder: (context, state) => const FileTransferScreen(),
    ),
  ],
);