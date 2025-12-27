import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';
import '../../core/utils/time_formatter.dart';
import '../../core/constants/api_constants.dart';
import '../../data/models/chat.dart';

class ChatListItem extends StatelessWidget {
  final Chat chat;
  final VoidCallback onTap;

  const ChatListItem({
    super.key,
    required this.chat,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(
          horizontal: AppTheme.spacing16,
          vertical: AppTheme.spacing12,
        ),
        child: Row(
          children: [
            // Avatar
            Stack(
              children: [
                _buildAvatar(),
                if (chat.isOnline)
                  Positioned(
                    right: 0,
                    bottom: 0,
                    child: Container(
                      width: 16,
                      height: 16,
                      decoration: BoxDecoration(
                        color: AppTheme.successGreen,
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: AppTheme.backgroundDark,
                          width: 2,
                        ),
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(width: 12),
            // Chat info
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          chat.name,
                          style: Theme.of(context).textTheme.titleMedium,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        TimeFormatter.formatChatListTime(chat.lastMessageTime),
                        style: Theme.of(context).textTheme.bodySmall?.copyWith(
                              color: chat.unreadCount > 0
                                  ? AppTheme.primaryCyan
                                  : AppTheme.textTertiary,
                            ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          chat.senderName != null
                              ? '${chat.senderName}: ${chat.lastMessage}'
                              : chat.lastMessage,
                          style: Theme.of(context).textTheme.bodyMedium,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (chat.unreadCount > 0) ...[
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 8,
                            vertical: 4,
                          ),
                          decoration: const BoxDecoration(
                            color: AppTheme.primaryCyan,
                            shape: BoxShape.circle,
                          ),
                          constraints: const BoxConstraints(
                            minWidth: 24,
                            minHeight: 24,
                          ),
                          child: Center(
                            child: Text(
                              chat.unreadCount.toString(),
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ),
                      ],
                      if (chat.isMuted) ...[
                        const SizedBox(width: 8),
                        const Icon(
                          Icons.volume_off,
                          size: 16,
                          color: AppTheme.textTertiary,
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAvatar() {
    // Saved Messages special case
    if (chat.type == ChatType.saved) {
      return Container(
        width: 56,
        height: 56,
        decoration: const BoxDecoration(
          color: AppTheme.primaryPurple,
          shape: BoxShape.circle,
        ),
        child: const Center(
          child: Icon(Icons.bookmark, color: Colors.white, size: 28),
        ),
      );
    }

    final isUrl = chat.avatar.startsWith('http') || chat.avatar.startsWith('/');
    
    if (!isUrl || chat.avatar.isEmpty) {
      // If avatar field is not empty and not a URL, it might be initials (e.g., from default avatars)
      final String initials = (chat.avatar.isNotEmpty && chat.avatar.length <= 3) 
          ? chat.avatar.toUpperCase()
          : (chat.name.length >= 2 ? chat.name.substring(0, 2).toUpperCase() : chat.name.toUpperCase());
      
      IconData? typeIcon;
      if (chat.type == ChatType.channel) typeIcon = Icons.campaign;
      if (chat.type == ChatType.supergroup) typeIcon = Icons.groups;
      if (chat.type == ChatType.secret) typeIcon = Icons.lock;
      
      return Container(
        width: 56,
        height: 56,
        decoration: BoxDecoration(
          color: AppTheme.primaryCyan.withValues(alpha: 0.2),
          shape: BoxShape.circle,
        ),
        child: Center(
          child: typeIcon != null 
            ? Icon(typeIcon, color: AppTheme.primaryCyan, size: 24)
            : Text(
                initials,
                style: const TextStyle(
                  color: AppTheme.primaryCyan,
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                ),
              ),
        ),
      );
    }

    final fullUrl = chat.avatar.startsWith('/') 
        ? '${ApiConstants.serverBaseUrl}${chat.avatar}'
        : chat.avatar;

    // Use a temporary user object (or simple logic) to get initials
    final initials = chat.name.length >= 2 
        ? chat.name.substring(0, 2).toUpperCase() 
        : chat.name.toUpperCase();

    return CircleAvatar(
      radius: 28,
      backgroundColor: AppTheme.cardDark,
      backgroundImage: NetworkImage(fullUrl),
      onBackgroundImageError: (exception, stackTrace) {
        debugPrint('Error loading avatar: $exception');
      },
      child: Center(
        child: Text(
          initials,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 16,
            fontWeight: FontWeight.bold,
          ),
        ),
      ),
    );
  }
}