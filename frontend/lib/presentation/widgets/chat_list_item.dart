import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';
import '../../core/utils/time_formatter.dart';
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
    // Check if avatar is a URL (starts with http)
    final isUrl = chat.avatar.startsWith('http');
    
    if (chat.type == ChatType.group || !isUrl) {
      // For groups or when avatar is not a URL, display initials
      return Container(
        width: 56,
        height: 56,
        decoration: const BoxDecoration(
          color: AppTheme.primaryCyan,
          shape: BoxShape.circle,
        ),
        child: Center(
          child: Text(
            chat.avatar,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 18,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
      );
    }

    // For direct chats with URL avatars, use NetworkImage with error handling
    return CircleAvatar(
      radius: 28,
      backgroundColor: AppTheme.cardDark,
      backgroundImage: NetworkImage(chat.avatar),
      onBackgroundImageError: (exception, stackTrace) {
        // Fallback to initials if image fails to load
      },
      child: chat.avatar.isEmpty
          ? const Icon(Icons.person, color: AppTheme.textSecondary)
          : null,
    );
  }
}