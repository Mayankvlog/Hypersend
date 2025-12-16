import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';
import '../../core/utils/time_formatter.dart';
import '../../data/models/message.dart';

class MessageBubble extends StatelessWidget {
  final Message message;
  final String? avatarUrl;

  const MessageBubble({
    super.key,
    required this.message,
    this.avatarUrl,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(
        horizontal: AppTheme.spacing16,
        vertical: AppTheme.spacing8,
      ),
      child: Row(
        mainAxisAlignment:
            message.isOwn ? MainAxisAlignment.end : MainAxisAlignment.start,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (!message.isOwn && avatarUrl != null) ...[
            CircleAvatar(
              radius: 16,
              backgroundColor: AppTheme.cardDark,
              backgroundImage: avatarUrl!.startsWith('http')
                  ? NetworkImage(avatarUrl!)
                  : null,
              onBackgroundImageError: (exception, stackTrace) {
                // Fallback handled by child
              },
              child: avatarUrl!.startsWith('http')
                  ? null
                  : Center(
                      child: Text(
                        avatarUrl!.length > 2
                            ? avatarUrl!.substring(0, 2).toUpperCase()
                            : avatarUrl!.toUpperCase(),
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 10,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
            ),
            const SizedBox(width: 8),
          ],
          Flexible(
            child: Container(
              padding: const EdgeInsets.symmetric(
                horizontal: 16,
                vertical: 12,
              ),
              decoration: BoxDecoration(
                color: message.isOwn ? AppTheme.primaryCyan : AppTheme.cardDark,
                borderRadius: BorderRadius.only(
                  topLeft: const Radius.circular(AppTheme.borderRadiusMessage),
                  topRight: const Radius.circular(AppTheme.borderRadiusMessage),
                  bottomLeft: Radius.circular(
                    message.isOwn ? AppTheme.borderRadiusMessage : 4,
                  ),
                  bottomRight: Radius.circular(
                    message.isOwn ? 4 : AppTheme.borderRadiusMessage,
                  ),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    message.content,
                    style: TextStyle(
                      color: message.isOwn
                          ? Colors.white
                          : AppTheme.textPrimary,
                      fontSize: 15,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        TimeFormatter.formatMessageTime(message.timestamp),
                        style: TextStyle(
                          color: message.isOwn
                              ? Colors.white.withValues(alpha: 0.8)
                              : AppTheme.textTertiary,
                          fontSize: 11,
                        ),
                      ),
                      if (message.isOwn) ...[
                        const SizedBox(width: 4),
                        Icon(
                          message.status == MessageStatus.read
                              ? Icons.done_all
                              : Icons.done,
                          size: 14,
                          color: message.status == MessageStatus.read
                              ? Colors.white
                              : Colors.white.withValues(alpha: 0.6),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
          ),
          if (message.isOwn) const SizedBox(width: 40),
          if (!message.isOwn && avatarUrl != null) const SizedBox(width: 40),
        ],
      ),
    );
  }
}