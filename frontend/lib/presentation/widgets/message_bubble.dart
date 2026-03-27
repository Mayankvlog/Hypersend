import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';
import '../../core/constants/api_constants.dart';
import '../../core/utils/time_formatter.dart';
import '../../data/models/message.dart';
import '../../data/services/service_provider.dart';
import 'message_reactions_bar.dart';

class MessageBubble extends StatelessWidget {
  final Message message;
  final String? avatarUrl;
  final VoidCallback? onLongPress;
  final void Function(String emoji)? onToggleReaction;
  final VoidCallback? onAddReaction;
  final void Function(Message message)? onFileTap;

  const MessageBubble({
    super.key,
    required this.message,
    this.avatarUrl,
    this.onLongPress,
    this.onToggleReaction,
    this.onAddReaction,
    this.onFileTap,
  });

  Widget _buildFilePreview(Message message) {
    final fileName = message.content ?? 'File';
    final fileExtension = fileName.split('.').last.toLowerCase();
    
    // Check if it's an image file
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'].contains(fileExtension)) {
      return _buildImagePreview(message, fileName);
    }
    
    // Default file preview
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Icon(Icons.insert_drive_file, color: Colors.white70, size: 20),
        const SizedBox(width: 8),
        Flexible(
          child: Text(
            fileName,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 13,
              fontWeight: FontWeight.w500,
              decoration: TextDecoration.underline,
            ),
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }

  Widget _buildImagePreview(Message message, String fileName) {
    final imageUrl = message.fileId != null 
        ? '${ApiConstants.baseUrl}/media/${message.fileId}?download=true'
        : null;
    
    if (imageUrl == null) {
      return _buildFileIcon(fileName);
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          constraints: const BoxConstraints(
            maxWidth: 200,
            maxHeight: 150,
          ),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(8),
            color: Colors.black.withValues(alpha: 0.3),
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(8),
            child: _buildAuthenticatedImage(imageUrl, fileName),
          ),
        ),
        const SizedBox(height: 4),
        Text(
          fileName,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 11,
            fontWeight: FontWeight.w500,
          ),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
      ],
    );
  }

  Widget _buildAuthenticatedImage(String imageUrl, String fileName) {
    final serviceProvider = ServiceProvider();
    final accessToken = serviceProvider.authService.accessToken;
    
    // Build headers for authenticated image request
    Map<String, String> headers = {'Cache-Control': 'no-cache'};
    if (accessToken != null && accessToken.isNotEmpty) {
      headers['Authorization'] = 'Bearer $accessToken';
    }

    return Image.network(
      imageUrl,
      width: 200,
      height: 150,
      fit: BoxFit.cover,
      headers: headers,
      errorBuilder: (context, error, stackTrace) {
        debugPrint('[IMAGE_PREVIEW] Error loading image: $error');
        return Container(
          width: 200,
          height: 150,
          decoration: BoxDecoration(
            color: Colors.red.withValues(alpha: 0.2),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.broken_image, color: Colors.red, size: 32),
              const SizedBox(height: 8),
              Text(
                'Image not available',
                style: TextStyle(
                  color: Colors.red.withValues(alpha: 0.8),
                  fontSize: 12,
                ),
              ),
              Text(
                fileName,
                style: TextStyle(
                  color: Colors.white.withValues(alpha: 0.6),
                  fontSize: 10,
                ),
                textAlign: TextAlign.center,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
            ],
          ),
        );
      },
      loadingBuilder: (context, child, loadingProgress) {
        if (loadingProgress == null) return child;
        return Container(
          width: 200,
          height: 150,
          decoration: BoxDecoration(
            color: Colors.white.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(8),
          ),
          child: const Center(
            child: CircularProgressIndicator(
              valueColor: AlwaysStoppedAnimation<Color>(Colors.white70),
              strokeWidth: 2,
            ),
          ),
        );
      },
    );
  }

  Widget _buildFileIcon(String fileName) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Icon(Icons.insert_drive_file, color: Colors.white70, size: 20),
        const SizedBox(width: 8),
        Flexible(
          child: Text(
            fileName,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 13,
              fontWeight: FontWeight.w500,
              decoration: TextDecoration.underline,
            ),
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }

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
              backgroundImage: avatarUrl!.isNotEmpty && !avatarUrl!.endsWith('/') && !avatarUrl!.contains('/avatar/')
                  ? (avatarUrl!.startsWith('http')
                      ? NetworkImage(
                          avatarUrl!,
                          // CRITICAL FIX: Add cache-busting to prevent stale images
                          headers: {'Cache-Control': 'no-cache'},
                        )
                      : NetworkImage(
                          '${ApiConstants.serverBaseUrl}${avatarUrl!}',
                          // CRITICAL FIX: Add cache-busting to prevent stale images
                          headers: {'Cache-Control': 'no-cache'},
                        )
                  )
                  : null,
              child: avatarUrl!.isNotEmpty && !avatarUrl!.endsWith('/') && !avatarUrl!.contains('/avatar/')
                  ? null
                  : Center(
                      child: Text(
                        '',
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
            child: GestureDetector(
              onLongPress: onLongPress,
              child: Column(
                crossAxisAlignment: message.isOwn
                    ? CrossAxisAlignment.end
                    : CrossAxisAlignment.start,
                children: [
                  if (message.isPinned)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 6),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: const [
                          Icon(Icons.push_pin, size: 14, color: Colors.amber),
                          SizedBox(width: 6),
                          Text(
                            'Pinned',
                            style: TextStyle(
                              color: Colors.amber,
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
                      ),
                    ),
                  Container(
              padding: const EdgeInsets.symmetric(
                horizontal: 16,
                vertical: 12,
              ),
              decoration: BoxDecoration(
                      color: message.isOwn
                          ? AppTheme.primaryCyan
                          : AppTheme.cardDark,
                borderRadius: BorderRadius.only(
                        topLeft:
                            const Radius.circular(AppTheme.borderRadiusMessage),
                        topRight:
                            const Radius.circular(AppTheme.borderRadiusMessage),
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
                  if (message.fileId != null) ...[
                    GestureDetector(
                      onTap: () => onFileTap?.call(message),
                      child: Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: Colors.black.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: _buildFilePreview(message),
                      ),
                    ),
                    const SizedBox(height: 8),
                  ],
                  Text(
                          message.isDeleted
                              ? 'Message deleted'
                              : (message.content ?? ''),
                    style: TextStyle(
                      color: message.isOwn
                          ? Colors.white
                          : AppTheme.textPrimary,
                      fontSize: 15,
                            fontStyle: message.isDeleted
                                ? FontStyle.italic
                                : FontStyle.normal,
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
                            if (message.isEdited && !message.isDeleted) ...[
                              const SizedBox(width: 8),
                              Text(
                                'edited',
                                style: TextStyle(
                                  color: message.isOwn
                                      ? Colors.white.withValues(alpha: 0.8)
                                      : AppTheme.textTertiary,
                                  fontSize: 11,
                                ),
                              ),
                            ],
                      if (message.isOwn) ...[
                              const SizedBox(width: 6),
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
                  if (message.reactions.isNotEmpty &&
                      onToggleReaction != null &&
                      onAddReaction != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 6),
                      child: MessageReactionsBar(
                        reactions: message.reactions,
                        onToggleReaction: onToggleReaction!,
                        onAddReaction: onAddReaction!,
                      ),
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