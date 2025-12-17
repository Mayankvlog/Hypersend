import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/constants/app_strings.dart';
import '../../core/theme/app_theme.dart';
import '../../data/mock/mock_data.dart';
import '../../data/models/message.dart';
import '../../data/models/chat.dart';
import '../../data/models/group.dart';
import '../widgets/message_bubble.dart';

class ChatDetailScreen extends StatefulWidget {
  final String chatId;

  const ChatDetailScreen({
    super.key,
    required this.chatId,
  });

  @override
  State<ChatDetailScreen> createState() => _ChatDetailScreenState();
}

class _ChatDetailScreenState extends State<ChatDetailScreen> {
  final TextEditingController _messageController = TextEditingController();
  late List<Message> _messages;
  late final Chat _chat;
  Group? _group;

  static const List<String> _quickReactions = ['👍', '❤️', '😂', '😮', '😢', '🔥'];

  @override
  void initState() {
    super.initState();
    _chat = MockData.chats.firstWhere((c) => c.id == widget.chatId);
    _group = MockData.groups.where((g) => g.id == widget.chatId).isNotEmpty
        ? MockData.groups.firstWhere((g) => g.id == widget.chatId)
        : null;
    _messages = MockData.messages.where((m) => m.chatId == widget.chatId).toList();
    _markAllVisibleAsRead();
  }

  @override
  void dispose() {
    _messageController.dispose();
    super.dispose();
  }

  void _sendMessage() {
    if (_messageController.text.trim().isEmpty) return;

    setState(() {
      _messages.add(
        Message(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          chatId: widget.chatId,
          senderId: 'me',
          content: _messageController.text.trim(),
          timestamp: DateTime.now(),
          status: MessageStatus.sent,
          isOwn: true,
          readBy: const ['me'],
        ),
      );
    });

    _messageController.clear();
  }

  void _markAllVisibleAsRead() {
    final me = MockData.currentUser.id;
    setState(() {
      _messages = _messages
          .map((m) => m.readBy.contains(me) ? m : m.copyWith(readBy: [...m.readBy, me]))
          .toList();
    });
  }

  void _togglePin(Message message) {
    setState(() {
      _messages = _messages
          .map((m) => m.id == message.id ? m.copyWith(isPinned: !m.isPinned) : m)
          .toList();
    });
  }

  void _toggleReaction(Message message, String emoji) {
    final me = MockData.currentUser.id;
    final current = Map<String, List<String>>.from(message.reactions);
    final users = List<String>.from(current[emoji] ?? const []);
    if (users.contains(me)) {
      users.remove(me);
    } else {
      users.add(me);
    }
    if (users.isEmpty) {
      current.remove(emoji);
    } else {
      current[emoji] = users;
    }

    setState(() {
      _messages = _messages
          .map((m) => m.id == message.id ? m.copyWith(reactions: current) : m)
          .toList();
    });
  }

  Future<void> _showReactionPicker(Message message) async {
    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: AppTheme.backgroundDark,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                for (final emoji in _quickReactions)
                  InkWell(
                    onTap: () {
                      Navigator.of(context).pop();
                      _toggleReaction(message, emoji);
                    },
                    borderRadius: BorderRadius.circular(12),
                    child: Container(
                      width: 48,
                      height: 48,
                      alignment: Alignment.center,
                      decoration: BoxDecoration(
                        color: AppTheme.cardDark,
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Text(emoji, style: const TextStyle(fontSize: 22)),
                    ),
                  ),
              ],
            ),
          ),
        );
      },
    );
  }

  Future<void> _editMessage(Message message) async {
    final controller = TextEditingController(text: message.content ?? '');
    final newText = await showDialog<String>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          title: const Text('Edit Message'),
          content: TextField(
            controller: controller,
            maxLines: null,
            decoration: const InputDecoration(
              border: OutlineInputBorder(),
              hintText: 'Edit your message',
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(),
              child: const Text('Cancel'),
            ),
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(controller.text.trim()),
              child: const Text('Update'),
            ),
          ],
        );
      },
    );

    if (newText == null || newText.isEmpty) return;
    setState(() {
      _messages = _messages
          .map((m) => m.id == message.id ? m.copyWith(content: newText, isEdited: true, editedAt: DateTime.now()) : m)
          .toList();
    });
  }

  Future<void> _deleteMessage(Message message) async {
    final confirm = await showDialog<bool>(
          context: context,
          builder: (dialogContext) {
            return AlertDialog(
              title: const Text('Delete Message'),
              content: const Text('Are you sure you want to delete this message?'),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(false),
                  child: const Text('Cancel'),
                ),
                TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(true),
                  child: const Text(
                    'Delete',
                    style: TextStyle(color: AppTheme.errorRed),
                  ),
                ),
              ],
            );
          },
        ) ??
        false;

    if (!confirm) return;
    setState(() {
      _messages = _messages
          .map((m) => m.id == message.id ? m.copyWith(isDeleted: true, deletedAt: DateTime.now(), content: '') : m)
          .toList();
    });
  }

  Future<void> _showMessageActions(Message message) async {
    final canEdit = message.isOwn && !message.isDeleted;
    final canDelete = message.isOwn && !message.isDeleted;

    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: AppTheme.backgroundDark,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) {
        return SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(Icons.emoji_emotions_outlined, color: AppTheme.primaryCyan),
                title: const Text('React'),
                onTap: () {
                  Navigator.of(context).pop();
                  _showReactionPicker(message);
                },
              ),
              ListTile(
                leading: Icon(message.isPinned ? Icons.push_pin_outlined : Icons.push_pin, color: Colors.amber),
                title: Text(message.isPinned ? 'Unpin' : 'Pin'),
                onTap: () {
                  Navigator.of(context).pop();
                  _togglePin(message);
                },
              ),
              if (canEdit) ...[
                const Divider(height: 0),
                ListTile(
                  leading: const Icon(Icons.edit_outlined, color: AppTheme.primaryCyan),
                  title: const Text('Edit'),
                  onTap: () {
                    Navigator.of(context).pop();
                    _editMessage(message);
                  },
                ),
              ],
              if (canDelete) ...[
                const Divider(height: 0),
                ListTile(
                  leading: const Icon(Icons.delete_outline, color: AppTheme.errorRed),
                  title: const Text('Delete'),
                  onTap: () {
                    Navigator.of(context).pop();
                    _deleteMessage(message);
                  },
                ),
              ],
              const Divider(height: 0),
              ListTile(
                leading: const Icon(Icons.done_all, color: AppTheme.textSecondary),
                title: Text('Read by: ${message.readBy.length}'),
                onTap: () => Navigator.of(context).pop(),
              ),
            ],
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final user = MockData.chatUser;
    final pinned = _messages.where((m) => m.isPinned && !m.isDeleted).toList();

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: Row(
          children: [
            Stack(
              children: [
                CircleAvatar(
                  radius: 20,
                  backgroundColor: AppTheme.cardDark,
                  backgroundImage: user.avatar.startsWith('http')
                      ? NetworkImage(user.avatar)
                      : null,
                  onBackgroundImageError: (exception, stackTrace) {
                    // Fallback handled by child
                  },
                  child: user.avatar.startsWith('http')
                      ? null
                      : Center(
                          child: Text(
                            user.avatar.length > 2
                                ? user.avatar.substring(0, 2).toUpperCase()
                                : user.avatar.toUpperCase(),
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                ),
                if (user.isOnline)
                  Positioned(
                    right: 0,
                    bottom: 0,
                    child: Container(
                      width: 12,
                      height: 12,
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
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    _chat.type == ChatType.group ? _chat.name : user.name,
                    style: const TextStyle(fontSize: 16),
                  ),
                  Text(
                    _chat.type == ChatType.group ? '${(_group?.members.length ?? 0)} members' : AppStrings.online,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: AppTheme.primaryCyan,
                        ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          if (_chat.type == ChatType.group)
            IconButton(
              icon: const Icon(Icons.info_outline),
              onPressed: () => context.push('/group/${_chat.id}'),
            ),
          IconButton(
            icon: const Icon(Icons.more_vert),
            onPressed: () {},
          ),
        ],
      ),
      body: Column(
        children: [
          if (pinned.isNotEmpty)
            Container(
              width: double.infinity,
              margin: const EdgeInsets.fromLTRB(16, 12, 16, 0),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.amber.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.amber.withValues(alpha: 0.35)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.push_pin, color: Colors.amber, size: 18),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      pinned.last.content ?? '',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: AppTheme.textPrimary,
                          ),
                    ),
                  ),
                ],
              ),
            ),
          // Messages list
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.symmetric(vertical: 16),
              itemCount: _messages.length + 1, // +1 for date divider
              itemBuilder: (context, index) {
                if (index == 0) {
                  return Center(
                    child: Container(
                      margin: const EdgeInsets.symmetric(vertical: 16),
                      padding: const EdgeInsets.symmetric(
                        horizontal: 16,
                        vertical: 6,
                      ),
                      decoration: BoxDecoration(
                        color: AppTheme.cardDark,
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Text(
                        AppStrings.today,
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ),
                  );
                }

                final message = _messages[index - 1];
                return MessageBubble(
                  message: message,
                  avatarUrl: message.isOwn ? null : user.avatar,
                  onLongPress: () => _showMessageActions(message),
                  onToggleReaction: (emoji) => _toggleReaction(message, emoji),
                  onAddReaction: () => _showReactionPicker(message),
                );
              },
            ),
          ),
          // Input bar
          Container(
            padding: const EdgeInsets.all(AppTheme.spacing16),
            decoration: const BoxDecoration(
              color: AppTheme.backgroundDark,
              border: Border(
                top: BorderSide(
                  color: AppTheme.dividerColor,
                  width: 1,
                ),
              ),
            ),
            child: Row(
              children: [
                IconButton(
                  icon: const Icon(Icons.attach_file),
                  onPressed: () {},
                  color: AppTheme.textSecondary,
                ),
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: InputDecoration(
                      hintText: AppStrings.typeMessage,
                      suffixIcon: IconButton(
                        icon: const Icon(Icons.emoji_emotions_outlined),
                        onPressed: () {},
                        color: AppTheme.textSecondary,
                      ),
                    ),
                    onSubmitted: (_) => _sendMessage(),
                  ),
                ),
                const SizedBox(width: 8),
                Container(
                  width: 48,
                  height: 48,
                  decoration: const BoxDecoration(
                    color: AppTheme.primaryCyan,
                    shape: BoxShape.circle,
                  ),
                  child: IconButton(
                    icon: const Icon(Icons.send),
                    onPressed: _sendMessage,
                    color: Colors.white,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}