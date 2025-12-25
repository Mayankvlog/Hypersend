import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/constants/app_strings.dart';
import '../../core/theme/app_theme.dart';
import '../../data/models/message.dart';
import '../../data/models/chat.dart';
import '../../data/services/service_provider.dart';
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
  List<Message> _messages = [];
  Chat? _chat;
  bool _loading = true;
  String? _error;
  String _meId = '';

  static const List<String> _quickReactions = ['👍', '❤️', '😂', '😮', '😢', '🔥'];

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _messageController.dispose();
    super.dispose();
  }

  void _showEmojiPicker() {
    const emojis = ['😀', '😃', '😄', '😁', '😅', '😂', '🤣', '😊', '😇', '🙂', '🙃', '😉', '😌', '😍', '🥰', '😘', '😗', '😙', '😚', '😋', '😛', '😝', '😜', '🤪', '🤨', '🧐', '🤓', '😎', '🤩', '🥳', '😏', '😒', '😞', '😔', '😟', '😕', '🙁', '☹️', '😣', '😖', '😫', '😩', '🥺', '😢', '😭', '😤', '😠', '😡', '🤬', '🤯', '😳', '🥵', '🥶', '😱', '😨', '😰', '😥', '😓', '🤗', '🤔', '🤭', '🤫', '🤥', '😶', '😐', '😑', '😬', '🙄', '😯', '😴', '🤤', '😪', '😵', '🤐', '🥴', '🤢', '🤮', '🤧', '😷', '🤒', '🤕', '🤑', '🤠', '😈', '👿', '👹', '👺', '🤡', '👻', '💀', '☠️', '👽', '👾', '🤖', '🎃', '😺', '😸', '😹', '😻', '😼', '😽', '🙀', '😿', '😾'];
    
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.backgroundDark,
      builder: (context) => Container(
        padding: const EdgeInsets.all(16),
        height: 250,
        child: GridView.builder(
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 8,
            mainAxisSpacing: 8,
            crossAxisSpacing: 8,
          ),
          itemCount: emojis.length,
          itemBuilder: (context, index) => InkWell(
            onTap: () {
              final text = _messageController.text;
              final selection = _messageController.selection;
              final newText = text.replaceRange(
                selection.start >= 0 ? selection.start : text.length,
                selection.end >= 0 ? selection.end : text.length,
                emojis[index],
              );
              _messageController.text = newText;
              _messageController.selection = TextSelection.collapsed(
                offset: (selection.start >= 0 ? selection.start : text.length) + emojis[index].length,
              );
              Navigator.pop(context);
            },
            child: Center(child: Text(emojis[index], style: const TextStyle(fontSize: 24))),
          ),
        ),
      ),
    );
  }

  Future<void> _pickAndUploadFile() async {
    try {
      final result = await serviceProvider.apiService.pickFile();
      if (result == null) return;

      final bytes = result.files.first.bytes;
      final name = result.files.first.name;
      final size = result.files.first.size;
      final mime = 'application/octet-stream'; // Default or lookup

      if (bytes == null) {
        // Handle path-based pick for non-web if needed
        return;
      }

      // Show progress
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Uploading $name...'), duration: const Duration(seconds: 1)),
      );

      // Resumable upload logic
      final init = await serviceProvider.apiService.initUpload(
        filename: name,
        size: size,
        mime: mime,
        chatId: widget.chatId,
      );

      final uploadId = init['upload_id'];
      
      // Upload in 1MB chunks (simplified for now as one chunk if small, or full bytes)
      await serviceProvider.apiService.uploadChunk(
        uploadId: uploadId,
        chunkIndex: 0,
        bytes: bytes,
      );

      await serviceProvider.apiService.completeUpload(uploadId: uploadId);

      _loadMessages();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Upload failed: $e')),
      );
    }
  }

  void _sendMessage() {
    if (_messageController.text.trim().isEmpty) return;
    _sendMessageApi(_messageController.text.trim());
    _messageController.clear();
  }

  Future<void> _sendMessageApi(String text) async {
    if (!serviceProvider.authService.isLoggedIn) {
      if (!mounted) return;
      context.go('/auth');
      return;
    }

    // Optimistic append
    final me = serviceProvider.authService.accessToken != null ? 'me' : 'me';
    final optimistic = Message(
      id: 'tmp_${DateTime.now().millisecondsSinceEpoch}',
      chatId: widget.chatId,
      senderId: me,
      content: text,
      timestamp: DateTime.now(),
      status: MessageStatus.sent,
      isOwn: true,
      readBy: const [],
    );
    setState(() => _messages.add(optimistic));

    try {
      await serviceProvider.apiService.sendMessage(chatId: widget.chatId, content: text);
      await _loadMessages();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to send: $e')),
      );
    }
  }

  Future<void> _load() async {
    if (!serviceProvider.authService.isLoggedIn) {
      if (!mounted) return;
      context.go('/auth');
      return;
    }
    await _loadMessages();
  }

  Future<void> _loadMessages() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final chatList = await serviceProvider.apiService.getChats();
      final found = chatList.map(Chat.fromApi).where((c) => c.id == widget.chatId).toList();
      final chat = found.isNotEmpty ? found.first : null;
      final res = await serviceProvider.apiService.getChatMessages(widget.chatId);
      final raw = List<Map<String, dynamic>>.from(res['messages'] ?? const []);
      final meId = (await serviceProvider.apiService.getMe())['id']?.toString() ?? '';
      final msgs = raw.map((m) => Message.fromApi(m, currentUserId: meId)).toList();
      if (!mounted) return;
      setState(() {
        _chat = chat;
        _messages = msgs;
        _meId = meId;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  void _togglePin(Message message) {
    if (message.id.startsWith('tmp_')) return;
    final willPin = !message.isPinned;
    setState(() {
      _messages = _messages
          .map((m) => m.id == message.id ? m.copyWith(isPinned: willPin) : m)
          .toList();
    });
    () async {
      try {
        if (willPin) {
          await serviceProvider.apiService.pinMessage(message.id);
        } else {
          await serviceProvider.apiService.unpinMessage(message.id);
        }
        await _loadMessages();
      } catch (e) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Pin failed: $e')));
      }
    }();
  }

  void _toggleReaction(Message message, String emoji) {
    if (message.id.startsWith('tmp_')) return;
    // optimistic toggle
    final current = Map<String, List<String>>.from(message.reactions);
    final users = List<String>.from(current[emoji] ?? const []);
    if (users.contains(_meId)) {
      users.remove(_meId);
    } else {
      users.add(_meId);
    }
    if (users.isEmpty) {
      current.remove(emoji);
    } else {
      current[emoji] = users;
    }
    setState(() {
      _messages = _messages.map((m) => m.id == message.id ? m.copyWith(reactions: current) : m).toList();
    });
    () async {
      try {
        await serviceProvider.apiService.toggleReaction(message.id, emoji);
        await _loadMessages();
      } catch (e) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Reaction failed: $e')));
      }
    }();
  }

  String _getChatSubtitle() {
    switch (_chat?.type) {
      case ChatType.group:
        return 'Group';
      case ChatType.supergroup:
        return 'Supergroup';
      case ChatType.channel:
        return 'Channel';
      case ChatType.secret:
        return 'Secret Chat';
      case ChatType.saved:
        return 'Cloud Storage';
      default:
        return AppStrings.online;
    }
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
    if (message.id.startsWith('tmp_')) return;
    setState(() {
      _messages = _messages
          .map((m) => m.id == message.id ? m.copyWith(content: newText, isEdited: true, editedAt: DateTime.now()) : m)
          .toList();
    });
    try {
      await serviceProvider.apiService.editMessage(message.id, newText);
      await _loadMessages();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Edit failed: $e')));
    }
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
    if (message.id.startsWith('tmp_')) return;
    setState(() {
      _messages = _messages
          .map((m) => m.id == message.id ? m.copyWith(isDeleted: true, deletedAt: DateTime.now(), content: null) : m)
          .toList();
    });
    try {
      await serviceProvider.apiService.deleteMessage(message.id, hardDelete: false);
      await _loadMessages();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Delete failed: $e')));
    }
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
                  child: Center(
                    child: Text(
                      () {
                        final name = (_chat?.name ?? 'Chat').trim();
                        if (name.isEmpty) return 'C';
                        return name.length >= 2
                            ? name.substring(0, 2).toUpperCase()
                            : name.substring(0, 1).toUpperCase();
                      }(),
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
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
                    _chat?.name ?? 'Chat',
                    style: const TextStyle(fontSize: 16),
                  ),
                  Text(
                    _getChatSubtitle(),
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
          if (_chat?.type == ChatType.group || _chat?.type == ChatType.supergroup)
            IconButton(
              icon: const Icon(Icons.info_outline),
              onPressed: () => context.push('/group/${widget.chatId}'),
            ),
          if (_chat?.type == ChatType.channel)
            IconButton(
              icon: const Icon(Icons.analytics_outlined),
              onPressed: () {}, // Channel Info/Stats
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
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                    ? Center(
                        child: Padding(
                          padding: const EdgeInsets.all(24),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Icon(Icons.error_outline, color: AppTheme.errorRed, size: 48),
                              const SizedBox(height: 12),
                              Text('Failed to load messages', style: Theme.of(context).textTheme.titleMedium),
                              const SizedBox(height: 8),
                              Text(_error!, textAlign: TextAlign.center, style: Theme.of(context).textTheme.bodySmall),
                              const SizedBox(height: 16),
                              ElevatedButton(onPressed: _loadMessages, child: const Text('Retry')),
                            ],
                          ),
                        ),
                      )
                    : ListView.builder(
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
                            avatarUrl: null,
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
                  onPressed: _pickAndUploadFile,
                  color: AppTheme.textSecondary,
                ),
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: InputDecoration(
                      hintText: AppStrings.typeMessage,
                      suffixIcon: IconButton(
                        icon: const Icon(Icons.emoji_emotions_outlined),
                        onPressed: () => _showEmojiPicker(),
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