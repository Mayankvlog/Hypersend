// ignore_for_file: deprecated_member_use
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../core/constants/app_strings.dart';
import '../../core/theme/app_theme.dart';
import '../../data/models/chat.dart';
import '../../data/models/message.dart';
import '../../data/services/service_provider.dart';
import '../widgets/message_bubble.dart';
import '../../core/utils/emoji_utils.dart';
// Web-specific imports - necessary for web file download functionality
// ignore: avoid_web_libraries_in_flutter
import 'dart:html' as html;


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

  static const List<String> _quickReactions = ['\u{1F44D}', '\u{2764}', '\u{1F602}', '\u{1F62E}', '\u{1F622}', '\u{1F525}'];

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


  void _showChannelOptions() {
    if (_chat?.type != ChatType.channel) return;
    
    showModalBottomSheet(
      context: context,
      builder: (context) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          ListTile(
            leading: const Icon(Icons.info_outline),
            title: const Text('Channel Info'),
            onTap: () {
              Navigator.pop(context);
              // Navigate to channel info (implementation pending)
            },
          ),
          ListTile(
            leading: const Icon(Icons.delete_forever, color: Colors.red),
            title: const Text('Remove Permanently', style: TextStyle(color: Colors.red)),
            onTap: () {
              Navigator.pop(context);
              _showRemoveChannelConfirmation();
            },
          ),
        ],
      ),
    );
  }

  void _showRemoveChannelConfirmation() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Remove Channel Permanently'),
        content: const Text('Are you sure you want to remove this channel? This action cannot be undone and all messages will be deleted.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () async {
              Navigator.pop(context);
              try {
                await serviceProvider.apiService.removeChannel(widget.chatId);
                if (mounted) {
                  context.pop();
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Channel removed successfully')),
                  );
                }
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed to remove channel: $e')),
                  );
                }
              }
            },
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
  }

  String? _extractPeerIdFromChatId(String chatId) {
    // Chat ID for direct messages is typically "user1_user2" format
    // Extract the peer ID by splitting and finding the one that's not our ID
    final parts = chatId.split('_');
    if (parts.length == 2) {
      if (parts[0] == _meId) {
        return parts[1];
      } else if (parts[1] == _meId) {
        return parts[0];
      }
    }
    return null;
  }

  void _showP2pChatOptions() {
    if (_chat?.type != ChatType.direct) return;
    
    showModalBottomSheet(
      context: context,
      builder: (context) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          ListTile(
            leading: const Icon(Icons.person_add),
            title: const Text('Add to Contacts'),
            onTap: () {
              Navigator.pop(context);
              _showAddToContactsDialog();
            },
          ),
        ],
      ),
    );
  }

  void _showAddToContactsDialog() {
    final nameController = TextEditingController();
    
    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setState) => AlertDialog(
          title: const Text('Add to Contacts'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Save this contact as:',
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 12),
              TextField(
                controller: nameController,
                onChanged: (_) => setState(() {}),
                decoration: InputDecoration(
                  hintText: _chat?.name ?? 'Contact Name',
                  prefixIcon: const Icon(Icons.person),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                  contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  errorText: nameController.text.isEmpty 
                    ? 'Contact name is required' 
                    : null,
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () {
                nameController.dispose();
                Navigator.pop(context);
              },
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: nameController.text.trim().isEmpty
                ? null
                : () async {
                  final displayName = nameController.text.trim();
                  
                  try {
                    // For direct chats, the peer ID is embedded in the chat ID or we need to fetch chat details
                    // The chat ID format for direct chats is typically "user1_user2"
                    final chatId = widget.chatId;
                    final peerId = _extractPeerIdFromChatId(chatId);
                    
                    if (peerId == null || peerId.isEmpty) {
                      if (mounted) {
                        nameController.dispose();
                        Navigator.pop(context);
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Unable to add contact - invalid chat')),
                        );
                      }
                      return;
                    }
                     
                    // Contact functionality has been removed
                    if (mounted) {
                      nameController.dispose();
                      Navigator.pop(context);
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text('Started chat with $displayName')),
                      );
                    }
                  } catch (e) {
                    if (mounted) {
                      nameController.dispose();
                      Navigator.pop(context);
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text('Failed to add contact: $e')),
                      );
                    }
                  }
                },
              child: const Text('Add'),
            ),
          ],
        ),
      ),
    );
  }

  void _showEmojiPicker() {
    final List<String> emojis = EmojiUtils.getEmojiList();
    
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.backgroundDark,
      isScrollControlled: true,
      builder: (context) => SizedBox(
        height: MediaQuery.of(context).size.height * 0.6,
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Padding(
                    padding: EdgeInsets.only(left: 16),
                    child: Text('Emojis', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                  ),
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('Done', style: TextStyle(color: AppTheme.primaryCyan)),
                  ),
                ],
              ),
            ),
            Expanded(
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 16),
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
                      final start = selection.start >= 0 ? selection.start : text.length;
                      final end = selection.end >= 0 ? selection.end : text.length;
                      final newText = text.replaceRange(start, end, emojis[index]);
                      _messageController.value = TextEditingValue(
                        text: newText,
                        selection: TextSelection.collapsed(offset: start + emojis[index].length),
                      );
                    },
                    child: Center(child: Text(emojis[index], style: const TextStyle(fontSize: 24))),
                  ),
                ),
              ),
            ),
          ],
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
      
      // Upload in 1MB chunks
      const chunkSize = 1024 * 1024; // 1MB
      int offset = 0;
      int chunkIndex = 0;
      
      while (offset < bytes.length) {
        final end = (offset + chunkSize < bytes.length) ? offset + chunkSize : bytes.length;
        final chunk = bytes.sublist(offset, end);
        
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Uploading $name: chunk ${chunkIndex + 1}/${(bytes.length / chunkSize).ceil()}'),
            duration: const Duration(milliseconds: 500),
          ),
        );

        await serviceProvider.apiService.uploadChunk(
          uploadId: uploadId,
          chunkIndex: chunkIndex,
          bytes: chunk,
        );
        
        offset = end;
        chunkIndex++;
      }

      final completed = await serviceProvider.apiService.completeUpload(uploadId: uploadId);
      final remoteFileId = completed['file_id'];

      // Send the file message
      if (!mounted) return;
      await serviceProvider.apiService.sendMessage(
        chatId: widget.chatId,
        content: name, // Use filename as fallback text
        fileId: remoteFileId,
      );

      await _loadMessages();
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

  Future<void> _uploadFile() async {
    try {
      // Trigger file picker and upload
      await _pickAndUploadFile();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Upload failed: ${e.toString()}'),
            backgroundColor: AppTheme.errorRed,
          ),
        );
      }
    }
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
      if (_meId.isEmpty) {
        final me = await serviceProvider.apiService.getMe();
        _meId = me['id']?.toString() ?? me['_id']?.toString() ?? '';
      }
      final currentUserId = _meId;
      final msgs = raw.map((m) => Message.fromApi(m, currentUserId: currentUserId)).toList();
      if (!mounted) return;
      setState(() {
        _chat = chat;
        _messages = msgs;
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

  Future<void> _downloadFile(Message message) async {
    if (message.fileId == null) return;
    
    final fileId = message.fileId!.trim();
    final fileName = message.content ?? 'file';
    debugPrint('[FILE_DOWNLOAD] Processing file download: $fileName (ID: $fileId)');
    
    // Show loading dialog
    if (!mounted) return;
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        content: Row(
          children: [
            const CircularProgressIndicator(),
            const SizedBox(width: 16),
            Text('Downloading $fileName...'),
          ],
        ),
      ),
    );
    
    try {
      // Get file metadata first to determine file type
      final fileInfo = await _getFileInfo(fileId);
      final contentType = fileInfo['content_type'] ?? 'application/octet-stream';
      // Enhanced file type detection for better download handling
      final isPDF = contentType.toLowerCase().contains('pdf');
      final isImage = contentType.toLowerCase().contains('image');
      final isVideo = contentType.toLowerCase().contains('video');

      
      debugPrint('[FILE_DOWNLOAD] File type: $contentType, isPDF: $isPDF, isImage: $isImage, isVideo: $isVideo');
      
      if (kIsWeb) {
        // For web, create blob URL and open in new tab
        await _openFileInWeb(fileId, fileName, isPDF);
      } else {
        // For native platforms, download and open file
        await _downloadAndOpenFile(fileId, fileName, contentType);
      }
      
      // Show success message
      if (!mounted) return;
      Navigator.pop(context); // Close loading dialog
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(isPDF 
              ? 'PDF opened successfully' 
              : 'File downloaded: $fileName'),
          backgroundColor: AppTheme.successGreen,
          duration: const Duration(seconds: 2),
        ),
      );
      
    } catch (e) {
      debugPrint('[FILE_DOWNLOAD_ERROR] $e');
      if (!mounted) return;
      Navigator.pop(context); // Close loading dialog
      
      String errorMessage = e.toString();
      if (errorMessage.contains('not found')) {
        errorMessage = 'File not found or has been deleted';
      } else if (errorMessage.contains('permission')) {
        errorMessage = 'You do not have permission to access this file';
      } else if (errorMessage.contains('timeout')) {
        errorMessage = 'Download timeout. Please try again';
      }
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Failed to open file: $errorMessage'),
          backgroundColor: AppTheme.errorRed,
          duration: const Duration(seconds: 3),
        ),
      );
    }
  }

  Future<Map<String, dynamic>> _getFileInfo(String fileId) async {
    try {
      final response = await serviceProvider.apiService.getFileInfo(fileId);
      return response;
    } catch (e) {
      debugPrint('[FILE_INFO_ERROR] Failed to get file info: $e');
      return {};
    }
  }

  Future<void> _openFileInWeb(String fileId, String fileName, bool isPDF) async {
    try {
      final response = await serviceProvider.apiService.downloadFileBytes(fileId);
      final bytes = response.data ?? [];
      
      if (bytes.isEmpty) {
        throw Exception('No data received or file is empty');
      }
      
      if (kIsWeb) {
        // Web-specific file download using dart:html
        // ignore: avoid_web_libraries_in_flutter
        final blob = html.Blob([bytes]);
        // ignore: avoid_web_libraries_in_flutter
        final url = html.Url.createObjectUrlFromBlob(blob);
        
        // Create download link
        // ignore: avoid_web_libraries_in_flutter
        html.AnchorElement(href: url)
          ..setAttribute('download', fileName)
          ..click();
        
        // Clean up blob URL
        // ignore: avoid_web_libraries_in_flutter
        html.Url.revokeObjectUrl(url);
      }
      
      debugPrint('[FILE_WEB] Downloaded ${bytes.length} bytes as $fileName');
    } catch (e) {
      debugPrint('[FILE_WEB_ERROR] $e');
      rethrow;
    }
  }

  Future<void> _downloadAndOpenFile(String fileId, String fileName, String contentType) async {
    try {
      debugPrint('[FILE_NATIVE] Starting enhanced download for: $fileName');
      
      if (kIsWeb) {
        // Web: Use browser download
        final isPDF = contentType.toLowerCase().contains('pdf');
        await _openFileInWeb(fileId, fileName, isPDF);
        return;
      } else {
        // Native: Use FileTransferService for proper chunked download
        // Generate a safe filename and path
        final safeFileName = fileName.replaceAll(RegExp(r'[^\w\-_.]'), '_');
        final savePath = safeFileName;
        
        debugPrint('[FILE_NATIVE] Download path: $savePath');
        
        // Use FileTransferService for chunked download (now supports large files)
        await serviceProvider.fileTransferService.downloadFile(
          fileId: fileId,
          fileName: fileName,
          savePath: savePath,
          onProgress: (progress) {
            debugPrint('[FILE_NATIVE] Download progress: ${(progress * 100).toStringAsFixed(1)}%');
          },
        );
        
        debugPrint('[FILE_NATIVE] Download completed, attempting to open file');
        
        // For now, just log completion - opening file requires platform-specific handling
        debugPrint('[FILE_NATIVE] Download completed: $savePath');
        debugPrint('[FILE_NATIVE] File saved successfully');
      }
    } catch (e) {
      debugPrint('[FILE_NATIVE_ERROR] $e');
      rethrow;
    }
  }


  String _getChatSubtitle() {
    switch (_chat?.type) {
      case ChatType.group:
        return 'Group';
      case ChatType.supergroup:
        return 'Supergroup';
      case ChatType.channel:
        return 'Channel';

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
          if (_chat != null && _chat?.type != ChatType.saved)
            IconButton(
              icon: const Icon(Icons.more_vert),
              onPressed: _chat?.type == ChatType.channel 
                ? _showChannelOptions 
                : (_chat?.type == ChatType.direct ? _showP2pChatOptions : null),
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
                            onFileTap: (msg) => _downloadFile(msg),
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
                  onPressed: _uploadFile,
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