// ignore_for_file: deprecated_member_use
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:go_router/go_router.dart';
import 'package:path_provider/path_provider.dart';

import 'package:url_launcher/url_launcher.dart';
import 'package:path/path.dart' as path;

// Platform-specific imports: dart:io is conditionally imported only for non-web platforms
// import 'dart:io' if (dart.library.html) 'dart:html'; // Removed to avoid VoidCallback conflict

// Conditional imports for platform-specific implementations
import 'chat_io.dart' if (dart.library.html) 'chat_io_stub.dart' as io;

import '../../core/constants/app_strings.dart';
import '../../core/constants/api_constants.dart';
import '../../core/theme/app_theme.dart';
import '../../data/models/chat.dart';
import '../../data/models/message.dart';
import '../../data/services/service_provider.dart';
import '../../data/services/websocket_service.dart';
import '../widgets/message_bubble.dart';
import '../../core/utils/time_formatter.dart';
import '../../core/utils/emoji_utils.dart';


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
  
  // Precomputed list items for lazy loading
  late List<dynamic> _listItems;
  
  // CRITICAL: Persistent WebSocket connection (initialized once)
  WebSocketService? _webSocketService;
  bool _wsConnected = false;
  
  // Camera functionality removed - only Photos/Videos option available

  static const List<String> _quickReactions = ['\u{1F44D}', '\u{2764}', '\u{1F602}', '\u{1F62E}', '\u{1F622}', '\u{1F525}'];

  @override
  void initState() {
    super.initState();
    _listItems = <dynamic>[]; // Initialize empty list items
    _load();
  }

  @override
  void dispose() {
    _messageController.dispose();
    // Close WebSocket connection
    if (_webSocketService != null) {
      _webSocketService!.disconnect();
      _webSocketService = null;
    }
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

  void _showGroupOptions() {
    if (_chat?.type != ChatType.group && _chat?.type != ChatType.supergroup) return;
    
    showModalBottomSheet(
      context: context,
      builder: (context) => FutureBuilder<Map<String, dynamic>>(
        future: _getGroupMuteStatus(),
        builder: (context, snapshot) {
          final isMuted = snapshot.data?['isMuted'] ?? false;
          
          return Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(Icons.info_outline),
                title: const Text('Group Info'),
                onTap: () {
                  Navigator.pop(context);
                  context.push('/group/${widget.chatId}');
                },
              ),
              ListTile(
                leading: Icon(isMuted ? Icons.notifications : Icons.notifications_off_outlined),
                title: Text(isMuted ? 'Unmute Notifications' : 'Mute Notifications'),
                onTap: () {
                  Navigator.pop(context);
                  _toggleMuteNotifications();
                },
              ),
              ListTile(
                leading: const Icon(Icons.exit_to_app, color: Colors.red),
                title: const Text('Leave Group', style: TextStyle(color: Colors.red)),
                onTap: () {
                  Navigator.pop(context);
                  _showLeaveGroupConfirmation();
                },
              ),
            ],
          );
        },
      ),
    );
  }

  Future<Map<String, dynamic>> _getGroupMuteStatus() async {
    try {
      final groupRes = await serviceProvider.apiService.getGroup(widget.chatId);
      final group = groupRes['group'] as Map<String, dynamic>?;
      if (group == null) return {'isMuted': false};
      
      final me = await serviceProvider.apiService.getMe();
      final meId = me['id']?.toString() ?? '';
      final mutedBy = List<String>.from(group['muted_by'] ?? []);
      final isMuted = mutedBy.contains(meId);
      
      return {'isMuted': isMuted};
    } catch (e) {
      return {'isMuted': false};
    }
  }

  Future<void> _toggleMuteNotifications() async {
    try {
      // Get current group info to check mute status
      final groupRes = await serviceProvider.apiService.getGroup(widget.chatId);
      final group = groupRes['group'] as Map<String, dynamic>?;
      if (group == null) {
        throw Exception('Group not found');
      }
      
      final me = await serviceProvider.apiService.getMe();
      final meId = me['id']?.toString() ?? '';
      final mutedBy = List<String>.from(group['muted_by'] ?? []);
      final isCurrentlyMuted = mutedBy.contains(meId);
      
      // Show loading feedback
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(isCurrentlyMuted ? 'Unmuting notifications...' : 'Muting notifications...'),
            duration: const Duration(milliseconds: 500),
          ),
        );
      }
      
      // Toggle mute status
      await serviceProvider.apiService.muteGroup(widget.chatId, mute: !isCurrentlyMuted);
      
      if (mounted) {
        // Refresh the chat data to update the UI state
        await _loadMessages();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(isCurrentlyMuted ? 'Notifications unmuted' : 'Notifications muted'),
            backgroundColor: isCurrentlyMuted ? Colors.green : Colors.orange,
            duration: const Duration(seconds: 2),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to toggle notifications: ${e.toString().replaceAll('Exception: ', '')}'),
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 3),
          ),
        );
      }
    }
  }

  Future<void> _showLeaveGroupConfirmation() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Leave Group?'),
        content: const Text('Are you sure you want to leave this group? This action cannot be undone.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Leave', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
    
    if (confirmed == true) {
      try {
        if (mounted) {
          showDialog(
            context: context,
            barrierDismissible: false,
            builder: (context) => const AlertDialog(
              content: Row(
                children: [
                  SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)),
                  SizedBox(width: 16),
                  Text('Leaving group...'),
                ],
              ),
            ),
          );
        }
        
        await serviceProvider.apiService.leaveGroup(widget.chatId);
        
        if (mounted) {
          Navigator.of(context).pop();
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Left group successfully'),
              backgroundColor: Colors.green,
              duration: Duration(seconds: 2),
            ),
          );
          context.go('/chats');
        }
      } catch (e) {
        if (mounted) {
          Navigator.of(context).pop();
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to leave group: $e'),
              backgroundColor: Colors.red,
              duration: const Duration(seconds: 3),
            ),
          );
        }
      }
    }
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
    int selectedCategoryIndex = 0;
    final TextEditingController searchController = TextEditingController();
    final List<String> searchSuggestions = [
      'smileys & emotions', 'animal', 'food', 'sport', 'travel',
      'flags','activities' , 'objects' 
    ];
    
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.backgroundDark,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.only(
          topLeft: Radius.circular(16),
          topRight: Radius.circular(16),
        ),
      ),
      builder: (context) => StatefulBuilder(
        builder: (context, setState) {
          final categories = EmojiUtils.categories;
          final searchQuery = searchController.text.trim();
          final List<String> displayedEmojis = searchQuery.isEmpty
              ? categories[selectedCategoryIndex].emojis
              : EmojiUtils.searchEmojis(searchQuery);
          
          return SizedBox(
            height: MediaQuery.of(context).size.height * 0.75,
            child: Column(
              children: [
                // Header with close button
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  decoration: BoxDecoration(
                    border: Border(
                      bottom: BorderSide(
                        color: AppTheme.dividerColor,
                        width: 1,
                      ),
                    ),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'Emojis',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                      GestureDetector(
                        onTap: () => Navigator.pop(context),
                        child: Container(
                          padding: const EdgeInsets.all(4),
                          child: const Icon(Icons.close, size: 24),
                        ),
                      ),
                    ],
                  ),
                ),
                
                // Search bar - WhatsApp style
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
                  child: TextField(
                    controller: searchController,
                    onChanged: (_) => setState(() {}),
                    textAlignVertical: TextAlignVertical.center,
                    decoration: InputDecoration(
                      hintText: 'Search emojis',
                      hintStyle: TextStyle(
                        color: AppTheme.textSecondary.withValues(alpha: 0.5),
                        fontSize: 14,
                      ),
                      prefixIcon: const Padding(
                        padding: EdgeInsets.only(left: 8),
                        child: Icon(
                          Icons.search,
                          size: 20,
                          color: AppTheme.primaryCyan,
                        ),
                      ),
                      prefixIconConstraints: const BoxConstraints(minWidth: 32),
                      suffixIcon: searchController.text.isNotEmpty
                          ? GestureDetector(
                              onTap: () {
                                searchController.clear();
                                setState(() {});
                              },
                              child: Container(
                                padding: const EdgeInsets.all(8),
                                child: const Icon(
                                  Icons.cancel,
                                  size: 18,
                                  color: AppTheme.textSecondary,
                                ),
                              ),
                            )
                          : null,
                      isDense: true,
                      contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                      filled: true,
                      fillColor: AppTheme.dividerColor.withValues(alpha: 0.3),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(20),
                        borderSide: BorderSide.none,
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(20),
                        borderSide: BorderSide.none,
                      ),
                      focusedBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(20),
                        borderSide: const BorderSide(
                          color: AppTheme.primaryCyan,
                          width: 1,
                        ),
                      ),
                    ),
                    style: const TextStyle(fontSize: 14),
                  ),
                ),
                
                // Quick search suggestions
                if (searchQuery.isEmpty)
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Quick search:',
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                color: AppTheme.textSecondary.withValues(alpha: 0.6),
                                fontSize: 11,
                                fontWeight: FontWeight.w500,
                              ),
                        ),
                        const SizedBox(height: 6),
                        Wrap(
                          spacing: 6,
                          runSpacing: 6,
                          children: searchSuggestions.map((suggestion) {
                            return GestureDetector(
                              onTap: () {
                                searchController.text = suggestion;
                                setState(() {});
                              },
                              child: Container(
                                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                                decoration: BoxDecoration(
                                  color: AppTheme.dividerColor.withValues(alpha: 0.4),
                                  borderRadius: BorderRadius.circular(16),
                                  border: Border.all(
                                    color: AppTheme.primaryCyan.withValues(alpha: 0.3),
                                    width: 0.5,
                                  ),
                                ),
                                child: Text(
                                  suggestion,
                                  style: const TextStyle(
                                    fontSize: 12,
                                    color: AppTheme.primaryCyan,
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                              ),
                            );
                          }).toList(),
                        ),
                      ],
                    ),
                  ),
                
                // Search result count
                if (searchQuery.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                    child: Row(
                      children: [
                        Text(
                          '${displayedEmojis.length} result${displayedEmojis.length == 1 ? '' : 's'}',
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                color: AppTheme.textSecondary,
                                fontSize: 12,
                              ),
                        ),
                      ],
                    ),
                  ),
                
                // Category tabs (visible only when not searching)
                if (searchQuery.isEmpty)
                  SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: Row(
                      children: List.generate(categories.length, (index) {
                        final isSelected = index == selectedCategoryIndex;
                        return Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                          child: GestureDetector(
                            onTap: () => setState(() => selectedCategoryIndex = index),
                            child: Container(
                              width: 44,
                              height: 44,
                              decoration: BoxDecoration(
                                shape: BoxShape.circle,
                                color: isSelected
                                    ? AppTheme.primaryCyan.withValues(alpha: 0.2)
                                    : AppTheme.dividerColor.withValues(alpha: 0.2),
                                border: isSelected
                                    ? Border.all(
                                        color: AppTheme.primaryCyan,
                                        width: 2,
                                      )
                                    : null,
                              ),
                              child: Center(
                                child: Text(
                                  categories[index].icon,
                                  style: const TextStyle(fontSize: 22),
                                ),
                              ),
                            ),
                          ),
                        );
                      }),
                    ),
                  ),
                
                // Emoji grid
                Expanded(
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                    child: displayedEmojis.isEmpty
                        ? Center(
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                const Icon(
                                  Icons.emoji_emotions_outlined,
                                  size: 56,
                                  color: AppTheme.textSecondary,
                                ),
                                const SizedBox(height: 16),
                                Text(
                                  'No results found',
                                  style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                                        color: AppTheme.textSecondary,
                                        fontWeight: FontWeight.w600,
                                      ),
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  'Try: smile, love, animal, food',
                                  textAlign: TextAlign.center,
                                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                        color: AppTheme.textSecondary.withValues(alpha: 0.6),
                                        fontSize: 13,
                                      ),
                                ),
                              ],
                            ),
                          )
                        : GridView.builder(
                            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                              crossAxisCount: 7,
                              mainAxisSpacing: 12,
                              crossAxisSpacing: 12,
                            ),
                            padding: const EdgeInsets.symmetric(horizontal: 8),
                            itemCount: displayedEmojis.length,
                            itemBuilder: (context, index) {
                              final emoji = displayedEmojis[index];
                              return GestureDetector(
                                onTap: () {
                                  final text = _messageController.text;
                                  final selection = _messageController.selection;
                                  final start = selection.start >= 0 ? selection.start : text.length;
                                  final end = selection.end >= 0 ? selection.end : text.length;
                                  final newText = text.replaceRange(start, end, emoji);
                                  _messageController.value = TextEditingValue(
                                    text: newText,
                                    selection: TextSelection.collapsed(offset: start + emoji.length),
                                  );
                                  Navigator.pop(context);
                                },
                                child: Container(
                                  decoration: BoxDecoration(
                                    borderRadius: BorderRadius.circular(8),
                                    color: Colors.transparent,
                                  ),
                                  child: Center(
                                    child: Text(
                                      emoji,
                                      style: const TextStyle(fontSize: 32),
                                    ),
                                  ),
                                ),
                              );
                            },
                          ),
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  Future<void> _uploadFile() async {
    _showAttachmentMenu();
  }

  void _showAttachmentMenu() {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.backgroundDark,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) => SafeArea(
        child: Container(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Title
              const Text(
                'Select attachment',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
              ),
              const SizedBox(height: 24),
              
              // First row: Photos/Videos, Documents
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  const SizedBox(width: 40), // Spacer for alignment
                  _buildAttachmentButton(
                    icon: Icons.image,
                    label: 'Photos/Videos',
                    color: Colors.green,
                    onTap: () {
                      Navigator.pop(context);
                      _uploadFromMediaPicker('photo_video');
                    },
                  ),
                  _buildAttachmentButton(
                    icon: Icons.description,
                    label: 'Documents',
                    color: Colors.orange,
                    onTap: () {
                      Navigator.pop(context);
                      _uploadFromMediaPicker('document');
                    },
                  ),
                  const SizedBox(width: 40), // Spacer for alignment
                ],
              ),
              const SizedBox(height: 24),
              
              // Second row: Audio, Files
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  const SizedBox(width: 40), // Spacer for alignment
                  _buildAttachmentButton(
                    icon: Icons.mic,
                    label: 'Audio',
                    color: Colors.purple,
                    onTap: () {
                      Navigator.pop(context);
                      _uploadFromMediaPicker('audio');
                    },
                  ),
                  _buildAttachmentButton(
                    icon: Icons.folder,
                    label: 'Files',
                    color: Colors.red,
                    onTap: () {
                      Navigator.pop(context);
                      _uploadFromMediaPicker('file');
                    },
                  ),
                  const SizedBox(width: 40), // Spacer for alignment
                ],
              ),
              const SizedBox(height: 12),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildAttachmentButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
  }) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(16),
          child: Container(
            width: 80,
            height: 80,
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.2),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: color.withValues(alpha: 0.5), width: 2),
            ),
            child: Icon(icon, color: color, size: 32),
          ),
        ),
        const SizedBox(height: 8),
        SizedBox(
          width: 80,
          child: Text(
            label,
            textAlign: TextAlign.center,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
          ),
        ),
      ],
    );
  }



  Future<void> _uploadFromMediaPicker(String attachmentType) async {
    try {
      final result = await serviceProvider.apiService.pickFile();
      if (result == null) return;

      final bytes = result.files.first.bytes;
      final name = result.files.first.name;
      final size = result.files.first.size;
      
      // Determine MIME type safely without filesystem operations
      String mime = 'application/octet-stream';
      if (name.toLowerCase().endsWith('.jpg') || name.toLowerCase().endsWith('.jpeg')) {
        mime = 'image/jpeg';
      } else if (name.toLowerCase().endsWith('.png')) {
        mime = 'image/png';
      } else if (name.toLowerCase().endsWith('.gif')) {
        mime = 'image/gif';
      } else if (name.toLowerCase().endsWith('.mp4')) {
        mime = 'video/mp4';
      } else if (name.toLowerCase().endsWith('.pdf')) {
        mime = 'application/pdf';
      } else if (name.toLowerCase().endsWith('.txt')) {
        mime = 'text/plain';
      }

      if (bytes == null) return;

      // Show initial upload notification
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Uploading $name...'), duration: const Duration(seconds: 1)),
      );

      // Initialize upload with attachment endpoint
      final initEndpoint = _getAttachmentInitEndpoint(attachmentType);
      final init = await serviceProvider.apiService.initUpload(
        filename: name,
        size: size,
        mime: mime,
        chatId: widget.chatId,
        endpoint: initEndpoint, // Use specific attachment endpoint
      );

      final uploadId = init['uploadId'] ?? init['upload_id'];
      final chunkSize = (init['chunk_size'] as num).toInt();
      int offset = 0;
      int chunkIndex = 0;
      final totalChunks = (bytes.length / chunkSize).ceil();

      // Upload chunks with progress tracking
      while (offset < bytes.length) {
        final end = (offset + chunkSize < bytes.length) ? offset + chunkSize : bytes.length;
        final chunk = bytes.sublist(offset, end);

        if (!mounted) return;
        final progressPercent = ((chunkIndex + 1) / totalChunks * 100).toStringAsFixed(1);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Uploading $name: $progressPercent%'),
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

      // Complete upload
      final completed = await serviceProvider.apiService.completeUpload(uploadId: uploadId);
      final remoteFileId = completed['file_id'];
      
      // DEBUG: Print both IDs to verify the fix
      debugPrint('🔍 FILE ID DEBUG:');
      debugPrint('UPLOAD ID: $uploadId');
      debugPrint('FILE ID: $remoteFileId');
      debugPrint('IDs are different: ${uploadId != remoteFileId}');

      // Send the attachment message
      if (!mounted) return;
      await serviceProvider.apiService.sendMessage(
        chatId: widget.chatId,
        content: name,
        fileId: remoteFileId,
      );

      // Reload messages to show the new attachment
      await _loadMessages();

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('$name sent successfully'),
            backgroundColor: AppTheme.successGreen,
            duration: const Duration(seconds: 2),
          ),
        );
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Upload failed: ${e.toString()}'),
          backgroundColor: AppTheme.errorRed,
        ),
      );
    }
  }

  String _getAttachmentInitEndpoint(String attachmentType) {
    switch (attachmentType) {
      case 'photo_video':
        return 'attach/photos-videos/init';
      case 'document':
        return 'attach/documents/init';
      case 'audio':
        return 'attach/audio/init';
      case 'file':
        return 'attach/files/init';
      default:
        return 'files/init';
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
    
    // First load messages via HTTP
    await _loadMessages();
    
    // Then establish persistent WebSocket connection (one-time initialization)
    if (!_wsConnected && _meId.isNotEmpty) {
      await _initializeWebSocket();
    }
  }
  
  /// Initialize persistent WebSocket connection for real-time message delivery
  /// CRITICAL: This runs ONCE per chat - no re-initialization on re-render
  Future<void> _initializeWebSocket() async {
    if (_wsConnected || _webSocketService != null) {
      return; // Already initialized
    }
    
    try {
      // Create WebSocket service instance
      _webSocketService = WebSocketService();
      
      // Connect to production domain with token authentication
      await _webSocketService!.connect(widget.chatId);
      _wsConnected = true;
      
      debugPrint('[WEBSOCKET] ✅ Persistent WebSocket connection established for chat ${widget.chatId}');
      debugPrint('[WEBSOCKET] 🌐 Connected to production domain: wss://zaply.in.net');
    } catch (e) {
      // WebSocket connection failed - log error
      debugPrint('[WEBSOCKET] ❌ Connection failed for chat ${widget.chatId}: $e');
      _wsConnected = false;
      _webSocketService = null;
    }
  }
  
  /// Handle real-time message from WebSocket
  void _handleWebSocketMessage(Map<String, dynamic> data) {
    final messageType = data['type'] as String?;
    
    if (messageType == 'new_message') {
      // CRITICAL: Keep timestamp as UTC from backend
      // Frontend UI layer (Intl.DateTimeFormat) handles timezone display ONLY
      final msg = Message.fromApi(data, currentUserId: _meId);
      
      if (mounted) {
        setState(() {
          // Add only if not already present (deduplication by message_id)
          if (!_messages.any((m) => m.id == msg.id)) {
            _messages.add(msg);
            // Refresh derived _listItems to include new message
            _precomputeListItems();
          }
        });
      }
    } else if (messageType == 'message_state_update') {
      // Handle delivery/read receipts
      final messageId = data['message_id'] as String?;
      final state = data['state'] as String?; // 'delivered' or 'read'
      
      if (messageId != null && state != null && mounted) {
        setState(() {
          _messages = _messages.map((m) {
            if (m.id == messageId) {
              return m.copyWith(status: state == 'read' ? MessageStatus.read : MessageStatus.delivered);
            }
            return m;
          }).toList();
          // Refresh derived _listItems to reflect message status updates
          _precomputeListItems();
        });
      }
    } else if (messageType == 'typing') {
      // Handle typing indicator (show UI indicator if needed)
      // This is optional - not required for basic functionality
    }
  }
  
  /// Handle WebSocket errors
  void _handleWebSocketError(String error) {
    debugPrint('[WEBSOCKET_ERROR] Connection error for chat ${widget.chatId}: $error');
    _wsConnected = false;
    // Do not attempt auto-reconnect - connection is persistent per chat
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
      
      // CRITICAL: Message.fromApi already converts UTC→local timezone
      // DO NOT do double conversion here
      final msgs = raw.map((m) => Message.fromApi(m, currentUserId: currentUserId)).toList();
      
      if (!mounted) return;
      setState(() {
        _chat = chat;
        _messages = msgs;
        _loading = false;
      });
      // Precompute list items for lazy loading after messages are loaded
      _precomputeListItems();
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
    
    // Get file metadata first to determine file type
    final fileInfo = await _getFileInfo(fileId);

    // Prefer backend-reported content type, but fall back to filename-based guess
    String contentType;
    final dynamic rawContentType = fileInfo['content_type'];
    if (rawContentType is String && rawContentType.trim().isNotEmpty) {
      contentType = rawContentType;
    } else {
      contentType = _guessMimeTypeFromName(fileName);
      debugPrint('[FILE_DOWNLOAD] Falling back to extension-based MIME: $contentType');
    }

    // Enhanced file type detection for better download handling
    final isPDF = contentType.toLowerCase().contains('pdf');
    final isImage = contentType.toLowerCase().contains('image');
    final isVideo = contentType.toLowerCase().contains('video');

    debugPrint('[FILE_DOWNLOAD] File type: $contentType, isPDF: $isPDF, isImage: $isImage, isVideo: $isVideo');
    
    // For images, show preview option first
    if (isImage) {
      await _showImageOptions(message, fileId, fileName, contentType);
      return;
    }
    
    // For non-image files, proceed with normal download
    await _proceedWithDownload(fileId, fileName, contentType, isPDF, message);
  }

  Future<void> _showImageOptions(Message message, String fileId, String fileName, String contentType) async {
    if (!mounted) return;
    
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Image Options'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 250,
              height: 180,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(8),
                color: Colors.black.withValues(alpha: 0.1),
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(8),
                child: _buildPresignedImagePreview(fileId, fileName),
              ),
            ),
            const SizedBox(height: 16),
            Text(
              fileName,
              style: const TextStyle(fontWeight: FontWeight.w500),
              textAlign: TextAlign.center,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              Navigator.of(context).pop();
              _proceedWithDownload(fileId, fileName, contentType, false, message);
            },
            child: const Text('Download'),
          ),
          if (!kIsWeb)
            TextButton(
              onPressed: () {
                Navigator.of(context).pop();
                _openImageExternally(fileId, fileName);
              },
              child: const Text('Open in Viewer'),
            ),
        ],
      ),
    );
  }

  Widget _buildPresignedImagePreview(String fileId, String fileName) {
    return FutureBuilder<String?>(
      future: serviceProvider.apiService.getPresignedDownloadUrl(fileId),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return Container(
            width: 250,
            height: 180,
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
        }

        if (snapshot.hasError || !snapshot.hasData || snapshot.data == null) {
          debugPrint('[IMAGE_PREVIEW] Error getting presigned URL: ${snapshot.error}');
          return Container(
            width: 250,
            height: 180,
            decoration: BoxDecoration(
              color: Colors.red.withValues(alpha: 0.2),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.broken_image, color: Colors.red, size: 32),
                SizedBox(height: 8),
                Text('Preview not available'),
              ],
            ),
          );
        }

        final presignedUrl = snapshot.data!;
        return Image.network(
          presignedUrl,
          width: 250,
          height: 180,
          fit: BoxFit.cover,
          errorBuilder: (context, error, stackTrace) {
            debugPrint('[IMAGE_PREVIEW] Error loading image from presigned URL: $error');
            return Container(
              width: 250,
              height: 180,
              decoration: BoxDecoration(
                color: Colors.red.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.broken_image, color: Colors.red, size: 32),
                  SizedBox(height: 8),
                  Text('Preview not available'),
                ],
              ),
            );
          },
          loadingBuilder: (context, child, loadingProgress) {
            if (loadingProgress == null) return child;
            return Container(
              width: 250,
              height: 180,
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
      },
    );
  }

  Widget _buildAuthenticatedImagePreview(String imageUrl, String fileName) {
    final serviceProvider = ServiceProvider();
    final accessToken = serviceProvider.authService.accessToken;
    
    // Build headers for authenticated image request
    Map<String, String> headers = {'Cache-Control': 'no-cache'};
    if (accessToken != null && accessToken.isNotEmpty) {
      headers['Authorization'] = 'Bearer $accessToken';
    }

    return Image.network(
      imageUrl,
      width: 250,
      height: 180,
      fit: BoxFit.cover,
      headers: headers,
      errorBuilder: (context, error, stackTrace) {
        debugPrint('[IMAGE_PREVIEW] Error loading image: $error');
        return Container(
          width: 250,
          height: 180,
          decoration: BoxDecoration(
            color: Colors.red.withValues(alpha: 0.2),
            borderRadius: BorderRadius.circular(8),
          ),
          child: const Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.broken_image, color: Colors.red, size: 32),
              SizedBox(height: 8),
              Text('Preview not available'),
            ],
          ),
        );
      },
      loadingBuilder: (context, child, loadingProgress) {
        if (loadingProgress == null) return child;
        return Container(
          width: 250,
          height: 180,
          decoration: BoxDecoration(
            color: Colors.white.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(8),
          ),
          child: const Center(
            child: CircularProgressIndicator(),
          ),
        );
      },
    );
  }

  Future<void> _openImageExternally(String imageUrl, String fileName) async {
    try {
      debugPrint('[IMAGE_VIEWER] Opening image externally: $imageUrl');
      
      if (io.Platform.isWindows) {
        await io.Process.run('start', [imageUrl], runInShell: true);
      } else if (io.Platform.isMacOS) {
        await io.Process.run('open', [imageUrl]);
      } else if (io.Platform.isLinux) {
        await io.Process.run('xdg-open', [imageUrl]);
      }
      
      debugPrint('[IMAGE_VIEWER] Successfully opened image in external viewer');
    } catch (e) {
      debugPrint('[IMAGE_VIEWER] Error opening image: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to open image: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<void> _proceedWithDownload(String fileId, String fileName, String contentType, bool isPDF, [Message? message]) async {
    // Show loading dialog without spinner
    if (!mounted) return;
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        content: Text('Downloading $fileName...'),
      ),
    );
    
    try {      
      if (kIsWeb) {
        // For web, trigger a real download (Content-Disposition: attachment)
        // Prefer the secure media endpoint (/api/v1/media/{file_key}) when available.
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
      
      // Enhanced error handling with specific messages
      String errorMessage = e.toString().toLowerCase();
      String userMessage = 'Failed to download file. Please try again.';
      
      if (errorMessage.contains('network') || errorMessage.contains('connection')) {
        userMessage = 'Network error. Please check your connection and try again.';
      } else if (errorMessage.contains('permission') || errorMessage.contains('unauthorized')) {
        userMessage = 'You do not have permission to access this file.';
      } else if (errorMessage.contains('timeout')) {
        userMessage = 'Download timeout. Please try again.';
      } else if (errorMessage.contains('not found') || errorMessage.contains('404')) {
        userMessage = 'File not found or has been deleted.';
      } else if (errorMessage.contains('cors') || errorMessage.contains('cross-origin')) {
        userMessage = 'Download blocked by browser security. Please try again.';
      } else if (errorMessage.contains('invalid url')) {
        userMessage = 'Invalid file link. Please contact support.';
      }
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(userMessage),
          backgroundColor: AppTheme.errorRed,
          duration: const Duration(seconds: 4),
          action: SnackBarAction(
            label: 'Retry',
            textColor: Colors.white,
            onPressed: () {
              // Retry download - create a temporary message if needed
              if (message != null) {
                _downloadFile(message);
              } else {
                _proceedWithDownload(fileId, fileName, contentType, isPDF);
              }
            },
          ),
        ),
      );
    }
  }

  Future<Map<String, dynamic>> _getFileInfo(String fileId) async {
    try {
      final response = await serviceProvider.apiService.getFileInfo(fileId);
      return response;
    } catch (e) {
      // Gracefully handle timeouts / gateway errors so UI can still attempt download
      debugPrint('[FILE_INFO_ERROR] Failed to get file info: $e');
      return {};
    }
  }

  /// Best-effort MIME type guess based on filename extension.
  /// Used when the backend cannot return file info (e.g. 504/timeout).
  String _guessMimeTypeFromName(String name) {
    final lower = name.toLowerCase();
    if (lower.endsWith('.pdf')) return 'application/pdf';
    if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
    if (lower.endsWith('.png')) return 'image/png';
    if (lower.endsWith('.gif')) return 'image/gif';
    if (lower.endsWith('.webp')) return 'image/webp';
    if (lower.endsWith('.mp4')) return 'video/mp4';
    if (lower.endsWith('.zip')) return 'application/zip';
    if (lower.endsWith('.dmg')) return 'application/x-apple-diskimage';
    return 'application/octet-stream';
  }

  Future<void> _openFileInWeb(String fileId, String fileName, bool isPDF) async {
    if (!kIsWeb) {
      throw Exception('Web-only download helper called on non-web platform');
    }

    debugPrint('[FILE_WEB] Initiating download for: $fileName');
    debugPrint('[FILE_WEB] File ID: $fileId');

    // STRATEGY 1: Try to get a presigned URL from the download endpoint first
    try {
      final downloadResponse = await serviceProvider.apiService.get('/files/$fileId/download');
      
      if (downloadResponse.statusCode == 200 && downloadResponse.data != null) {
        final data = downloadResponse.data;
        // Handle both direct response and wrapped response formats
        String? presignedUrl;
        
        if (data is Map<String, dynamic>) {
          // Direct response format from updated endpoint
          presignedUrl = data['download_url'] as String?;
        } else if (data['data'] != null && data['data'] is Map<String, dynamic>) {
          // Wrapped response format
          presignedUrl = data['data']['download_url'] as String?;
        }
        
        if (presignedUrl != null && presignedUrl.isNotEmpty) {
          debugPrint('[FILE_WEB] Using presigned URL for download: ${presignedUrl.length > 50 ? '${presignedUrl.substring(0, 50)}...' : presignedUrl}');
          io.saveFileDirectFromUrl(fileName, presignedUrl);
          debugPrint('[FILE_WEB] Presigned URL download triggered for $fileName');
          return;
        }
      }
    } catch (e) {
      debugPrint('[FILE_WEB] Presigned URL attempt failed, falling back to token-based download: $e');
    }

    // STRATEGY 2: Fallback to token-based download
    final accessToken = serviceProvider.authService.accessToken;

    // Build the download URL with enhanced error handling
    String downloadUrl;
    try {
      // Try multiple endpoint strategies for better compatibility
      if (fileId.isNotEmpty) {
        // Strategy 1: Try media endpoint first (preferred)
        downloadUrl = '${ApiConstants.serverBaseUrl}/api/v1/media/$fileId?download=true&force_download=true';
        debugPrint('[FILE_WEB] Trying media endpoint: $downloadUrl');
      } else {
        // Strategy 2: Fallback to legacy files endpoint
        downloadUrl = '${ApiConstants.baseUrl}/files/$fileId/download?dl=1&force_download=true';
        debugPrint('[FILE_WEB] Using legacy endpoint: $downloadUrl');
      }

      // Add authentication token
      if (accessToken != null && accessToken.isNotEmpty) {
        final separator = downloadUrl.contains('?') ? '&' : '?';
        downloadUrl = '$downloadUrl${separator}token=$accessToken';
        debugPrint('[FILE_WEB] Added auth token: ${downloadUrl.substring(0, downloadUrl.indexOf('token=') + 10)}...');
      }
    } catch (e) {
      debugPrint('[FILE_WEB_ERROR] URL generation failed: $e');
      // Ultimate fallback - construct basic URL
      downloadUrl = '${ApiConstants.baseUrl}/files/$fileId/download?dl=1&force_download=true';
      if (accessToken != null) {
        downloadUrl += '&token=$accessToken';
      }
    }
      
    debugPrint('[FILE_WEB] Download URL: $downloadUrl');
      
    // Create an anchor element and trigger download
    // This is the proper way to handle downloads on web
    io.saveFileDirectFromUrl(fileName, downloadUrl);
      
    debugPrint('[FILE_WEB] Download triggered for $fileName');
  }

  Future<void> _downloadFileInWeb(String fileId, String fileName) async {
    try {
      if (!kIsWeb) {
        throw Exception('Web-only download helper called on non-web platform');
      }

      debugPrint('[FILE_WEB] Initiating simple download for: $fileName');
      debugPrint('[FILE_WEB] File ID: $fileId');

      final accessToken = serviceProvider.authService.accessToken;
      
      // Use the legacy download URL since we don't have fileKey without Message object
      final downloadUrl = '${ApiConstants.baseUrl}/files/$fileId/download?dl=1';
      
      final finalUrl = accessToken != null 
          ? '$downloadUrl&token=$accessToken'
          : downloadUrl;
      
      debugPrint('[FILE_WEB] Download URL: $finalUrl');
      
      // Create an anchor element and trigger download
      io.saveFileDirectFromUrl(fileName, finalUrl);
      
      debugPrint('[FILE_WEB] Download triggered for $fileName');
    } catch (e) {
      debugPrint('[FILE_WEB_ERROR] $e');
      rethrow;
    }
  }

  Future<void> _downloadAndOpenFile(String fileId, String fileName, String contentType) async {
    try {
      debugPrint('[FILE_NATIVE] Starting enhanced download for: $fileName');
      
      if (kIsWeb) {
        // Web: Use direct download without Message object
        await _downloadFileInWeb(fileId, fileName);
        return;
      } else {
        // Native: Use FileTransferService for proper chunked download
        // Generate a safe filename and path
        final safeFileName = fileName.replaceAll(RegExp(r'[^\w\-_.]'), '_');
        
        // Get downloads directory - use platform-appropriate directory
        io.Directory? downloadsDir;
        try {
          // Use path_provider to get appropriate base directory (native only)
          if (io.Platform.isAndroid) {
            final baseDir = await getExternalStorageDirectory();
            if (baseDir != null) {
              downloadsDir = io.Directory(path.join(baseDir.path, 'karo'));
            }
          } else {
            // For iOS, macOS, Windows, Linux - use application documents
            final baseDir = await getApplicationDocumentsDirectory();
            downloadsDir = io.Directory(path.join(baseDir.path, 'karo'));
          }
          
          if (downloadsDir != null && !await downloadsDir.exists()) {
            await downloadsDir.create(recursive: true);
          }
        } catch (e) {
          debugPrint('[FILE_NATIVE] Could not create karo directory: $e');
          // Fallback to default downloads directory
          try {
            // Use chat_io helper function for downloads directory
            final downloadsDirResult = await io.getDownloadsDirectory();
            if (downloadsDirResult != null) {
              downloadsDir = io.Directory(path.join(downloadsDirResult.path, 'karo'));
            }
          } catch (fallbackError) {
            debugPrint('[FILE_NATIVE] Could not get fallback downloads directory: $fallbackError');
          }
        }
        
        // Final fallback to application documents (native only)
        try {
          final appDocsDir = await getApplicationDocumentsDirectory();
          downloadsDir ??= io.Directory(path.join(appDocsDir.path, 'karo'));
        } catch (e) {
          debugPrint('[FILE_NATIVE] Could not get application documents directory: $e');
          throw Exception('Unable to determine download directory');
        }
        
        final savePath = '${downloadsDir.path}/$safeFileName';
        
        debugPrint('[FILE_NATIVE] Download path: $savePath');
        
        // Use FileTransferService for chunked download (now supports large files)
        await serviceProvider.fileTransferService.downloadFile(
          fileId: fileId,
          fileName: fileName,
          savePath: safeFileName,
          onProgress: (progress) {
            debugPrint('[FILE_NATIVE] Download progress: ${(progress * 100).toStringAsFixed(1)}%');
          },
        );
        
        debugPrint('[FILE_NATIVE] Download completed, attempting to open file');
        
        // Verify file exists and open it
        final file = io.File(savePath);
        if (await file.exists()) {
          await _openDownloadedFile(savePath, contentType);
        } else {
          throw Exception('Downloaded file not found at: $savePath');
        }
        debugPrint('[FILE_NATIVE] File saved successfully');
      }
    } catch (e) {
      debugPrint('[FILE_NATIVE_ERROR] $e');
      rethrow;
    }
  }

  Future<void> _openDownloadedFile(String filePath, String contentType) async {
    if (kIsWeb) {
      throw Exception('File operations not supported on web platform');
    }

    try {
      debugPrint('[FILE_OPEN] Attempting to open file: $filePath');
      debugPrint('[FILE_OPEN] File exists check starting...');
      
      final file = io.File(filePath);
      final fileExists = await file.exists();
      debugPrint('[FILE_OPEN] File exists: $fileExists');
      
      if (!fileExists) {
        debugPrint('[FILE_OPEN] File not found error: $filePath');
        throw Exception('Downloaded file not found at: $filePath');
      }

      debugPrint('[FILE_OPEN] Platform: ${io.Platform.operatingSystem}');
      debugPrint('[FILE_OPEN] File size: ${await file.length()} bytes');

      if (io.Platform.isAndroid || io.Platform.isIOS) {
        // For mobile platforms, use url_launcher to open file
        debugPrint('[FILE_OPEN] Using mobile platform file opening');
        final uri = Uri.file(filePath);
        debugPrint('[FILE_OPEN] File URI: $uri');
        
        if (await canLaunchUrl(uri)) {
          await launchUrl(uri);
          debugPrint('[FILE_OPEN] Successfully launched file via url_launcher');
        } else {
          debugPrint('[FILE_OPEN] Failed to launch file via url_launcher');
          throw Exception('Cannot open file: $filePath');
        }
      } else if (io.Platform.isWindows || io.Platform.isLinux || io.Platform.isMacOS) {
        // For desktop platforms, use Process.run to open file with default application
        debugPrint('[FILE_OPEN] Using desktop platform file opening');
        
        if (io.Platform.isWindows) {
          debugPrint('[FILE_OPEN] Opening with Windows start command');
          await io.Process.run('start', [filePath], runInShell: true);
        } else if (io.Platform.isMacOS) {
          debugPrint('[FILE_OPEN] Opening with macOS open command');
          await io.Process.run('open', [filePath]);
        } else if (io.Platform.isLinux) {
          debugPrint('[FILE_OPEN] Opening with Linux xdg-open command');
          await io.Process.run('xdg-open', [filePath]);
        }
        
        debugPrint('[FILE_OPEN] Desktop file opening command executed');
      } else {
        debugPrint('[FILE_OPEN] Unsupported platform: ${io.Platform.operatingSystem}');
        throw Exception('Unsupported platform for file opening: ${io.Platform.operatingSystem}');
      }
      
      debugPrint('[FILE_OPEN] Successfully opened file: $filePath');
    } catch (e) {
      debugPrint('[FILE_OPEN_ERROR] Failed to open file: $e');
      debugPrint('[FILE_OPEN_ERROR] Stack trace: ${StackTrace.current}');
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
        return 'Saved Messages';
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

  /// Precompute list items that includes both messages and date separators.
  /// Messages are grouped by date (calendar date) with proper separators.
  /// This ensures proper WhatsApp-style date grouping.
  void _precomputeListItems() {
    final items = <dynamic>[];
    DateTime? previousMessageDate;

    for (final message in _messages) {
      // Get calendar date (year, month, day) only
      final messageDate = DateTime(
        message.timestamp.year,
        message.timestamp.month,
        message.timestamp.day,
      );

      // Check if date changed from previous message
      if (previousMessageDate == null || previousMessageDate != messageDate) {
        // Insert date separator for new date
        items.add({
          'type': 'date_separator',
          'date': messageDate,
          'timestamp': message.timestamp,
        });
        previousMessageDate = messageDate;
      }

      // Add message
      items.add({
        'type': 'message',
        'message': message,
      });
    }

    _listItems = items;
  }

  /// Build a single list item based on its type
  Widget _buildListItem(dynamic item) {
    if (item['type'] == 'date_separator') {
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
            TimeFormatter.formatDateDivider(item['timestamp']),
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ),
      );
    } else if (item['type'] == 'message') {
      final message = item['message'] as Message;
      return MessageBubble(
        message: message,
        avatarUrl: null,
        onLongPress: () => _showMessageActions(message),
        onToggleReaction: (emoji) => _toggleReaction(message, emoji),
        onAddReaction: () => _showReactionPicker(message),
        onFileTap: (msg) => _downloadFile(msg),
      );
    }
    
    return const SizedBox.shrink();
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
                // FIXED: Never show initials to prevent 2 words avatar
                CircleAvatar(
                  radius: 20,
                  backgroundColor: AppTheme.cardDark,
                  child: null, // No initials - just empty circle
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
          if (_chat != null && _chat?.type != ChatType.saved)
            PopupMenuButton<String>(
              icon: const Icon(Icons.more_vert),
              tooltip: 'More options',
              onSelected: (value) {
                switch (value) {
                  case 'group_options':
                    _showGroupOptions();
                    break;
                  case 'p2p_options':
                    _showP2pChatOptions();
                    break;
                  case 'channel_options':
                    _showChannelOptions();
                    break;
                }
              },
              itemBuilder: (context) {
                if (_chat?.type == ChatType.group || _chat?.type == ChatType.supergroup) {
                  return [
                    const PopupMenuItem(
                      value: 'group_options',
                      child: Row(
                        children: [
                          Icon(Icons.info_outline),
                          SizedBox(width: 8),
                          Text('Group Options'),
                        ],
                      ),
                    ),
                  ];
                } else if (_chat?.type == ChatType.direct) {
                  return [
                    const PopupMenuItem(
                      value: 'p2p_options',
                      child: Row(
                        children: [
                          Icon(Icons.person_add),
                          SizedBox(width: 8),
                          Text('Contact Options'),
                        ],
                      ),
                    ),
                  ];
                } else if (_chat?.type == ChatType.channel) {
                  return [
                    const PopupMenuItem(
                      value: 'channel_options',
                      child: Row(
                        children: [
                          Icon(Icons.settings_outlined),
                          SizedBox(width: 8),
                          Text('Channel Options'),
                        ],
                      ),
                    ),
                  ];
                }
                return [];
              },
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
                        itemCount: _listItems.length,
                        itemBuilder: (context, index) {
                          return _buildListItem(_listItems[index]);
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