import 'package:equatable/equatable.dart';

enum ChatType { direct, group, supergroup, channel, secret, saved }

class Chat extends Equatable {
  final String id;
  final ChatType type;
  final String name;
  final String avatar;
  final String lastMessage;
  final DateTime lastMessageTime;
  final int unreadCount;
  final bool isMuted;
  final bool isOnline;
  final String? senderName;

  const Chat({
    required this.id,
    required this.type,
    required this.name,
    required this.avatar,
    required this.lastMessage,
    required this.lastMessageTime,
    this.unreadCount = 0,
    this.isMuted = false,
    this.isOnline = false,
    this.senderName,
  });

  factory Chat.fromApi(Map<String, dynamic> json) {
    final typeStr = (json['type'] ?? 'private').toString();
    ChatType chatType;
    switch (typeStr) {
      case 'private':
      case 'direct':
        chatType = ChatType.direct;
        break;
      case 'group':
        chatType = ChatType.group;
        break;
      case 'supergroup':
        chatType = ChatType.supergroup;
        break;
      case 'channel':
        chatType = ChatType.channel;
        break;
      case 'secret':
        chatType = ChatType.secret;
        break;
      case 'saved':
        chatType = ChatType.saved;
        break;
      default:
        chatType = ChatType.direct;
    }

    final last = json['last_message'] as Map<String, dynamic>?;
    final lastText = (last?['text'] ?? last?['content'] ?? '').toString();
    final lastAtRaw = last?['created_at'];
    final lastAt = lastAtRaw is String ? DateTime.tryParse(lastAtRaw) : null;

    final displayName = (json['display_name'] ?? json['name'] ?? (chatType == ChatType.group ? 'Group' : 'Chat')).toString();
    final senderName = json['last_message_sender_name']?.toString();

    // avatar_url from backend is the only source of image; otherwise use initials from name
    String avatar;
    final avatarUrlRaw = json['avatar_url']?.toString() ?? '';
    if (avatarUrlRaw.isNotEmpty) {
      avatar = avatarUrlRaw;
    // FIXED: Never generate initials to prevent 2 words avatar
    } else {
      // Always use empty string for avatar to prevent initials
      avatar = ''; // No initials - just empty string
    }

    DateTime fallbackTime() {
      final raw = json['created_at'];
      if (raw is String) {
        return DateTime.tryParse(raw) ?? DateTime.now();
      }
      return DateTime.now();
    }

    return Chat(
      id: (json['_id'] ?? json['id'] ?? '').toString(),
      type: chatType,
      name: displayName,
      avatar: avatar,
      lastMessage: lastText.isEmpty ? 'No messages yet' : lastText,
      lastMessageTime: lastAt ?? fallbackTime(),
      unreadCount: 0,
      isMuted: false,
      isOnline: false,
      senderName: senderName,
    );
  }

  @override
  List<Object?> get props => [
        id,
        type,
        name,
        avatar,
        lastMessage,
        lastMessageTime,
        unreadCount,
        isMuted,
        isOnline,
        senderName,
      ];
}