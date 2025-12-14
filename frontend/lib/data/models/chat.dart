import 'package:equatable/equatable.dart';

enum ChatType { direct, group }

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