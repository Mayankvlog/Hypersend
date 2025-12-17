import 'package:equatable/equatable.dart';

enum MessageStatus { sent, delivered, read }

class Message extends Equatable {
  final String id;
  final String chatId;
  final String senderId;
  final String? content;
  final DateTime timestamp;
  final MessageStatus status;
  final bool isOwn;
  final bool isPinned;
  final bool isEdited;
  final bool isDeleted;
  final DateTime? editedAt;
  final DateTime? deletedAt;
  final Map<String, List<String>> reactions; // emoji -> userIds
  final List<String> readBy; // userIds

  const Message({
    required this.id,
    required this.chatId,
    required this.senderId,
    required this.content,
    required this.timestamp,
    required this.status,
    required this.isOwn,
    this.isPinned = false,
    this.isEdited = false,
    this.isDeleted = false,
    this.editedAt,
    this.deletedAt,
    this.reactions = const {},
    this.readBy = const [],
  });

  Message copyWith({
    String? id,
    String? chatId,
    String? senderId,
    String? content,
    DateTime? timestamp,
    MessageStatus? status,
    bool? isOwn,
    bool? isPinned,
    bool? isEdited,
    bool? isDeleted,
    DateTime? editedAt,
    DateTime? deletedAt,
    Map<String, List<String>>? reactions,
    List<String>? readBy,
  }) {
    return Message(
      id: id ?? this.id,
      chatId: chatId ?? this.chatId,
      senderId: senderId ?? this.senderId,
      content: content ?? this.content,
      timestamp: timestamp ?? this.timestamp,
      status: status ?? this.status,
      isOwn: isOwn ?? this.isOwn,
      isPinned: isPinned ?? this.isPinned,
      isEdited: isEdited ?? this.isEdited,
      isDeleted: isDeleted ?? this.isDeleted,
      editedAt: editedAt ?? this.editedAt,
      deletedAt: deletedAt ?? this.deletedAt,
      reactions: reactions ?? this.reactions,
      readBy: readBy ?? this.readBy,
    );
  }

  @override
  List<Object?> get props => [
        id,
        chatId,
        senderId,
        content,
        timestamp,
        status,
        isOwn,
        isPinned,
        isEdited,
        isDeleted,
        editedAt,
        deletedAt,
        reactions,
        readBy,
      ];
}