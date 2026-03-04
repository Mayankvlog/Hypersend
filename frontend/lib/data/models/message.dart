import 'package:equatable/equatable.dart';

enum MessageStatus { sending, sent, delivered, read }

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
  final String? fileId;

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
    this.fileId,
  });

  factory Message.fromApi(Map<String, dynamic> json, {required String currentUserId}) {
    final senderId = (json['sender_id'] ?? json['senderId'] ?? '').toString().trim();
    final createdAtRaw = json['created_at'] ?? json['createdAt'];
    DateTime? createdAt;
    
    if (createdAtRaw is String) {
      createdAt = DateTime.tryParse(createdAtRaw);
      // CRITICAL: Keep timestamp in UTC - frontend displays in local time via Intl.DateTimeFormat
      // DO NOT convert to local time here - let UI layer handle display formatting
    } else if (createdAtRaw is DateTime) {
      // Keep as-is, do not convert timezone
      createdAt = createdAtRaw;
    }

    final reactionsRaw = (json['reactions'] as Map?)?.cast<String, dynamic>() ?? const <String, dynamic>{};
    final reactions = <String, List<String>>{};
    for (final entry in reactionsRaw.entries) {
      final users = (entry.value as List?)?.map((e) => e.toString()).toList() ?? <String>[];
      reactions[entry.key] = users;
    }

    final readByRaw = (json['read_by'] as List?) ?? const [];
    final readBy = readByRaw
        .map((e) => (e is Map ? e['user_id'] : e)?.toString())
        .whereType<String>()
        .toList();

    final isDeleted = json['is_deleted'] == true;
    final text = (json['text'] ?? '').toString().trim();
    final fileId = (json['file_id'] ?? json['fileId'])?.toString().trim();

    return Message(
      id: (json['_id'] ?? json['id'] ?? '').toString().trim(),
      chatId: (json['chat_id'] ?? json['chatId'] ?? '').toString().trim(),
      senderId: senderId,
      content: isDeleted ? null : text,
      timestamp: createdAt ?? DateTime.now(),
      status: _parseMessageStatus(json, readBy),
      isOwn: senderId == currentUserId,
      isPinned: json['is_pinned'] == true,
      isEdited: json['is_edited'] == true,
      isDeleted: isDeleted,
      editedAt: (json['edited_at'] is String) ? DateTime.tryParse(json['edited_at']) : null,
      deletedAt: (json['deleted_at'] is String) ? DateTime.tryParse(json['deleted_at']) : null,
      reactions: reactions,
      readBy: readBy,
      fileId: fileId,
    );
  }

  // Helper function to parse message status from API response
  static MessageStatus _parseMessageStatus(Map<String, dynamic> json, List<String> readBy) {
    // Check for explicit status field first
    final statusStr = (json['status'] ?? json['message_state'])?.toString().toLowerCase();
    
    switch (statusStr) {
      case 'sending':
        return MessageStatus.sending;
      case 'sent':
        return MessageStatus.sent;
      case 'delivered':
        return MessageStatus.delivered;
      case 'read':
        return MessageStatus.read;
    }
    
    // Fallback: infer from read_by count
    if (readBy.length > 1) {
      return MessageStatus.read;
    } else if (readBy.length == 1) {
      return MessageStatus.delivered;
    } else {
      return MessageStatus.sent;
    }
  }

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
      // ignore: unnecessary_this (false positive - this.readBy is needed for null coalescing)
      readBy: readBy ?? this.readBy,
      // ignore: unnecessary_this (false positive - this.fileId is needed for null coalescing)
      fileId: fileId ?? this.fileId,
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
        fileId,
      ];
}