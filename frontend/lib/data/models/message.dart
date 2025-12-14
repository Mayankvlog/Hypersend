import 'package:equatable/equatable.dart';

enum MessageStatus { sent, delivered, read }

class Message extends Equatable {
  final String id;
  final String chatId;
  final String senderId;
  final String content;
  final DateTime timestamp;
  final MessageStatus status;
  final bool isOwn;

  const Message({
    required this.id,
    required this.chatId,
    required this.senderId,
    required this.content,
    required this.timestamp,
    required this.status,
    required this.isOwn,
  });

  @override
  List<Object?> get props => [
        id,
        chatId,
        senderId,
        content,
        timestamp,
        status,
        isOwn,
      ];
}