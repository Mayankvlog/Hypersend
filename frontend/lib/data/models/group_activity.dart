import 'package:equatable/equatable.dart';

class GroupActivity extends Equatable {
  final String id;
  final String event;
  final String actorId;
  final DateTime timestamp;
  final Map<String, dynamic> meta;

  const GroupActivity({
    required this.id,
    required this.event,
    required this.actorId,
    required this.timestamp,
    this.meta = const {},
  });

  @override
  List<Object?> get props => [id, event, actorId, timestamp, meta];
}



