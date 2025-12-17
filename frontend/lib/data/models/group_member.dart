import 'package:equatable/equatable.dart';

enum GroupRole { admin, member }

class GroupMember extends Equatable {
  final String userId;
  final GroupRole role;
  final DateTime joinedAt;

  const GroupMember({
    required this.userId,
    this.role = GroupRole.member,
    required this.joinedAt,
  });

  GroupMember copyWith({
    String? userId,
    GroupRole? role,
    DateTime? joinedAt,
  }) {
    return GroupMember(
      userId: userId ?? this.userId,
      role: role ?? this.role,
      joinedAt: joinedAt ?? this.joinedAt,
    );
  }

  @override
  List<Object?> get props => [userId, role, joinedAt];
}



