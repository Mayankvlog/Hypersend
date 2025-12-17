import 'package:equatable/equatable.dart';
import 'group_member.dart';
import 'group_activity.dart';

class Group extends Equatable {
  final String id; // same as chatId
  final String name;
  final String description;
  final String avatar; // initials or url
  final String createdBy;
  final List<GroupMember> members;
  final bool notificationsMuted;
  final List<GroupActivity> activity;

  const Group({
    required this.id,
    required this.name,
    this.description = '',
    required this.avatar,
    required this.createdBy,
    this.members = const [],
    this.notificationsMuted = false,
    this.activity = const [],
  });

  Group copyWith({
    String? id,
    String? name,
    String? description,
    String? avatar,
    String? createdBy,
    List<GroupMember>? members,
    bool? notificationsMuted,
    List<GroupActivity>? activity,
  }) {
    return Group(
      id: id ?? this.id,
      name: name ?? this.name,
      description: description ?? this.description,
      avatar: avatar ?? this.avatar,
      createdBy: createdBy ?? this.createdBy,
      members: members ?? this.members,
      notificationsMuted: notificationsMuted ?? this.notificationsMuted,
      activity: activity ?? this.activity,
    );
  }

  @override
  List<Object?> get props => [
        id,
        name,
        description,
        avatar,
        createdBy,
        members,
        notificationsMuted,
        activity,
      ];
}



