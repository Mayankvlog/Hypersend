import 'package:equatable/equatable.dart';

class User extends Equatable {
  final String id;
  final String name;
  final String username;
  final String avatar;
  final bool isOnline;

  const User({
    required this.id,
    required this.name,
    required this.username,
  /// Create a User from API response map
  factory User.fromApi(Map<String, dynamic> json) {
    return User(
      id: (json['_id'] ?? json['id'] ?? '').toString(),
      name: (json['name'] ?? json['full_name'] ?? '').toString(),
      username: (json['username'] ?? json['email'] ?? '').toString(),
      avatar: (json['avatar_url'] ?? json['avatar'] ?? '').toString(),
      isOnline: (json['is_online'] ?? json['online'] ?? false) as bool,
    );
  }
    required this.avatar,
    this.isOnline = false,
  });

  @override
  List<Object?> get props => [id, name, username, avatar, isOnline];

  User copyWith({
    String? id,
    String? name,
    String? username,
    String? avatar,
    bool? isOnline,
  }) {
    return User(
      id: id ?? this.id,
      name: name ?? this.name,
      username: username ?? this.username,
      avatar: avatar ?? this.avatar,
      isOnline: isOnline ?? this.isOnline,
    );
  }
}