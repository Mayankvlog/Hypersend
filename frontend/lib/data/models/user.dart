import 'package:equatable/equatable.dart';

class User extends Equatable {
  final String id;
  final String name;
  final String username;
  final String? email;
  final String avatar;
  final bool isOnline;
  const User({
    required this.id,
    required this.name,
    required this.username,
    required this.avatar,
    this.email,
    this.isOnline = false,
  });

  /// Create a User from API response map
  factory User.fromApi(Map<String, dynamic> json) {
    return User(
      id: (json['_id'] ?? json['id'] ?? '').toString(),
      name: (json['name'] ?? json['full_name'] ?? '').toString(),
      username: (json['username'] ?? json['username_alias'] ?? json['email']?.toString()?.split('@')?.first ?? 'user').toString(),
      email: json['email']?.toString(),
      avatar: (json['avatar_url'] ?? json['avatar'] ?? '').toString(),
      isOnline: (json['is_online'] ?? json['online'] ?? false) as bool,
    );
  }

  @override
  List<Object?> get props => [id, name, username, email, avatar, isOnline];

  User copyWith({
    String? id,
    String? name,
    String? username,
    String? email,
    String? avatar,
    bool? isOnline,
  }) {
    return User(
      id: id ?? this.id,
      name: name ?? this.name,
      username: username ?? this.username,
      email: email ?? this.email,
      avatar: avatar ?? this.avatar,
      isOnline: isOnline ?? this.isOnline,
    );
  }
}