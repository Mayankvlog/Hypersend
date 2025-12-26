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
      username: (json['username'] ?? json['username_alias'] ?? (json['email'] as String?)?.split('@').first ?? 'user').toString(),
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

  /// Helper to determine if the avatar string is a file path/URL or just initials
  bool get isAvatarPath {
    if (avatar.isEmpty) return false;
    
    // Explicit URL prefixes
    if (avatar.startsWith('http://') || avatar.startsWith('https://')) return true;
    
    // Absolute paths from backend
    if (avatar.startsWith('/')) return true;
    
    // Check for common image extensions if it contains a dot
    // Initials (e.g., "AM") won't match these extensions
    final lower = avatar.toLowerCase();
    if (lower.contains('.')) {
      final extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'];
      for (final ext in extensions) {
        if (lower.endsWith(ext)) return true;
      }
    }
    
    // If it's very short (1-2 chars), it's definitely initials
    if (avatar.length <= 2) return false;

    // Fallback: If it contains a slash and is long enough, likely a path
    if (avatar.contains('/') && avatar.length > 5) return true;

    return false;
  }

  /// Resolves the full avatar URL for display
  String get fullAvatarUrl {
    if (!isAvatarPath) return '';
    if (avatar.startsWith('http')) return avatar;
    if (avatar.startsWith('/')) {
      return 'https://zaply.in.net$avatar';
    }
    // Relative path fallback
    return 'https://zaply.in.net/$avatar';
  }
}