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
      id: (json['_id'] ?? json['id'] ?? '').toString().trim(),
      name: (json['name'] ?? json['full_name'] ?? '').toString().trim(),
      username: (json['username'] ?? json['username_alias'] ?? (json['email'] as String?)?.split('@').first ?? 'user').toString().trim(),
      email: json['email']?.toString().trim(),
      avatar: (json['avatar_url'] ?? json['avatar'] ?? '').toString().trim(),
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
    final trimmed = avatar.trim();
    if (trimmed.isEmpty) return false;
    
    // Explicit URL prefixes
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return true;
    
    // Absolute paths from backend
    if (trimmed.startsWith('/')) return true;
    
    // Check for common image extensions if it contains a dot
    final lower = trimmed.toLowerCase();
    if (lower.contains('.')) {
      final extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'];
      for (final ext in extensions) {
        if (lower.endsWith(ext)) return true;
      }
    }
    
    // If it's very short (1-2 chars), it's definitely initials
    if (trimmed.length <= 2) return false;

    // Fallback: If it contains a slash and is long enough, likely a path
    if (trimmed.contains('/') && trimmed.length > 5) return true;

    return false;
  }

  /// Resolves the full avatar URL for display
  String get fullAvatarUrl {
    final trimmed = avatar.trim();
    if (!isAvatarPath) return '';
    if (trimmed.startsWith('http')) return trimmed;
    if (trimmed.startsWith('/')) {
      return 'https://zaply.in.net$trimmed';
    }
    // Relative path fallback
    return 'https://zaply.in.net/$trimmed';
  }

  /// Helper to get initials from name or avatar field
  String get initials {
    if (!isAvatarPath && avatar.isNotEmpty && avatar.length <= 3) {
      return avatar.toUpperCase();
    }
    if (name.trim().isEmpty) return '??';
    final parts = name.trim().split(' ');
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return name.substring(0, name.length >= 2 ? 2 : 1).toUpperCase();
  }
}