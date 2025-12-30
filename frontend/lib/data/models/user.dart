import 'package:equatable/equatable.dart';
import '../../core/constants/api_constants.dart';

class User extends Equatable {
  final String id;
  final String name;
  final String username;
  final String? email;
  final String? bio;
  final String avatar;
  final String? avatarUrl;
  final bool isOnline;
  final DateTime? lastSeen;
  final String? status;
  final DateTime? updatedAt;
  final bool isContact;
  final bool isBlocked;
  
  const User({
    required this.id,
    required this.name,
    required this.username,
    required this.avatar,
    this.avatarUrl,
    this.email,
    this.bio,
    this.isOnline = false,
    this.lastSeen,
    this.status,
    this.updatedAt,
    this.isContact = false,
    this.isBlocked = false,
  });

  /// Create a User from API response map
  factory User.fromApi(Map<String, dynamic> json) {
    return User(
      id: (json['_id'] ?? json['id'] ?? '').toString().trim(),
      name: (json['name'] ?? json['full_name'] ?? '').toString().trim(),
      username: (json['username'] ?? json['username_alias'] ?? (json['email'] as String?)?.split('@').first ?? 'user').toString().trim(),
      email: json['email']?.toString().trim(),
      bio: json['bio']?.toString().trim(),
      avatar: json['avatar']?.toString().trim() ?? '',
      avatarUrl: json['avatar_url']?.toString().trim(),
      isOnline: (json['is_online'] ?? json['online'] ?? false) as bool,
      lastSeen: json['last_seen'] != null ? DateTime.tryParse(json['last_seen']) : null,
      status: json['status']?.toString().trim(),
      updatedAt: json['updated_at'] != null ? DateTime.tryParse(json['updated_at']) : null,
      isContact: (json['is_contact'] ?? false) as bool,
      isBlocked: (json['is_blocked'] ?? false) as bool,
    );
  }

  @override
  List<Object?> get props => [
        id, name, username, email, bio, avatar, avatarUrl, isOnline, 
        lastSeen, status, updatedAt, isContact, isBlocked
      ];

  User copyWith({
    String? id,
    String? name,
    String? username,
    String? email,
    String? bio,
    String? avatar,
    String? avatarUrl,
    bool? isOnline,
    DateTime? lastSeen,
    String? status,
    DateTime? updatedAt,
    bool? isContact,
    bool? isBlocked,
  }) {
    return User(
      id: id ?? this.id,
      name: name ?? this.name,
      username: username ?? this.username,
      email: email ?? this.email,
      bio: bio ?? this.bio,
      avatar: avatar ?? this.avatar,
      avatarUrl: avatarUrl ?? this.avatarUrl,
      isOnline: isOnline ?? this.isOnline,
      lastSeen: lastSeen ?? this.lastSeen,
      status: status ?? this.status,
      updatedAt: updatedAt ?? this.updatedAt,
      isContact: isContact ?? this.isContact,
      isBlocked: isBlocked ?? this.isBlocked,
    );
  }

  /// Helper to determine if the avatar string is a file path/URL or just initials
  bool get isAvatarPath {
    // Check avatarUrl first (for uploaded images)
    if (avatarUrl != null && avatarUrl!.isNotEmpty) {
      final trimmed = avatarUrl!.trim();
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
    
    // Fallback to avatar field (for initials)
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
    // Try avatarUrl first (for uploaded images)
    if (avatarUrl != null && avatarUrl!.isNotEmpty) {
      final trimmed = avatarUrl!.trim();
      if (trimmed.startsWith('http')) return trimmed;
      if (trimmed.startsWith('/')) {
        return '${ApiConstants.serverBaseUrl}$trimmed';
      }
      // If it doesn't start with http or /, assume it's a relative path
      return '${ApiConstants.serverBaseUrl}/$trimmed';
    }
    
    // Fallback to avatar field
    final trimmed = avatar.trim();
    if (trimmed.startsWith('http')) return trimmed;
    if (trimmed.startsWith('/')) {
      return '${ApiConstants.serverBaseUrl}$trimmed';
    }
    // For non-URL avatars (initials), return empty string
    return '';
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

  /// Get formatted last seen text
  String get lastSeenText {
    if (isOnline) return 'online';
    if (lastSeen == null) return 'last seen a long time ago';
    
    final now = DateTime.now();
    final difference = now.difference(lastSeen!);
    
    if (difference.inMinutes < 1) {
      return 'last seen just now';
    } else if (difference.inMinutes < 60) {
      return 'last seen ${difference.inMinutes} minute${difference.inMinutes == 1 ? '' : 's'} ago';
    } else if (difference.inHours < 24) {
      return 'last seen ${difference.inHours} hour${difference.inHours == 1 ? '' : 's'} ago';
    } else if (difference.inDays < 7) {
      return 'last seen ${difference.inDays} day${difference.inDays == 1 ? '' : 's'} ago';
    } else {
      // Format date for older times using locale-appropriate format
      final date = lastSeen!;
      return 'last seen ${date.day}/${date.month}/${date.year}';
    }
  }

  /// Get status text or fallback to last seen
  String get displayStatus {
    if (status?.isNotEmpty == true) {
      return status!;
    }
    return lastSeenText;
  }

  /// Check if username is not empty
  bool get usernameIsNotEmpty => username.isNotEmpty;

  /// Check if user is recently online (within last 5 minutes)
  bool get isRecentlyOnline {
    if (isOnline) return true;
    if (lastSeen == null) return false;
    final difference = DateTime.now().difference(lastSeen!);
    return difference.inMinutes < 5;
  }
}