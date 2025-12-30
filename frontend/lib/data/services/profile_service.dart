import 'package:flutter/foundation.dart';

import '../models/user.dart';
import 'api_service.dart';

class ProfileService {
  final ApiService _apiService;
  User? _currentUser;

  ProfileService(this._apiService);

  User? get currentUser => _currentUser;

  // Initialize with user data
  void setUser(User user) {
    _currentUser = user;
  }

  // Update user profile with field validation and safeguards
  Future<User> updateProfile({
    String? name,
    String? username,
    String? avatar,  // NOTE: Only for initials (max 10 chars)
    String? avatarUrl,  // NOTE: Only for image URLs (max 500 chars)
    String? email,
    String? bio,
  }) async {
      // Validate field constraints - MORE RELAXED VALIDATION
      if (avatar != null && avatar.length > 200) {  // Increased from 50 to 200
        debugPrint('[PROFILE_SERVICE] WARNING: Avatar field long. Using avatarUrl field instead.');
        // Don't throw error, just handle gracefully
        if (avatarUrl == null) {
          // Move long avatar to avatarUrl field
          avatarUrl = avatar;
          avatar = null;
        }
      }
      
      if (avatarUrl != null && avatarUrl.length > 2000) {  // Increased from 1000 to 2000
        debugPrint('[PROFILE_SERVICE] ERROR: AvatarUrl field extremely long. Truncating.');
        avatarUrl = avatarUrl.substring(0, 2000);  // Truncate instead of throwing
      }
    if (_currentUser == null) {
      throw Exception('No user logged in');
    }

    try {
      // Validate name - only if name is being updated
      if (name != null) {
        if (name.isEmpty && _currentUser!.name.isEmpty) {
          throw Exception('Name cannot be empty. Please provide a valid name.');
        }
        if (name.isNotEmpty && name.length < 2) {
          throw Exception('Name must be at least 2 characters long. Current length: ${name.length}');
        }
      }

      debugPrint('[PROFILE_UPDATE] Starting profile update');
      debugPrint('[PROFILE_UPDATE] Fields: name=$name, email=$email, username=$username, avatar=$avatar');
      
      // Build update map - only include fields that are not null
      final updateMap = <String, dynamic>{};
      if (name != null) updateMap['name'] = name;
      if (username != null) updateMap['username'] = username;
      if (email != null) updateMap['email'] = email;
      if (avatar != null) updateMap['avatar'] = avatar;  // Add avatar field for initials
      if (avatarUrl != null) {
        updateMap['avatar_url'] = avatarUrl;  // Add avatar_url field for image URL
        // Also send profile_picture for backend compatibility
        updateMap['profile_picture'] = avatarUrl;
      }
      if (bio != null) updateMap['bio'] = bio;
      
      debugPrint('[PROFILE_UPDATE] Sending to API: $updateMap');
      
      // Call API to update profile (avatar is handled separately)
      final response = await _apiService.updateProfile(updateMap);
      
      debugPrint('[PROFILE_UPDATE] API response: $response');

      // Update local user object
      _currentUser = _currentUser!.copyWith(
        name: name ?? _currentUser!.name,
        username: username ?? _currentUser!.username,
        email: email ?? _currentUser!.email,
        bio: bio ?? _currentUser!.bio,
        avatar: avatar ?? _currentUser!.avatar,
        avatarUrl: avatarUrl ?? _currentUser!.avatarUrl,
      );
      debugPrint('[PROFILE_UPDATE] Local user updated successfully');
      return _currentUser!;
    } catch (e) {
      debugPrint('[PROFILE_UPDATE_ERROR] Failed: $e');
      rethrow;
    }
  }

  // Change password
  Future<bool> changePassword({
    required String oldPassword,
    required String newPassword,
  }) async {
    try {
      // Validate old password
      if (oldPassword.isEmpty || newPassword.isEmpty) {
        throw Exception('Password cannot be empty');
      }
      if (newPassword.length < 6) {
        throw Exception('Password must be at least 6 characters');
      }
      // Call API to change password
      await _apiService.changePassword(
        oldPassword: oldPassword,
        newPassword: newPassword,
      );
      return true;
    } catch (e) {
      rethrow;
    }
  }

  // Reset password (send reset email)
  Future<bool> resetPassword({required String email}) async {
    try {
      if (email.isEmpty || !email.contains('@')) {
        throw Exception('Please provide a valid email address');
      }
      // Call API to send reset email
      await _apiService.resetPassword(email: email);
      return true;
    } catch (e) {
      rethrow;
    }
  }

  // Change email
  Future<bool> changeEmail({
    required String newEmail,
    required String password,
  }) async {
    try {
      if (newEmail.isEmpty || !newEmail.contains('@')) {
        throw Exception('Please provide a valid email address');
      }
      if (password.isEmpty) {
        throw Exception('Password is required to change email');
      }
      // Call API to change email
      await _apiService.changeEmail(
        newEmail: newEmail,
        password: password,
      );
      // Update user email in memory
      if (_currentUser != null) {
        _currentUser = _currentUser!.copyWith(
          email: newEmail,
        );
      }
      return true;
    } catch (e) {
      rethrow;
    }
  }

  // Change username
  Future<bool> changeUsername(String newUsername) async {
    try {
      if (newUsername.isEmpty) {
        throw Exception('Username cannot be empty');
      }
      if (newUsername.length < 3) {
        throw Exception('Username must be at least 3 characters');
      }
      // Call API to change username (correct method signature)
      await _apiService.updateProfile({'username': newUsername});
      _currentUser = _currentUser!.copyWith(username: newUsername);
      return true;
    } catch (e) {
      rethrow;
    }
  }

  // Update avatar
Future<String> uploadAvatar(Uint8List bytes, String filename) async {
    try {
      debugPrint('[PROFILE_SERVICE] Uploading avatar: $filename');
      final response = await _apiService.uploadAvatar(bytes, filename);
      
      debugPrint('[PROFILE_SERVICE] Raw response: $response');
      debugPrint('[PROFILE_SERVICE] Response type: ${response.runtimeType}');
      
       if (response is! Map<String, dynamic>) {
        throw Exception('Invalid response from server: expected Map, got ${response.runtimeType}');
      }
      
       final Map<String, dynamic> responseMap = response;
      
      // Check for avatar_url field (required)
      if (!responseMap.containsKey('avatar_url') || responseMap['avatar_url'] == null) {
        debugPrint('[PROFILE_SERVICE] Response keys: ${responseMap.keys.toList()}');
        throw Exception('Invalid response from server: missing avatar_url field');
      }
      
      final avatarUrl = responseMap['avatar_url'].toString();
      debugPrint('[PROFILE_SERVICE] Avatar uploaded successfully: $avatarUrl');
      
      // Extract avatar field if available (for initials)
      final String avatar = responseMap.containsKey('avatar') ? responseMap['avatar'].toString() : '';
      
      // Update local user with new avatar URL and avatar (server already updated during upload)
      if (_currentUser != null) {
        _currentUser = _currentUser!.copyWith(
          avatarUrl: avatarUrl,
          avatar: avatar.isNotEmpty ? avatar : _currentUser!.avatar, // Keep existing if empty
        );
        debugPrint('[PROFILE_SERVICE] Local user updated with new avatar URL: $avatarUrl');
        debugPrint('[PROFILE_SERVICE] Local user avatar field: $avatar');
      }
      
      return avatarUrl;
    } catch (e) {
      debugPrint('[PROFILE_SERVICE] Failed to upload avatar: $e');
      rethrow;
    }
  }

  // Update avatar (legacy path for default avatars)
  Future<String> updateAvatar(String avatarPath) async {
    try {
      if (avatarPath.isEmpty) {
        throw Exception('Avatar path cannot be empty');
      }
      // Call API to update avatar - use updateProfile with only avatar field
      await updateProfile(avatar: avatarPath);
      return avatarPath;
    } catch (e) {
      rethrow;
    }
  }

  // Get user details
  User? getUserDetails() {
    return _currentUser;
  }

  // Clear profile data
  void clearProfile() {
    _currentUser = null;
  }
}
