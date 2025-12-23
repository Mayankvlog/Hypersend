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

  // Update user profile
  Future<User> updateProfile({
    String? name,
    String? username,
    String? avatar,
    String? email,
  }) async {
    if (_currentUser == null) {
      throw Exception('No user logged in');
    }

    try {
      // Validate name
      if ((name ?? '').isEmpty && _currentUser!.name.isEmpty) {
        throw Exception('Name cannot be empty');
      }
      if ((name ?? '').isNotEmpty && name!.length < 2) {
        throw Exception('Name must be at least 2 characters');
      }

      print('[PROFILE_UPDATE] Starting profile update');
      print('[PROFILE_UPDATE] Fields: name=$name, email=$email, username=$username');
      
      // Call API to update profile
      final response = await _apiService.updateProfile({
        if (name != null) 'name': name,
        if (username != null) 'username': username,
        if (avatar != null) 'avatar': avatar,
        if (email != null) 'email': email,
      });
      
      print('[PROFILE_UPDATE] API response: $response');

      // Update local user object
      _currentUser = _currentUser!.copyWith(
        name: name ?? _currentUser!.name,
        username: username ?? _currentUser!.username,
        email: email ?? _currentUser!.email,
        avatar: avatar ?? _currentUser!.avatar,
      );
      print('[PROFILE_UPDATE] Local user updated successfully');
      return _currentUser!;
    } catch (e) {
      print('[PROFILE_UPDATE_ERROR] Failed: $e');
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
          username: newEmail.split('@')[0],
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
      // Call API to change username
      await _apiService.updateProfile({'username': newUsername});
      _currentUser = _currentUser!.copyWith(username: newUsername);
      return true;
    } catch (e) {
      rethrow;
    }
  }

  // Update avatar
  Future<String> updateAvatar(String avatarPath) async {
    try {
      if (avatarPath.isEmpty) {
        throw Exception('Avatar path cannot be empty');
      }
      // Call API to update avatar
      await _apiService.updateProfile({'avatar': avatarPath});
      _currentUser = _currentUser!.copyWith(avatar: avatarPath);
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
