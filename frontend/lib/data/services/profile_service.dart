import '../models/user.dart';

class ProfileService {
  User? _currentUser;

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
      _currentUser = _currentUser!.copyWith(
        name: name ?? _currentUser!.name,
        username: username ?? _currentUser!.username,
        avatar: avatar ?? _currentUser!.avatar,
      );
      return _currentUser!;
    } catch (e) {
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
      // Simulate password change - in real app, validate old password against hash
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
      // Simulate sending reset email
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
      // Simulate email change - in real app, verify password and update
      if (_currentUser != null) {
        // Update user email in memory (in real app, send to backend)
        _currentUser = _currentUser!.copyWith(
          username: newEmail.split('@')[0], // Use email prefix as username update reference
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
