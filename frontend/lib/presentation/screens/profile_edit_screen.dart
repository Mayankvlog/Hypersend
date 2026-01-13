import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/theme/app_theme.dart';
import '../../data/models/user.dart';
import '../../data/services/service_provider.dart';

class ProfileEditScreen extends StatefulWidget {
  final User user;

  const ProfileEditScreen({
    super.key,
    required this.user,
  });

  @override
  State<ProfileEditScreen> createState() => _ProfileEditScreenState();
}

class _ProfileEditScreenState extends State<ProfileEditScreen> {
  late TextEditingController _nameController;
  late TextEditingController _usernameController;
  late TextEditingController _emailController;
  late TextEditingController _statusController;
  late String _currentAvatar;
  late User _initialUser;  // Store the actual source for change comparison
  bool _isLoading = false;
  bool _nameChanged = false;
  bool _usernameChanged = false;
  bool _emailChanged = false;
  bool _avatarChanged = false;

  @override
  void initState() {
    super.initState();
    // Prefer service data if available, fallback to widget prop
    _initialUser = serviceProvider.profileService.currentUser ?? widget.user;
    
    _nameController = TextEditingController(text: _initialUser.name);
    _usernameController = TextEditingController(text: _initialUser.username);
    _currentAvatar = _initialUser.avatar;
    
    final userEmail = _initialUser.email ?? '';
    final isValidEmail = (userEmail.contains('@') && userEmail.contains('.'));
    _emailController = TextEditingController(text: isValidEmail ? userEmail : '');
    _statusController = TextEditingController(text: 'Available');
  }

  @override
  void dispose() {
    _nameController.dispose();
    _usernameController.dispose();
    _emailController.dispose();
    _statusController.dispose();
    super.dispose();
  }

Future<void> _saveProfile() async {
    setState(() {
      _isLoading = true;
    });

    try {
      // Only validate name if it's being changed
      if (_nameChanged) {
        if (_nameController.text.trim().isEmpty) {
          throw Exception('Name cannot be empty');
        }
        if (_nameController.text.trim().length < 2) {
          throw Exception('Name must be at least 2 characters');
        }
      }
      
      // Email is optional - only validate and send if changed and not empty
      String? emailToSend;
      final currentEmail = (widget.user.email ?? '').trim();
      final newEmail = _emailController.text.trim();
      
      if (newEmail.isNotEmpty && newEmail != currentEmail) {
// More lenient email validation: basic format check
        if (!RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(newEmail)) {
          throw Exception('Invalid email format. Example: user@example.com');
        }
        emailToSend = newEmail;
      }
      
      // Only pass username if changed from initial value
      String? usernameToSend;
      final currentUsername = widget.user.username.trim();
      final newUsername = _usernameController.text.trim();
      
      if (newUsername != currentUsername && newUsername.isNotEmpty) {
        usernameToSend = newUsername;
      }

      // Only pass name if changed from initial value  
      String? nameToSend;
      final currentName = _initialUser.name.trim();
      final newName = _nameController.text.trim();
      
      if (newName != currentName) {
        if (newName.isEmpty) {
          throw Exception('Name cannot be empty');
        }
        nameToSend = newName;
      }

// Status field is treated as bio
      String? bioToSend;
      final newBio = _statusController.text.trim();
      final currentBio = _initialUser.bio ?? 'Available'; // Use actual user bio from database
      
      if (newBio != currentBio) {
        // Validate bio length (optional but should have reasonable limits)
        if (newBio.length > 500) {
          throw Exception('Status is too long. Maximum 500 characters allowed.');
        }
        bioToSend = newBio.isEmpty ? null : newBio;
      }

      debugPrint('[PROFILE_EDIT] Sending profile update: fields=${[nameToSend != null, usernameToSend != null, emailToSend != null, _avatarChanged, bioToSend != null]}');

// Check if at least one field is being updated (including avatar)
      if (nameToSend == null && usernameToSend == null && emailToSend == null && !_avatarChanged && bioToSend == null) {
        debugPrint('[PROFILE_EDIT] No changes detected - skipping save');
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('No changes to save'),
            backgroundColor: AppTheme.textSecondary,
          ),
        );
        setState(() => _isLoading = false);
        return;
      }
      
      debugPrint('[PROFILE_EDIT] Validation: nameChanged=$_nameChanged, usernameChanged=$_usernameChanged, emailChanged=$_emailChanged, avatarChanged=$_avatarChanged');

// Disable save button to prevent race condition
      if (mounted) {
        setState(() => _isLoading = true);
      }

      // Update profile - use avatarUrl for image URLs, avatar for initials only
      final updatedUser = await serviceProvider.profileService.updateProfile(
        name: nameToSend,
        username: usernameToSend,
        avatarUrl: _avatarChanged && _currentAvatar.startsWith('/') ? _currentAvatar : null,
        email: emailToSend,
        bio: bioToSend,
      );

      if (!mounted) return;

      // Build success message with updated fields
      List<String> updatedFields = [];
      if (nameToSend != null) updatedFields.add('Name');
      if (usernameToSend != null) updatedFields.add('Username');
      if (emailToSend != null) updatedFields.add('Email');
      if (bioToSend != null) updatedFields.add('Status');
      if (_avatarChanged && _currentAvatar != _initialUser.avatar) updatedFields.add('Profile Photo');
      
      final successMessage = updatedFields.isNotEmpty 
          ? 'Saved! ${updatedFields.join(', ')} updated'
          : 'Profile updated successfully!';

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(successMessage),
          backgroundColor: AppTheme.successGreen,
          duration: const Duration(seconds: 2),
        ),
      );

      // Update state and navigation atomically
      setState(() {
        _nameChanged = false;
        _usernameChanged = false;
        _emailChanged = false;
        _avatarChanged = false;
        _isLoading = false;
      });

      // Navigate after ensuring state is updated
      await Future.delayed(const Duration(milliseconds: 300));
      if (mounted) {
        context.pop(updatedUser);
      }
    } catch (e) {
      if (!mounted) return;
      
// Extract meaningful error message
      String errorMessage = 'Error: ${e.toString()}';
      final errorString = e.toString().toLowerCase();
      
      // Check for specific error types with more precise matching
      if (errorString.contains('422')) {
        // Only show validation error if it's not related to avatar-only operations
        if (_avatarChanged && !_nameChanged && !_usernameChanged && !_emailChanged) {
          // Avatar-only operation - don't show generic validation error
          errorMessage = 'Profile picture update failed. Please try again.';
        } else if (errorString.contains('avatar') || errorString.contains('picture')) {
          errorMessage = 'Profile picture issue: Please check image format or try a different photo.';
        } else if (errorString.contains('email')) {
          errorMessage = 'Email issue: Please check if this email is already in use or invalid.';
        } else if (errorString.contains('username')) {
          errorMessage = 'Username issue: This username may be taken or invalid.';
        } else if (errorString.contains('name')) {
          errorMessage = 'Name issue: Please provide a valid name (2+ characters).';
        } else if (errorString.contains('bio') || errorString.contains('status') || errorString.contains('too long')) {
          errorMessage = 'Status issue: Please check your status message and try again.';
        } else {
          errorMessage = 'Validation error: Please check all fields and try again.';
        }
      } else if (errorString.contains('409')) {
        errorMessage = 'Email already in use. Please try another email.';
      } else if (e.toString().contains('401')) {
        errorMessage = 'Unauthorized. Please login again.';
      } else if (e.toString().contains('404')) {
        errorMessage = 'User not found. Please try again.';
      } else if (errorString.contains('email already')) {
        errorMessage = 'Email already in use. Please try another email.';
      } else if (errorString.contains('invalid email')) {
        errorMessage = 'Invalid email format. Use: user@example.com';
      } else if (errorString.contains('at least')) {
        errorMessage = e.toString();
      } else if (errorString.contains('avatar') && 
                 (errorString.contains('upload') || errorString.contains('image'))) {
        // Operator precedence: check avatar first, then upload OR image
        // Specific avatar upload errors
        errorMessage = 'Profile picture upload failed. Please try again.';
      } else if (_avatarChanged && !_nameChanged && !_usernameChanged && !_emailChanged) {
        // Avatar-only operation with unknown error
        errorMessage = 'Profile picture update failed. Please try again.';
      }
      
      debugPrint('[PROFILE_EDIT_ERROR] Error: $e');
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(errorMessage),
          backgroundColor: AppTheme.errorRed,
          duration: const Duration(seconds: 3),
        ),
      );
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('Edit Profile'),
        actions: [
          TextButton(
            onPressed: (_nameChanged || _usernameChanged || _emailChanged || _avatarChanged) && !_isLoading
                ? _saveProfile
                : null,
            child: _isLoading
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      valueColor: AlwaysStoppedAnimation<Color>(
                        AppTheme.primaryCyan,
                      ),
                    ),
                  )
                : const Text(
                    'Save',
                    style: TextStyle(color: AppTheme.primaryCyan),
                  ),
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            const SizedBox(height: 24),
            // Avatar section
            Center(
              child: Stack(
                children: [
                   Builder(
                    builder: (context) {
                      // FIXED: Preserve actual avatar URL in tempUser so fullAvatarUrl works correctly
                      final tempUser = _initialUser.copyWith(
                        avatar: _currentAvatar.isNotEmpty ? _currentAvatar : _initialUser.avatar
                      );
                      // FIXED: Check if _currentAvatar is a URL by examining its content
                      final isUrl = _currentAvatar.isNotEmpty && 
                          (_currentAvatar.startsWith('http') || _currentAvatar.startsWith('/'));
                      // FIXED: Always use tempUser.initials - no redundant ternary needed
                      final displayInitials = tempUser.initials;
                                         
                      return CircleAvatar(
                        radius: 60,
                        backgroundColor: AppTheme.primaryCyan,
                        backgroundImage: isUrl && tempUser.fullAvatarUrl.isNotEmpty
                            ? NetworkImage(tempUser.fullAvatarUrl)
                            : null,
                        onBackgroundImageError: isUrl 
                            ? (e, s) {
                                debugPrint('Avatar image load failed: $e');
                                debugPrint('Image source: ${tempUser.fullAvatarUrl}');
                              }
                            : null,
                        child: Center(
                          child: Text(
                            displayInitials,
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 28,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      );
                    }
                  ),
                  Positioned(
                    bottom: 0,
                    right: 0,
                    child: InkWell(
                      onTap: () async {
                        final router = GoRouter.of(context);
                        final scaffoldMessenger = ScaffoldMessenger.of(context);
final result = await router.push('/profile-photo', extra: _currentAvatar);
                        if (!mounted) return;
if (result != null && result is String) {
                          debugPrint('[PROFILE_EDIT] Avatar updated successfully');
                          setState(() {
                            final newAvatar = result.trim();
                            // Only mark as changed if avatar actually changed
                            _avatarChanged = newAvatar != _currentAvatar;
                            _currentAvatar = ''; // ALWAYS clear to empty string when image is uploaded
                          });
                          
                          // Show success message
                          scaffoldMessenger.showSnackBar(
                            const SnackBar(
                              content: Text('Profile photo updated. Click "Save" to apply changes.'),
                              backgroundColor: AppTheme.successGreen,
                              duration: Duration(seconds: 3),
                            ),
                          );
                        } else {
                          debugPrint('[PROFILE_EDIT] Avatar update cancelled or failed');
                        }
                      },
                      child: Container(
                        padding: const EdgeInsets.all(8),
                        decoration: const BoxDecoration(
                          color: AppTheme.primaryCyan,
                          shape: BoxShape.circle,
                        ),
                        child: const Icon(
                          Icons.camera_alt,
                          color: Colors.white,
                          size: 16,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 32),
            // Name field
            _buildProfileField(
              label: 'Full Name',
              controller: _nameController,
              icon: Icons.person_outline,
              onChanged: (value) {
                setState(() {
                  _nameChanged = value.trim() != _initialUser.name.trim();
                });
              },
            ),
            const SizedBox(height: 16),
            // Username field
            _buildProfileField(
              label: 'Username',
              controller: _usernameController,
              icon: Icons.alternate_email,
              onChanged: (value) {
                setState(() {
                  _usernameChanged = value.trim() != _initialUser.username.trim();
                });
              },
            ),
            const SizedBox(height: 16),
            // Email field (editable)
            _buildProfileField(
              label: 'Email',
              controller: _emailController,
              icon: Icons.email_outlined,
              readOnly: false,
              onChanged: (value) {
                setState(() {
                  _emailChanged = value.trim() != (_initialUser.email ?? '').trim();
                });
              },
            ),
            const SizedBox(height: 16),
            // Status field
            _buildProfileField(
              label: 'Status',
              controller: _statusController,
              icon: Icons.comment_outlined,
              onChanged: (_) {},
            ),
            const SizedBox(height: 32),
            // Account actions
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'ACCOUNT',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          letterSpacing: 1.2,
                          fontWeight: FontWeight.w600,
                        ),
                  ),
                  const SizedBox(height: 8),
                  _buildActionTile(
                    icon: Icons.lock_outline,
                    title: 'Change Password',
                    onTap: () {
                      _showChangePasswordDialog();
                    },
                  ),
                  _buildActionTile(
                    icon: Icons.delete_outline,
                    title: 'Delete Account',
                    titleColor: AppTheme.errorRed,
                    onTap: () {
                      _showDeleteAccountDialog();
                    },
                  ),
                ],
              ),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  Widget _buildProfileField({
    required String label,
    required TextEditingController controller,
    required IconData icon,
    bool readOnly = false,
    Function(String)? onChanged,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: TextField(
        controller: controller,
        readOnly: readOnly,
        onChanged: onChanged,
        decoration: InputDecoration(
          labelText: label,
          prefixIcon: Icon(icon, color: AppTheme.textSecondary),
          suffixIcon: readOnly
              ? const Icon(Icons.lock, color: AppTheme.textSecondary, size: 18)
              : null,
        ),
      ),
    );
  }

  Widget _buildActionTile({
    required IconData icon,
    required String title,
    Color titleColor = AppTheme.textPrimary,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 12),
        child: Row(
          children: [
            Icon(icon, color: titleColor),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                title,
                style: TextStyle(color: titleColor),
              ),
            ),
            const Icon(Icons.chevron_right, color: AppTheme.textSecondary),
          ],
        ),
      ),
    );
  }

  void _showDeleteAccountDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Account'),
        content: const Text(
          'Are you sure you want to delete your account? This action cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              Navigator.of(context).pop();
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Account deleted successfully'),
                  backgroundColor: AppTheme.successGreen,
                ),
              );
            },
            child: const Text(
              'Delete',
              style: TextStyle(color: AppTheme.errorRed),
            ),
          ),
        ],
      ),
    );
  }

  void _showChangePasswordDialog() {
    final oldPasswordController = TextEditingController();
    final newPasswordController = TextEditingController();
    final confirmPasswordController = TextEditingController();

    showDialog(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Change Password'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: oldPasswordController,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'Current Password',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: newPasswordController,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'New Password',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: confirmPasswordController,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'Confirm Password',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () async {
              if (newPasswordController.text == confirmPasswordController.text &&
                  newPasswordController.text.isNotEmpty) {
                if (newPasswordController.text.length < 8) {
                   ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Password must be at least 8 characters'),
                      backgroundColor: AppTheme.errorRed,
                    ),
                  );
                  return;
                }

                Navigator.of(dialogContext).pop();
                
                setState(() => _isLoading = true);
                try {
                  await serviceProvider.profileService.changePassword(
                    oldPassword: oldPasswordController.text,
                    newPassword: newPasswordController.text,
                  );
                  
                  if (!mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Password changed successfully'),
                      backgroundColor: AppTheme.successGreen,
                    ),
                  );
                } catch (e) {
                  if (!mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('Failed to change password: ${e.toString()}'),
                      backgroundColor: AppTheme.errorRed,
                    ),
                  );
                } finally {
                  if (mounted) setState(() => _isLoading = false);
                }
              } else {
                if (!mounted) return;
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Passwords do not match or are empty'),
                    backgroundColor: AppTheme.errorRed,
                  ),
                );
              }
              oldPasswordController.clear();
              newPasswordController.clear();
              confirmPasswordController.clear();
            },
            child: const Text('Change'),
          ),
        ],
      ),
    );
  }

  }
