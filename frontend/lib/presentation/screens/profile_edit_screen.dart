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
  bool _isLoading = false;
  bool _nameChanged = false;
  bool _usernameChanged = false;
  bool _emailChanged = false;

  @override
  void initState() {
    super.initState();
    _nameController = TextEditingController(text: widget.user.name);
    _usernameController = TextEditingController(text: widget.user.username);
    // Initialize email from user email field if available, otherwise empty
    _emailController = TextEditingController(text: widget.user.email ?? '');
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
      // Validate name
      if (_nameController.text.isEmpty) {
        throw Exception('Name cannot be empty');
      }
      if (_nameController.text.length < 2) {
        throw Exception('Name must be at least 2 characters');
      }
      
      // Validate email format if email field is not empty
      String? emailToSend;
      if (_emailController.text.isNotEmpty) {
        // Check for valid email format: must have @ and a dot after @
        if (!_emailController.text.contains('@') || 
            !_emailController.text.contains('.') ||
            !_emailController.text.contains(RegExp(r'@[\w\.-]+\.\w+'))) {
          throw Exception('Please enter a valid email address (e.g., user@example.com)');
        }
        emailToSend = _emailController.text;
      }

      // Update profile
      final updatedUser = await serviceProvider.profileService.updateProfile(
        name: _nameController.text,
        username: _usernameController.text,
        avatar: widget.user.avatar,
        email: emailToSend,
      );

      if (!mounted) return;

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Profile updated successfully!'),
          backgroundColor: AppTheme.successGreen,
        ),
      );

      Future.delayed(const Duration(milliseconds: 500), () {
        if (mounted) {
          context.pop(updatedUser);
        }
      });
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Error: $e'),
          backgroundColor: AppTheme.errorRed,
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
            onPressed: (_nameChanged || _usernameChanged || _emailChanged) && !_isLoading
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
                  CircleAvatar(
                    radius: 60,
                    backgroundColor: AppTheme.cardDark,
                    child: Center(
                      child: Text(
                        widget.user.avatar.length > 2
                            ? widget.user.avatar.substring(0, 2).toUpperCase()
                            : widget.user.avatar.toUpperCase(),
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 28,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ),
                  Positioned(
                    bottom: 0,
                    right: 0,
                    child: InkWell(
                      onTap: () async {
                        final router = GoRouter.of(context);
                        final scaffoldMessenger = ScaffoldMessenger.of(context);
                        final result = await router.push('/profile-photo', extra: widget.user.avatar);
                        if (!mounted) return;
                        if (result != null) {
                          scaffoldMessenger.showSnackBar(
                            const SnackBar(
                              content: Text('Avatar updated'),
                              backgroundColor: AppTheme.successGreen,
                            ),
                          );
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
                  _nameChanged = value != widget.user.name;
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
                  _usernameChanged = value != widget.user.username;
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
                  _emailChanged = value != widget.user.username;
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
                    icon: Icons.email_outlined,
                    title: 'Change Email',
                    onTap: () {
                      _showChangeEmailDialog();
                    },
                  ),
                  _buildActionTile(
                    icon: Icons.vpn_key_outlined,
                    title: 'Reset Password',
                    onTap: () {
                      _showResetPasswordDialog();
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
            onPressed: () {
              if (newPasswordController.text == confirmPasswordController.text &&
                  newPasswordController.text.isNotEmpty) {
                Navigator.of(dialogContext).pop();
                if (!mounted) return;
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Password changed successfully'),
                    backgroundColor: AppTheme.successGreen,
                  ),
                );
              } else {
                if (!mounted) return;
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Passwords do not match'),
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

  // ignore: use_build_context_synchronously
  void _showChangeEmailDialog() {
    final emailController = TextEditingController(text: _emailController.text);
    final passwordController = TextEditingController();

    showDialog(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Change Email'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: emailController,
                keyboardType: TextInputType.emailAddress,
                decoration: const InputDecoration(
                  labelText: 'New Email',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: passwordController,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'Password (for verification)',
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
              final scaffoldMessenger = ScaffoldMessenger.of(context);
              if (emailController.text.contains('@') && passwordController.text.isNotEmpty) {
                try {
                  await serviceProvider.profileService.changeEmail(
                    newEmail: emailController.text,
                    password: passwordController.text,
                  );
                  Navigator.of(dialogContext).pop();
                  if (!mounted) return;
                  _emailController.text = emailController.text;
                  scaffoldMessenger.showSnackBar(
                    const SnackBar(
                      content: Text('Email updated successfully'),
                      backgroundColor: AppTheme.successGreen,
                    ),
                  );
                } catch (e) {
                  if (!mounted) return;
                  scaffoldMessenger.showSnackBar(
                    SnackBar(
                      content: Text('Error: $e'),
                      backgroundColor: AppTheme.errorRed,
                    ),
                  );
                }
              } else {
                if (!mounted) return;
                scaffoldMessenger.showSnackBar(
                  const SnackBar(
                    content: Text('Please enter valid email and password'),
                    backgroundColor: AppTheme.errorRed,
                  ),
                );
              }
              emailController.clear();
              passwordController.clear();
            },
            child: const Text('Update'),
          ),
        ],
      ),
    );
  }

  // ignore: use_build_context_synchronously
  void _showResetPasswordDialog() {
    final emailController = TextEditingController(text: _emailController.text);

    showDialog(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Reset Password'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('We will send a password reset link to:'),
            const SizedBox(height: 12),
            TextField(
              controller: emailController,
              keyboardType: TextInputType.emailAddress,
              decoration: const InputDecoration(
                labelText: 'Email Address',
                border: OutlineInputBorder(),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () async {
              final scaffoldMessenger = ScaffoldMessenger.of(context);
              if (emailController.text.contains('@')) {
                try {
                  await serviceProvider.profileService.resetPassword(
                    email: emailController.text,
                  );
                  Navigator.of(dialogContext).pop();
                  if (!mounted) return;
                  scaffoldMessenger.showSnackBar(
                    const SnackBar(
                      content: Text('Password reset link sent to your email'),
                      backgroundColor: AppTheme.successGreen,
                    ),
                  );
                } catch (e) {
                  if (!mounted) return;
                  scaffoldMessenger.showSnackBar(
                    SnackBar(
                      content: Text('Error: $e'),
                      backgroundColor: AppTheme.errorRed,
                    ),
                  );
                }
              } else {
                if (!mounted) return;
                scaffoldMessenger.showSnackBar(
                  const SnackBar(
                    content: Text('Please enter a valid email address'),
                    backgroundColor: AppTheme.errorRed,
                  ),
                );
              }
              emailController.clear();
            },
            child: const Text('Send'),
          ),
        ],
      ),
    );
  }
}
