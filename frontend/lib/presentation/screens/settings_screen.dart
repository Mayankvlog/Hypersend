import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/constants/app_strings.dart';
import '../../core/theme/app_theme.dart';
import '../../data/services/service_provider.dart';
import '../../data/services/settings_service.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late AppLanguage _selectedLanguage;
  late bool _notificationsEnabled;

  @override
  void initState() {
    super.initState();
    final settings = serviceProvider.settingsService;
    _selectedLanguage = settings.currentLanguage;
    _notificationsEnabled = settings.notificationsEnabled;
  }

  Future<void> _changeLanguage(AppLanguage language) async {
    try {
      await serviceProvider.settingsService.changeLanguage(language);
      setState(() {
        _selectedLanguage = language;
      });
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Language changed to ${language.label}'),
          backgroundColor: AppTheme.successGreen,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Error: $e'),
          backgroundColor: AppTheme.errorRed,
        ),
      );
    }
  }

  Future<void> _toggleNotifications() async {
    try {
      await serviceProvider.settingsService.toggleNotifications();
      setState(() {
        _notificationsEnabled = !_notificationsEnabled;
      });
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e')),
      );
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
        title: const Text('Settings'),
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            const SizedBox(height: 16),
            // User profile summary section
            FutureBuilder<Map<String, dynamic>>(
              future: serviceProvider.apiService.getMe(),
              builder: (context, snapshot) {
                final user = serviceProvider.profileService.currentUser;
                if (user == null && snapshot.connectionState == ConnectionState.waiting) {
                  return const Center(child: CircularProgressIndicator());
                }
                
                final displayUser = user;
                if (displayUser == null) return const SizedBox();

                return Container(
                  padding: const EdgeInsets.all(16),
                  margin: const EdgeInsets.symmetric(horizontal: 16),
                  decoration: BoxDecoration(
                    color: AppTheme.cardDark,
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Row(
                    children: [
                      CircleAvatar(
                        radius: 32,
                        backgroundColor: AppTheme.backgroundDark,
                        backgroundImage: displayUser.isAvatarPath
                            ? NetworkImage(displayUser.fullAvatarUrl)
                            : null,
                        // FIXED: Never show initials to prevent 2 words avatar
                        child: !displayUser.isAvatarPath && displayUser.initials.isNotEmpty
                            ? Text(
                                displayUser.initials,
                                style: const TextStyle(color: Colors.white, fontSize: 18),
                              )
                            : null,
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              displayUser.name,
                              style: const TextStyle(
                                fontSize: 18,
                                fontWeight: FontWeight.bold,
                                color: Colors.white,
                              ),
                            ),
                            Text(
                              '@${displayUser.username}',
                              style: const TextStyle(
                                color: AppTheme.textSecondary,
                                fontSize: 14,
                              ),
                            ),
                          ],
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.edit_outlined, color: AppTheme.primaryCyan),
                        onPressed: () async {
                          final result = await context.push('/profile-edit');
                          if (result != null && mounted) {
                            setState(() {}); // Refresh if updated
                          }
                        },
                      ),
                    ],
                  ),
                );
              },
            ),
            const SizedBox(height: 24),
            // Language section
            _buildSectionHeader('LANGUAGE & REGION'),
            _buildLanguageSelector(),
            const SizedBox(height: 24),
            // Notifications section
            _buildSectionHeader('NOTIFICATIONS'),
            _buildSettingsTile(
              icon: Icons.notifications_outlined,
              title: 'Enable Notifications',
              trailing: Switch(
                value: _notificationsEnabled,
                onChanged: (_) => _toggleNotifications(),
                activeTrackColor: AppTheme.primaryCyan,
              ),
            ),
            _buildSettingsTile(
              icon: Icons.music_note_outlined,
              title: 'Notification Sound',
              subtitle: 'Default',
              onTap: () {
                context.push('/notification-sound');
              },
            ),
            const SizedBox(height: 24),
            // Privacy & Security section
            _buildSectionHeader('PRIVACY & SECURITY'),
            _buildSettingsTile(
              icon: Icons.lock_outlined,
              title: 'Privacy Settings',
              onTap: () {
                context.push('/privacy-settings');
              },
            ),
            _buildSettingsTile(
              icon: Icons.block_outlined,
              title: 'Blocked Users',
              subtitle: '3 users blocked',
              onTap: () {
                context.push('/blocked-users');
              },
            ),
            const SizedBox(height: 24),
            // Storage section
            _buildSectionHeader('STORAGE'),
            _buildSettingsTile(
              icon: Icons.storage_outlined,
              title: 'Storage Usage',
              subtitle: '256 MB used of 1 GB',
              onTap: () {
                context.push('/storage-manager');
              },
            ),
            _buildSettingsTile(
              icon: Icons.delete_sweep_outlined,
              title: 'Clear Cache',
              onTap: () {
                showDialog(
                  context: context,
                  builder: (context) => AlertDialog(
                    title: const Text('Clear Cache'),
                    content:
                        const Text('Are you sure you want to clear the cache?'),
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
                              content: Text('Cache cleared'),
                              backgroundColor: AppTheme.successGreen,
                            ),
                          );
                        },
                        child: const Text('Clear'),
                      ),
                    ],
                  ),
                );
              },
            ),
            const SizedBox(height: 24),
            // About section
            _buildSectionHeader('ABOUT'),
            _buildSettingsTile(
              icon: Icons.info_outlined,
              title: 'App Version',
              subtitle: '1.0.0',
            ),
            _buildSettingsTile(
              icon: Icons.description_outlined,
              title: 'Terms & Conditions',
              onTap: () {
                showDialog(
                  context: context,
                  builder: (dialogContext) => AlertDialog(
                    title: const Text('Terms & Conditions'),
                    content: const SingleChildScrollView(
                      child: Text(
                        'By using zaply, you agree to our Terms & Conditions.\n\n'
                        '1. Privacy: We protect your data with end-to-end encryption.\n'
                        '2. Usage: zaply is for personal use only.\n'
                        '3. Content: You are responsible for content you share.\n'
                        '4. Compliance: Follow all applicable laws and regulations.\n'
                        '5. Disclaimer: We are not liable for service interruptions.\n\n'
                        'For full terms, visit: terms.zaply.com',
                      ),
                    ),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.of(dialogContext).pop(),
                        child: const Text('Close'),
                      ),
                    ],
                  ),
                );
              },
            ),
            const SizedBox(height: 24),
            // Account section
            _buildSectionHeader('ACCOUNT'),
            _buildSettingsTile(
              icon: Icons.logout,
              title: AppStrings.logout,
              onTap: () {
                // Logout: return to auth screen
                context.go('/auth');
              },
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  Widget _buildSectionHeader(String title) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Align(
        alignment: Alignment.centerLeft,
        child: Text(
          title,
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                letterSpacing: 1.2,
                fontWeight: FontWeight.w600,
              ),
        ),
      ),
    );
  }

  Widget _buildLanguageSelector() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          for (final language
              in serviceProvider.settingsService.availableLanguages)
            InkWell(
              onTap: () => _changeLanguage(language),
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 12),
                child: Row(
                  children: [
                    Icon(
                      Icons.language,
                      color: _selectedLanguage == language
                          ? AppTheme.primaryCyan
                          : AppTheme.textSecondary,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        language.label,
                        style: TextStyle(
                          color: _selectedLanguage == language
                              ? AppTheme.primaryCyan
                              : AppTheme.textPrimary,
                          fontWeight: _selectedLanguage == language
                              ? FontWeight.w600
                              : FontWeight.normal,
                        ),
                      ),
                    ),
                    if (_selectedLanguage == language)
                      const Icon(
                        Icons.check_circle,
                        color: AppTheme.primaryCyan,
                      ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildSettingsTile({
    required IconData icon,
    required String title,
    String? subtitle,
    Widget? trailing,
    VoidCallback? onTap,
  }) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        child: Row(
          children: [
            Icon(icon, color: AppTheme.primaryCyan),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title),
                  if (subtitle != null) ...[
                    const SizedBox(height: 2),
                    Text(
                      subtitle,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ],
              ),
            ),
            if (trailing != null)
              trailing
            else if (onTap != null)
              const Icon(Icons.chevron_right, color: AppTheme.textSecondary),
          ],
        ),
      ),
    );
  }
}
