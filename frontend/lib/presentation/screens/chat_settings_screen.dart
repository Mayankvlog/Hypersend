import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/constants/app_strings.dart';
import '../../core/theme/app_theme.dart';
import '../../data/mock/mock_data.dart';

class ChatSettingsScreen extends StatefulWidget {
  const ChatSettingsScreen({super.key});

  @override
  State<ChatSettingsScreen> createState() => _ChatSettingsScreenState();
}

class _ChatSettingsScreenState extends State<ChatSettingsScreen> {
  bool _isMuted = false;

  void _showFeatureMessage(String featureName) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('You tapped $featureName'),
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  Future<void> _confirmDangerAction({
    required String title,
    required String message,
    required String actionLabel,
  }) async {
    final confirmed = await showDialog<bool>(
          context: context,
          builder: (dialogContext) {
            return AlertDialog(
              title: Text(title),
              content: Text(message),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(false),
                  child: const Text('Cancel'),
                ),
                TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(true),
                  child: Text(
                    actionLabel,
                    style: const TextStyle(color: AppTheme.errorRed),
                  ),
                ),
              ],
            );
          },
        ) ??
        false;

    if (confirmed) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('$title action completed'),
          behavior: SnackBarBehavior.floating,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final user = MockData.settingsUser;

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text(AppStrings.chatSettings),
        actions: [
          TextButton(
            onPressed: () => context.push('/profile-edit'),
            child: const Text(
              AppStrings.edit,
              style: TextStyle(color: AppTheme.primaryCyan),
            ),
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            const SizedBox(height: 24),
            // Profile section
            Stack(
              children: [
                CircleAvatar(
                  radius: 60,
                  backgroundColor: AppTheme.cardDark,
                  backgroundImage: user.avatarUrl != null
                      ? NetworkImage(user.avatarUrl!)
                      : null,
                  onBackgroundImageError: (exception, stackTrace) {
                    // Fallback handled by child
                  },
                  child: user.avatarUrl != null
                      ? null
                      : Center(
                          // FIXED: Never show initials to prevent 2 words avatar
                          child: user.initials.isNotEmpty
                              ? Text(
                                  user.initials,
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontSize: 28,
                                    fontWeight: FontWeight.w600,
                                  ),
                                )
                              : null,
                        ),
                ),
                if (user.isOnline)
                  Positioned(
                    right: 4,
                    bottom: 4,
                    child: Container(
                      width: 20,
                      height: 20,
                      decoration: BoxDecoration(
                        color: AppTheme.successGreen,
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: AppTheme.backgroundDark,
                          width: 3,
                        ),
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 16),
            Text(
              user.name,
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            const SizedBox(height: 4),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(
                  user.username,
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
                const Text(' • ', style: TextStyle(color: AppTheme.textSecondary)),
                const Text(
                  AppStrings.online,
                  style: TextStyle(color: AppTheme.primaryCyan),
                ),
              ],
            ),
            const SizedBox(height: 32),
            // Action buttons
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  _ActionButton(
                    icon: Icons.search,
                    label: AppStrings.search,
                    onTap: () => _showFeatureMessage(AppStrings.search),
                  ),
                  _ActionButton(
                    icon: Icons.image_outlined,
                    label: AppStrings.media,
                    onTap: () => _showFeatureMessage(AppStrings.media),
                  ),
                  _ActionButton(
                    icon: Icons.share_outlined,
                    label: AppStrings.share,
                    onTap: () => _showFeatureMessage(AppStrings.share),
                  ),
                  _ActionButton(
                    icon: Icons.more_horiz,
                    label: AppStrings.more,
                    onTap: () => _showFeatureMessage(AppStrings.more),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 32),
            // Notifications section
            _SectionHeader(title: AppStrings.notifications),
            _SettingsTile(
              icon: Icons.notifications_off_outlined,
              title: AppStrings.muteNotifications,
              trailing: Switch(
                value: _isMuted,
                onChanged: (value) {
                  setState(() {
                    _isMuted = value;
                  });
                },
                activeTrackColor: AppTheme.primaryCyan,
              ),
            ),
            _SettingsTile(
              icon: Icons.music_note_outlined,
              title: AppStrings.customSound,
              subtitle: AppStrings.hypersendNote,
              trailing: const Icon(
                Icons.chevron_right,
                color: AppTheme.textSecondary,
              ),
              onTap: () => _showFeatureMessage(AppStrings.customSound),
            ),
            const SizedBox(height: 24),
            // Content & Privacy section
            _SectionHeader(title: AppStrings.contentPrivacy),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Column(
                children: [
                  Row(
                    children: [
                      const Icon(
                        Icons.grid_view_outlined,
                        color: AppTheme.primaryCyan,
                        size: 20,
                      ),
                      const SizedBox(width: 12),
                      const Text(
                        AppStrings.sharedMedia,
                        style: TextStyle(fontSize: 16),
                      ),
                      const Spacer(),
                      TextButton(
                        onPressed: () {},
                        child: const Text(
                          AppStrings.seeAll,
                          style: TextStyle(color: AppTheme.primaryCyan),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    height: 100,
                    child: ListView(
                      scrollDirection: Axis.horizontal,
                      children: [
                        _MediaThumbnail(
                          color: Colors.amber,
                          child: const Icon(Icons.image, color: Colors.white),
                        ),
                        _MediaThumbnail(
                          color: Colors.grey[800]!,
                          child: const Icon(Icons.code, color: Colors.white),
                        ),
                        _MediaThumbnail(
                          color: Colors.brown[700]!,
                          child: const Icon(Icons.radio, color: Colors.white),
                        ),
                        Container(
                          width: 100,
                          margin: const EdgeInsets.only(right: 12),
                          decoration: BoxDecoration(
                            color: AppTheme.cardDark,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: const Center(
                            child: Text(
                              '+42',
                              style: TextStyle(
                                color: AppTheme.textSecondary,
                                fontSize: 18,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            _SettingsTile(
              icon: Icons.timer_outlined,
              iconColor: Colors.orange,
              title: AppStrings.autoDeleteMessages,
              subtitle: AppStrings.off,
              trailing: const Icon(
                Icons.chevron_right,
                color: AppTheme.textSecondary,
              ),
              onTap: () =>
                  _showFeatureMessage(AppStrings.autoDeleteMessages),
            ),
            _SettingsTile(
              icon: Icons.fingerprint,
              iconColor: Colors.teal,
              title: AppStrings.encryptionKeys,
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: const [
                  Icon(
                    Icons.check_circle,
                    color: Colors.teal,
                    size: 20,
                  ),
                  SizedBox(width: 8),
                  Icon(
                    Icons.chevron_right,
                    color: AppTheme.textSecondary,
                  ),
                ],
              ),
              onTap: () =>
                  _showFeatureMessage(AppStrings.encryptionKeys),
            ),
            const SizedBox(height: 32),
            // Danger zone
            TextButton(
              onPressed: () => _confirmDangerAction(
                title: AppStrings.blockUser,
                message:
                    'Are you sure you want to block this user? You will no longer receive messages from them.',
                actionLabel: AppStrings.blockUser,
              ),
              child: const Text(
                AppStrings.blockUser,
                style: TextStyle(
                  color: AppTheme.errorRed,
                  fontSize: 16,
                ),
              ),
            ),
            const SizedBox(height: 8),
            TextButton(
              onPressed: () => _confirmDangerAction(
                title: AppStrings.deleteChat,
                message:
                    'Are you sure you want to delete this chat? This action cannot be undone.',
                actionLabel: AppStrings.deleteChat,
              ),
              child: const Text(
                AppStrings.deleteChat,
                style: TextStyle(
                  color: AppTheme.errorRed,
                  fontSize: 16,
                ),
              ),
            ),
            const SizedBox(height: 32),
            // Footer
            Text(
              'hypersend v1.0.0 • Chat ID: 893420',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  final String title;

  const _SectionHeader({required this.title});

  @override
  Widget build(BuildContext context) {
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
}

class _ActionButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;

  const _ActionButton({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Column(
        children: [
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: AppTheme.cardDark,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(icon, color: AppTheme.textPrimary),
          ),
          const SizedBox(height: 8),
          Text(
            label,
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      ),
    );
  }
}

class _SettingsTile extends StatelessWidget {
  final IconData icon;
  final Color? iconColor;
  final String title;
  final String? subtitle;
  final Widget? trailing;
  final VoidCallback? onTap;

  const _SettingsTile({
    required this.icon,
    this.iconColor,
    required this.title,
    this.subtitle,
    this.trailing,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        child: Row(
          children: [
            Icon(
              icon,
              color: iconColor ?? AppTheme.primaryCyan,
              size: 24,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: const TextStyle(fontSize: 16),
                  ),
                  if (subtitle != null) ...[
                    const SizedBox(height: 2),
                    Text(
                      subtitle!,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ],
              ),
            ),
            if (trailing != null) trailing!,
          ],
        ),
      ),
    );
  }
}

class _MediaThumbnail extends StatelessWidget {
  final Color color;
  final Widget child;

  const _MediaThumbnail({
    required this.color,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 100,
      margin: const EdgeInsets.only(right: 12),
      decoration: BoxDecoration(
        color: color,
        borderRadius: BorderRadius.circular(12),
      ),
      child: child,
    );
  }
}