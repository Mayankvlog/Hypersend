import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/theme/app_theme.dart';

class PrivacySettingsScreen extends StatefulWidget {
  const PrivacySettingsScreen({super.key});

  @override
  State<PrivacySettingsScreen> createState() => _PrivacySettingsScreenState();
}

class _PrivacySettingsScreenState extends State<PrivacySettingsScreen> {
  late bool _allowMessagesFromAnyone;
  late bool _showOnlineStatus;
  late bool _showReadReceipts;
  late bool _allowGroupInvites;
  late bool _shareActivity;

  @override
  void initState() {
    super.initState();
    _allowMessagesFromAnyone = true;
    _showOnlineStatus = true;
    _showReadReceipts = true;
    _allowGroupInvites = true;
    _shareActivity = false;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('Privacy Settings'),
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            const SizedBox(height: 24),
            _buildSectionHeader('WHO CAN CONTACT YOU'),
            _buildToggleTile(
              icon: Icons.mail_outline,
              title: 'Allow Messages from Anyone',
              value: _allowMessagesFromAnyone,
              onChanged: (value) {
                setState(() {
                  _allowMessagesFromAnyone = value;
                });
              },
            ),
            _buildToggleTile(
              icon: Icons.people_outline,
              title: 'Allow Group Invites',
              value: _allowGroupInvites,
              onChanged: (value) {
                setState(() {
                  _allowGroupInvites = value;
                });
              },
            ),
            const SizedBox(height: 24),
            _buildSectionHeader('YOUR STATUS'),
            _buildToggleTile(
              icon: Icons.online_prediction,
              title: 'Show Online Status',
              subtitle: 'Others can see when you are online',
              value: _showOnlineStatus,
              onChanged: (value) {
                setState(() {
                  _showOnlineStatus = value;
                });
              },
            ),
            _buildToggleTile(
              icon: Icons.done_all,
              title: 'Show Read Receipts',
              subtitle: 'Others can see when you read messages',
              value: _showReadReceipts,
              onChanged: (value) {
                setState(() {
                  _showReadReceipts = value;
                });
              },
            ),
            _buildToggleTile(
              icon: Icons.analytics_outlined,
              title: 'Share Activity Status',
              subtitle: 'Share what you\'re doing on Hypersend',
              value: _shareActivity,
              onChanged: (value) {
                setState(() {
                  _shareActivity = value;
                });
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

  Widget _buildToggleTile({
    required IconData icon,
    required String title,
    String? subtitle,
    required bool value,
    required ValueChanged<bool> onChanged,
  }) {
    return Padding(
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
          Switch(
            value: value,
            onChanged: onChanged,
            activeTrackColor: AppTheme.primaryCyan,
          ),
        ],
      ),
    );
  }
}
