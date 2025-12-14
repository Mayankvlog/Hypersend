import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/constants/app_strings.dart';
import '../../core/theme/app_theme.dart';
import '../../data/models/permission.dart';

class PermissionsScreen extends StatefulWidget {
  const PermissionsScreen({super.key});

  @override
  State<PermissionsScreen> createState() => _PermissionsScreenState();
}

class _PermissionsScreenState extends State<PermissionsScreen> {
  final List<Permission> _permissions = [
    const Permission(
      id: 'contacts',
      title: AppStrings.contactsPermission,
      description: AppStrings.contactsDescription,
      icon: Icons.person_outline,
      isGranted: true,
    ),
    const Permission(
      id: 'location',
      title: AppStrings.locationPermission,
      description: AppStrings.locationDescription,
      icon: Icons.location_on_outlined,
    ),
    const Permission(
      id: 'camera',
      title: AppStrings.cameraPermission,
      description: AppStrings.cameraDescription,
      icon: Icons.camera_alt_outlined,
    ),
    const Permission(
      id: 'microphone',
      title: AppStrings.microphonePermission,
      description: AppStrings.microphoneDescription,
      icon: Icons.mic_outlined,
    ),
    const Permission(
      id: 'files',
      title: AppStrings.filesPermission,
      description: AppStrings.filesDescription,
      icon: Icons.folder_outlined,
    ),
    const Permission(
      id: 'phone',
      title: AppStrings.phonePermission,
      description: AppStrings.phoneDescription,
      icon: Icons.phone_outlined,
      isGranted: true,
    ),
  ];

  void _togglePermission(int index) {
    setState(() {
      _permissions[index] = _permissions[index].copyWith(
        isGranted: !_permissions[index].isGranted,
      );
    });
  }

  void _startMessaging() {
    context.go('/chats');
  }

  void _skipForNow() {
    context.go('/chats');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(AppTheme.spacing24),
          child: Column(
            children: [
              const SizedBox(height: 40),
              // Shield icon
              Container(
                width: 120,
                height: 120,
                decoration: BoxDecoration(
                  color: AppTheme.cardDark,
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.shield_outlined,
                  size: 60,
                  color: AppTheme.primaryCyan,
                ),
              ),
              const SizedBox(height: 32),
              // Title
              Text(
                AppStrings.enableAccess,
                style: Theme.of(context).textTheme.headlineMedium,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              // Description
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Text(
                  AppStrings.permissionsDescription,
                  style: Theme.of(context).textTheme.bodyMedium,
                  textAlign: TextAlign.center,
                ),
              ),
              const SizedBox(height: 40),
              // Permission list
              Expanded(
                child: ListView.separated(
                  itemCount: _permissions.length,
                  separatorBuilder: (context, index) =>
                      const SizedBox(height: 16),
                  itemBuilder: (context, index) {
                    final permission = _permissions[index];
                    return _PermissionItem(
                      permission: permission,
                      onToggle: () => _togglePermission(index),
                    );
                  },
                ),
              ),
              const SizedBox(height: 24),
              // Start Messaging button
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: _startMessaging,
                  child: const Text(
                    AppStrings.startMessaging,
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              // Skip button
              TextButton(
                onPressed: _skipForNow,
                child: Text(
                  AppStrings.skipForNow,
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _PermissionItem extends StatelessWidget {
  final Permission permission;
  final VoidCallback onToggle;

  const _PermissionItem({
    required this.permission,
    required this.onToggle,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(AppTheme.spacing16),
      decoration: BoxDecoration(
        color: AppTheme.cardDark.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(AppTheme.borderRadiusCard),
      ),
      child: Row(
        children: [
          // Icon
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: AppTheme.inputBackground,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(
              permission.icon,
              color: AppTheme.primaryCyan,
              size: 28,
            ),
          ),
          const SizedBox(width: 16),
          // Title and description
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  permission.title,
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                const SizedBox(height: 4),
                Text(
                  permission.description,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ],
            ),
          ),
          const SizedBox(width: 16),
          // Toggle switch
          Switch(
            value: permission.isGranted,
            onChanged: (_) => onToggle(),
            activeTrackColor: AppTheme.primaryCyan,
            inactiveThumbColor: AppTheme.textSecondary,
            inactiveTrackColor: AppTheme.inputBackground,
          ),
        ],
      ),
    );
  }
}