import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/theme/app_theme.dart';

class ProfilePhotoScreen extends StatefulWidget {
  final String currentAvatar;

  const ProfilePhotoScreen({
    super.key,
    required this.currentAvatar,
  });

  @override
  State<ProfilePhotoScreen> createState() => _ProfilePhotoScreenState();
}

class _ProfilePhotoScreenState extends State<ProfilePhotoScreen> {
  late String _selectedPhoto;
  final List<String> defaultAvatars = [
    'AM', 'BN', 'CD', 'DT', 'ES', 'FG', 'HI', 'JK',
    'LM', 'NO', 'PQ', 'RS', 'TU', 'VW', 'XY', 'ZZ'
  ];

  @override
  void initState() {
    super.initState();
    _selectedPhoto = widget.currentAvatar;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('Change Profile Photo'),
        actions: [
          TextButton(
            onPressed: _selectedPhoto != widget.currentAvatar
                ? () {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Profile photo updated'),
                        backgroundColor: AppTheme.successGreen,
                      ),
                    );
                    context.pop(_selectedPhoto);
                  }
                : null,
            child: const Text(
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
            // Preview
            Center(
              child: Column(
                children: [
                  Text(
                    'Preview',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          letterSpacing: 1.2,
                          fontWeight: FontWeight.w600,
                        ),
                  ),
                  const SizedBox(height: 12),
                  CircleAvatar(
                    radius: 60,
                    backgroundColor: AppTheme.primaryCyan,
                    child: Text(
                      _selectedPhoto,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 32,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 32),
            // Upload options
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Column(
                children: [
                  ElevatedButton.icon(
                    onPressed: () {
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                          content: Text('Photo library access granted'),
                          backgroundColor: AppTheme.successGreen,
                        ),
                      );
                    },
                    icon: const Icon(Icons.photo_library),
                    label: const Text('Choose from Gallery'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppTheme.primaryCyan,
                      foregroundColor: Colors.white,
                      minimumSize: const Size(double.infinity, 48),
                    ),
                  ),
                  const SizedBox(height: 12),
                  ElevatedButton.icon(
                    onPressed: () {
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                          content: Text('Camera access granted'),
                          backgroundColor: AppTheme.successGreen,
                        ),
                      );
                    },
                    icon: const Icon(Icons.camera_alt),
                    label: const Text('Take a Photo'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppTheme.cardDark,
                      foregroundColor: AppTheme.primaryCyan,
                      minimumSize: const Size(double.infinity, 48),
                      side: const BorderSide(color: AppTheme.primaryCyan),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 32),
            // Default avatars
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  'DEFAULT AVATARS',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        letterSpacing: 1.2,
                        fontWeight: FontWeight.w600,
                      ),
                ),
              ),
            ),
            const SizedBox(height: 16),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: GridView.builder(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                  crossAxisCount: 4,
                  mainAxisSpacing: 16,
                  crossAxisSpacing: 16,
                ),
                itemCount: defaultAvatars.length,
                itemBuilder: (context, index) {
                  final avatar = defaultAvatars[index];
                  final isSelected = _selectedPhoto == avatar;

                  return InkWell(
                    onTap: () {
                      setState(() {
                        _selectedPhoto = avatar;
                      });
                    },
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        CircleAvatar(
                          radius: 32,
                          backgroundColor: isSelected
                              ? AppTheme.primaryCyan
                              : AppTheme.cardDark,
                          child: Text(
                            avatar,
                            style: const TextStyle(
                              color: Colors.white,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                        if (isSelected)
                          Container(
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: AppTheme.primaryCyan,
                                width: 3,
                              ),
                            ),
                            width: 64,
                            height: 64,
                          ),
                      ],
                    ),
                  );
                },
              ),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }
}
