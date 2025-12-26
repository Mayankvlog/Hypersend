import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import '../../core/theme/app_theme.dart';
import '../../data/services/service_provider.dart';

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
  bool _isUploading = false;
  Uint8List? _pickedFileBytes;
  String? _pickedFileName;

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
            onPressed: (_selectedPhoto != widget.currentAvatar || _pickedFileBytes != null) && !_isUploading
                ? _handleSave
                : null,
            child: _isUploading
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
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
                    backgroundImage: _pickedFileBytes != null
                        ? MemoryImage(_pickedFileBytes!)
                        : null,
                    child: _pickedFileBytes == null
                        ? Text(
                            _selectedPhoto,
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 32,
                              fontWeight: FontWeight.w600,
                            ),
                          )
                        : null,
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
                    onPressed: _pickImage,
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

Future<void> _pickImage() async {
    try {
      debugPrint('[PROFILE_PHOTO] Picking image...');
      final result = await FilePicker.platform.pickFiles(
        type: FileType.image,
        withData: true,
        allowMultiple: false,
      );

      if (result != null && result.files.single.bytes != null) {
        final file = result.files.single;
        debugPrint('[PROFILE_PHOTO] Image picked: ${file.name} (${file.bytes?.length} bytes)');
        
        // Validate file size (max 5MB)
        if (file.bytes != null && file.bytes!.length > 5 * 1024 * 1024) {
          throw Exception('Image size must be less than 5MB');
        }
        
        setState(() {
          _pickedFileBytes = file.bytes;
          _pickedFileName = file.name;
        });
        
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Image selected successfully'),
              backgroundColor: AppTheme.successGreen,
            ),
          );
        }
      } else {
        debugPrint('[PROFILE_PHOTO] No image selected');
      }
    } catch (e) {
      debugPrint('[PROFILE_PHOTO] Error picking image: $e');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Error selecting image: ${e.toString()}'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

Future<void> _handleSave() async {
    setState(() => _isUploading = true);
    try {
      String resultValue;
      
      if (_pickedFileBytes != null && _pickedFileName != null) {
        debugPrint('[PROFILE_PHOTO] Uploading new avatar image...');
        // Upload file
        resultValue = await serviceProvider.profileService.uploadAvatar(
          _pickedFileBytes!,
          _pickedFileName!,
        );
        debugPrint('[PROFILE_PHOTO] Avatar uploaded successfully: $resultValue');
      } else {
        debugPrint('[PROFILE_PHOTO] Updating avatar to: $_selectedPhoto');
        // Just update initials
        await serviceProvider.profileService.updateAvatar(_selectedPhoto);
        resultValue = _selectedPhoto;
        debugPrint('[PROFILE_PHOTO] Avatar initials updated successfully');
      }

      if (!mounted) return;
      
      // Show success message
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Profile photo updated successfully'),
          backgroundColor: AppTheme.successGreen,
          duration: Duration(seconds: 2),
        ),
      );
      
      // Navigate back with result
      Future.delayed(const Duration(milliseconds: 500), () {
        if (mounted) {
          context.pop(resultValue);
        }
      });
      
    } catch (e) {
      debugPrint('[PROFILE_PHOTO] Failed to update photo: $e');
      if (!mounted) return;
      
      String errorMessage = 'Failed to update profile photo';
      if (e.toString().contains('File must be an image')) {
        errorMessage = 'Please select a valid image file';
      } else if (e.toString().contains('size must be less than')) {
        errorMessage = 'Image size must be less than 5MB';
      } else if (e.toString().contains('timeout')) {
        errorMessage = 'Upload timeout. Please check your connection and try again';
      } else if (e.toString().isNotEmpty) {
        errorMessage = e.toString();
      }
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(errorMessage),
          backgroundColor: Colors.red,
          duration: const Duration(seconds: 3),
        ),
      );
    } finally {
      if (mounted) setState(() => _isUploading = false);
    }
  }
}
