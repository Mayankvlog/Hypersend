import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import '../../core/theme/app_theme.dart';
import '../../core/constants/api_constants.dart';
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
            onPressed: () {
              debugPrint('[PROFILE_PHOTO] Save button pressed');
              debugPrint('[PROFILE_PHOTO] _selectedPhoto=$_selectedPhoto, currentAvatar=${widget.currentAvatar}');
              debugPrint('[PROFILE_PHOTO] _pickedFileBytes=${_pickedFileBytes != null ? "not null" : "null"}');
              debugPrint('[PROFILE_PHOTO] _isUploading=$_isUploading');
              debugPrint('[PROFILE_PHOTO] Button enabled: ${(_selectedPhoto != widget.currentAvatar || _pickedFileBytes != null) && !_isUploading}');
              
              if ((_selectedPhoto != widget.currentAvatar || _pickedFileBytes != null) && !_isUploading) {
                _handleSave();
              }
            },
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
                        : widget.currentAvatar.startsWith('http')
                            ? NetworkImage(widget.currentAvatar)
                            : widget.currentAvatar.startsWith('/')
                                ? NetworkImage('${ApiConstants.serverBaseUrl}${widget.currentAvatar}')
                                : null,
                    child: _pickedFileBytes == null && !(widget.currentAvatar.startsWith('http') || widget.currentAvatar.startsWith('/'))
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
              child: ElevatedButton.icon(
                onPressed: _pickImage,
                icon: const Icon(Icons.photo_library),
                label: const Text('Choose from Gallery'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.primaryCyan,
                  foregroundColor: Colors.white,
                  minimumSize: const Size(double.infinity, 48),
                ),
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
      
      // Show loading feedback
      ScaffoldMessenger.of(context).hideCurrentSnackBar();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Selecting image...'),
          duration: Duration(seconds: 2),
        ),
      );
      
      final result = await FilePicker.platform.pickFiles(
        type: FileType.image,
        withData: true,
        allowMultiple: false,
      );

      debugPrint('[PROFILE_PHOTO] FilePicker result: ${result != null ? "has files" : "null"}');
      if (result != null) {
        debugPrint('[PROFILE_PHOTO] Files count: ${result.files.length}');
        final file = result.files.single;
        debugPrint('[PROFILE_PHOTO] File details: name=${file.name}, bytes=${file.bytes != null ? file.bytes!.length : "null"}');
      }

      if (result != null && result.files.single.bytes != null) {
        final file = result.files.single;
        debugPrint('[PROFILE_PHOTO] Image picked: ${file.name} (${file.bytes?.length} bytes)');
        
        // Validate file size (max 5MB)
        if (file.bytes != null && file.bytes!.length > 5 * 1024 * 1024) {
          throw Exception('Image size must be less than 5MB');
        }
        
        debugPrint('[PROFILE_PHOTO] Setting state with picked image...');
        setState(() {
          _pickedFileBytes = file.bytes;
          _pickedFileName = file.name;
        });
        debugPrint('[PROFILE_PHOTO] State updated');
        
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
    debugPrint('[PROFILE_PHOTO] _handleSave called');
    debugPrint('[PROFILE_PHOTO] _pickedFileBytes: ${_pickedFileBytes != null ? "not null (${_pickedFileBytes!.length} bytes)" : "null"}');
    debugPrint('[PROFILE_PHOTO] _pickedFileName: $_pickedFileName');
    debugPrint('[PROFILE_PHOTO] _selectedPhoto: $_selectedPhoto');
    debugPrint('[PROFILE_PHOTO] currentAvatar: ${widget.currentAvatar}');
    
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
      
      // Clear any existing messages and show success
      ScaffoldMessenger.of(context).hideCurrentSnackBar();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Profile photo updated successfully ✅'),
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
      final errorString = e.toString().toLowerCase();
      
      // Most specific conditions first
      if (errorString.contains('file must be an image')) {
        errorMessage = 'Please select a valid image file';
      } else if (errorString.contains('size must be less than') || errorString.contains('file too large')) {
        errorMessage = 'Image size must be less than 5MB';
      } else if (errorString.contains('timeout')) {
        errorMessage = 'Upload timeout. Please check your internet connection and try again';
      } else if (errorString.contains('connection refused')) {
        errorMessage = 'Cannot connect to server. Please check if server is running';
      } else if (errorString.contains('network') || errorString.contains('connection error')) {
        errorMessage = 'Network error. Please check your internet connection';
      } else if (errorString.contains('server error') || errorString.contains('500')) {
        errorMessage = 'Server error. Please try again later';
      } else if (errorString.contains('string should have at most 10 characters')) {
        errorMessage = 'Avatar initials too long. Please use 1-10 characters only.';
      } else if (errorString.contains('validation') || errorString.contains('invalid')) {
        errorMessage = 'Invalid data provided. Please check your inputs and try again.';
      } else if (errorString.isNotEmpty) {
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
