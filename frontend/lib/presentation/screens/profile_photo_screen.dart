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
  // REMOVED: _previewImageLoadFailed - not needed since we never show initials
  
  // Add debouncing to prevent infinite requests
  DateTime? _lastSaveAttempt;
  static const Duration _debounceDelay = Duration(seconds: 2);
  
  // Build NetworkImage with proper error handling to prevent infinite GET requests
  ImageProvider? _buildNetworkImage(String avatarUrl) {
    // Only create NetworkImage if avatarUrl is not empty and doesn't point to POST endpoint
    if (avatarUrl.isEmpty) {
      debugPrint('[PROFILE_PHOTO] Avatar URL is empty, using initials');
      return null;
    }
    
    // FIXED: Enhanced validation to prevent filename rendering glitches
    // Check if this looks like a filename pattern (like "YenSurferUserSetup")
    if (_isLikelyFilename(avatarUrl)) {
      debugPrint('[PROFILE_PHOTO] Detected filename pattern, preventing rendering glitch: $avatarUrl');
      return null; // This is a filename, not a URL - prevent glitch
    }
    
    // Check if this looks like a valid URL or path
    if (avatarUrl.startsWith('http')) {
      debugPrint('[PROFILE_PHOTO] Loading HTTP avatar: $avatarUrl');
      return NetworkImage(avatarUrl);
    } else if (avatarUrl.startsWith('/')) {
      // PREVENT requests to POST endpoints
      if (avatarUrl.endsWith('/')) {
        debugPrint('[PROFILE_PHOTO] Blocking POST endpoint request: $avatarUrl');
        return null;  // Don't load POST endpoints
      }
      
      // Check for valid avatar paths that contain 'avatar/' and have a filename with extension
      if (avatarUrl.contains('/avatar/') && 
          avatarUrl.split('/').last.contains('.')) {
        debugPrint('[PROFILE_PHOTO] Loading GET avatar: ${ApiConstants.serverBaseUrl}$avatarUrl');
        return NetworkImage('${ApiConstants.serverBaseUrl}$avatarUrl');
      }
      
      debugPrint('[PROFILE_PHOTO] Invalid avatar URL format: $avatarUrl');
      return null; // Invalid format - don't try to load
    }
    
    debugPrint('[PROFILE_PHOTO] Unknown avatar format: $avatarUrl');
    return null;
  }

  // FIXED: Helper method to detect filename patterns that cause rendering glitches
  bool _isLikelyFilename(String text) {
    // Check for common filename patterns that would cause rendering glitches
    // 1. Contains dots but no slashes (like "YenSurferUserSetup-x64-13.5.exe")
    if (text.contains('.') && !text.contains('/')) {
      // Additional check for executable-like patterns
      if (text.contains('-') && text.contains('x64') || text.contains('Setup')) {
        return true;
      }
      // Check for common filename extensions
      final extensions = ['.exe', '.jpg', '.png', '.gif', '.webp', '.jpeg', '.bmp'];
      for (final ext in extensions) {
        if (text.toLowerCase().endsWith(ext)) {
          return true;
        }
      }
      // Check if it looks like a filename (contains dots and no URL-like structure)
      if (text.split('.').length >= 2) {
        return true;
      }
    }
    
    // 2. Check for specific patterns that cause glitches
    if (text.contains('YenSurferUserSetup') || 
        text.contains('UserSetup') ||
        text.contains('x64') ||
        (text.contains('-') && text.split('-').length >= 2)) {
      return true;
    }
    
    return false;
  }

  // REMOVED: _getUserInitials - not needed since we never show initials

  @override
  void initState() {
    super.initState();
    // FIXED: Always use currentAvatar directly - don't create initials
    _selectedPhoto = widget.currentAvatar; // Use current avatar as-is
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
              
              // Operator precedence: check selection/change first, then not uploading
              final photoChanged = (_selectedPhoto != widget.currentAvatar || _pickedFileBytes != null);
              final notUploading = !_isUploading;
              
              if (photoChanged && notUploading) {
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
                  Builder(
                    builder: (_) {
                      final networkImage = _buildNetworkImage(widget.currentAvatar);
                      final backgroundImage = _pickedFileBytes != null
                          ? MemoryImage(_pickedFileBytes!)
                          : networkImage;

                      // FIXED: Never show initials to prevent 2 words avatar
                      return CircleAvatar(
                        radius: 60,
                        backgroundColor: AppTheme.primaryCyan,
                        backgroundImage: backgroundImage,
                        onBackgroundImageError: (error, stackTrace) {
                          // FIXED: No need to track load failure since we never show initials
                          debugPrint('[PROFILE_PHOTO] Preview image load failed: $error');
                        },
                        child: null, // Always null - no initials ever
                      );
                    },
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
        
        // Validate file size (max 10MB for profile photos)
        if (file.bytes != null && file.bytes!.length > 10 * 1024 * 1024) {
          throw Exception('Image size must be less than 10MB');
        }
        
        debugPrint('[PROFILE_PHOTO] Setting state with picked image...');
        setState(() {
          _pickedFileBytes = file.bytes;
          _pickedFileName = file.name;
          // reset fallback when new image is chosen
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
    // Prevent duplicate save calls with debouncing
    final now = DateTime.now();
    if (_isUploading) {
      debugPrint('[PROFILE_PHOTO] Save already in progress, ignoring duplicate call');
      return;
    }
    
    if (_lastSaveAttempt != null && 
        now.difference(_lastSaveAttempt!) < _debounceDelay) {
      debugPrint('[PROFILE_PHOTO] Save attempt too soon, debouncing');
      return;
    }
    _lastSaveAttempt = now;
    
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
        // Upload file - this updates both avatar and avatar_url on backend
        resultValue = await serviceProvider.profileService.uploadAvatar(
          _pickedFileBytes!,
          _pickedFileName!,
        );
        debugPrint('[PROFILE_PHOTO] Avatar uploaded successfully: $resultValue');
       } else {
         debugPrint('[PROFILE_PHOTO] No file selected - no changes made');
         // Don't send anything to backend if no file selected
         resultValue = widget.currentAvatar; // Return original value unchanged
         debugPrint('[PROFILE_PHOTO] No avatar changes to save');
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
      } else if (errorString.contains('method not allowed') || errorString.contains('405')) {
        errorMessage = 'Method not allowed. Please update app or contact support.';
      } else if (errorString.contains('server error') || errorString.contains('500')) {
        errorMessage = 'Server error. Please try again later';
      } else if (errorString.contains('string should have at most 10 characters')) {
        errorMessage = 'Avatar initials too long. Please use 1-10 characters only.';
      } else if (errorString.contains('avatar_url too long') || errorString.contains('avatarurl must be 500 characters or less')) {
        errorMessage = 'Avatar URL is too long. Please use a shorter URL (max 500 characters).';
       } else if (errorString.contains('avatar too long') || errorString.contains('avatar must be 10 characters or less')) {
         errorMessage = 'Avatar initials are too long. Please use 1-10 characters only.';
       } else if (errorString.contains('name cannot be empty') || errorString.contains('name must be at least 2 characters')) {
         // This shouldn't happen on photo-only screen - log for debugging
         debugPrint('[PHOTO_SCREEN] Unexpected name validation error on photo upload: $errorString');
         errorMessage = 'Photo upload failed. This appears to be a server issue. Please try again.';
       } else if (errorString.contains('validation failed') && errorString.contains('avatar')) {
          errorMessage = 'Photo validation failed. Please try a different image or check the format.';
        } else if (errorString.contains('validation failed') || errorString.contains('validation error')) {
          // For photo screen, be more specific about validation failures
          if (errorString.contains('file') || errorString.contains('upload') || errorString.contains('image')) {
            errorMessage = 'Photo upload failed. Please check image format (JPG, PNG) and file size.';
          } else {
            errorMessage = 'Photo upload failed due to server validation. Please try again.';
          }
        } else if (errorString.contains('invalid data provided')) {
          // Catch specific backend validation error
          errorMessage = 'Photo upload failed. Please check image format and try again.';
        } else if (errorString.contains('validation') && !errorString.contains('avatar')) {
           // For photo screen, hide validation errors that don't make sense
           errorMessage = 'Photo upload failed. Please try a different image or check your connection.';
        } else if (errorString.contains('invalid') && !errorString.contains('avatar')) {
           errorMessage = 'Photo upload failed. Please check image and try again.';
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
      if (mounted) {
        setState(() => _isUploading = false);
        // Reset debounce timer on error to prevent immediate retry
        _lastSaveAttempt = DateTime.now().subtract(const Duration(seconds: 1));
      }
    }
  }
}