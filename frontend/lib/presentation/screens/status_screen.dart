import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'dart:typed_data';
import 'package:video_player/video_player.dart';
import '../../core/theme/app_theme.dart';
import '../../core/constants/api_constants.dart';
import '../../data/services/service_provider.dart';

class StatusScreen extends StatefulWidget {
  const StatusScreen({super.key});

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final List<Map<String, dynamic>> _myStatus = [];
  List<Map<String, dynamic>> _recentUpdates = [];
  List<Map<String, dynamic>> _viewedUpdates = [];
  bool _loading = true;
  String? _error;
  VideoPlayerController? _videoController;
  bool _isVideoInitialized = false;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    debugPrint('[StatusScreen] Initializing - loading status data...');
    _loadStatusData();
    
    // Auto-refresh every 30 seconds to show expired statuses disappearing
    Future.delayed(const Duration(seconds: 30), () {
      if (mounted) {
        debugPrint('[StatusScreen] Auto-refresh triggered (30s interval)');
        _loadStatusData();
      }
    });
  }

  String? _statusMediaUrl(Map<String, dynamic> status) {
    final raw = status['file_url'] as String?;
    final fileKey = status['file_key'] as String?;

    String? base;
    if (raw != null && raw.isNotEmpty) {
      base = raw;
    } else if (fileKey != null && fileKey.isNotEmpty) {
      base = '${ApiConstants.serverBaseUrl}/api/v1/media/$fileKey';
    }

    if (base == null || base.isEmpty) return null;

    final ts = DateTime.now().millisecondsSinceEpoch;
    return base.contains('?') ? '$base&t=$ts' : '$base?t=$ts';
  }

  @override
  void dispose() {
    debugPrint('[StatusScreen] Disposing...');
    _videoController?.dispose();
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadStatusData() async {
    debugPrint('[StatusScreen] Loading status data...');
    
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      // Load all statuses from other users
      final response = await serviceProvider.apiService.getAllStatuses();
      
      debugPrint('[StatusScreen] API response received: ${response['statuses']?.length ?? 0} statuses');
      
      if (mounted) {
        setState(() {
          _recentUpdates = List<Map<String, dynamic>>.from(
            response['statuses']?.map((status) {
              // Skip expired statuses from display
              final isExpired = status['is_expired'] ?? false;
              final expiresAt = status['expires_at'] != null 
                ? DateTime.parse(status['expires_at'] as String)
                : DateTime.now();
              
              debugPrint('[StatusScreen] Status from ${status['user_id']}: expired=$isExpired, expires_at=$expiresAt');
              
              return {
                'id': status['id'],
                'user_id': status['user_id'],
                'user': {
                  'id': status['user_id'],
                  'name': 'User ${status['user_id']}', // TODO: Get actual user name from users endpoint
                  'avatar': 'U${(status['user_id'] as String)[0]}',
                  'avatar_color': '#2196F3',
                },
                'content': status['text'] ?? 'Media status',
                'timestamp': DateTime.parse(status['created_at'] as String),
                'expires_at': expiresAt,
                'is_expired': isExpired,
                'type': status['file_url'] != null 
                    ? (status['file_type'] == 'video' ? 'video' : 'image')
                    : 'text',
                'background_color': status['file_url'] != null ? '#4CAF50' : '#1E88E5',
                'views': status['views'] ?? 0,
                'file_url': status['file_url'],
                'file_key': status['file_key'],
                'file_type': status['file_type'],
              };
            }).toList() ?? []
          );
          
          // Filter out expired statuses for display
          _recentUpdates = _recentUpdates.where((s) => 
            !(s['is_expired'] as bool? ?? false)
          ).toList();
          
          _viewedUpdates = []; // TODO: Implement viewed status tracking
          _loading = false;
          
          debugPrint('[StatusScreen] Loaded ${_recentUpdates.length} non-expired statuses');
        });
      }
    } catch (e) {
      debugPrint('[StatusScreen] Error loading statuses: $e');
      
      // Extract user-friendly error message
      String errorMessage = 'Failed to load statuses';
      if (e.toString().contains('403')) {
        errorMessage = 'Please login to view statuses';
      } else if (e.toString().contains('404')) {
        errorMessage = 'No statuses available';
      } else if (e.toString().contains('Connection refused') || 
                 e.toString().contains('Network')) {
        errorMessage = 'Network connection failed. Please check your internet.';
      } else if (e.toString().contains('timeout')) {
        errorMessage = 'Request timed out. Please try again.';
      }
      
      if (mounted) {
        setState(() {
          _loading = false;
          _error = errorMessage;
        });
      }
    }
  }

  void _showStatusOptions() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (context) => Container(
        decoration: const BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
        child: SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 40,
                height: 4,
                margin: const EdgeInsets.symmetric(vertical: 12),
                decoration: BoxDecoration(
                  color: Colors.grey[300],
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              const Padding(
                padding: EdgeInsets.symmetric(horizontal: 24, vertical: 8),
                child: Text(
                  'Status Options',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Colors.black87,
                  ),
                ),
              ),
              ListTile(
                leading: const Icon(Icons.edit, color: AppTheme.primaryCyan),
                title: const Text('Text Status'),
                subtitle: const Text('Create a text-only status'),
                onTap: () {
                  Navigator.pop(context);
                  _createTextStatus();
                },
              ),
              ListTile(
                leading: const Icon(Icons.image, color: AppTheme.primaryCyan),
                title: const Text('Image Status'),
                subtitle: const Text('Share an image as status'),
                onTap: () {
                  Navigator.pop(context);
                  _pickAndUploadImage();
                },
              ),
              Container(
                margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [Colors.orange[400]!, Colors.deepOrange[400]!],
                    begin: Alignment.centerLeft,
                    end: Alignment.centerRight,
                  ),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: ListTile(
                  leading: Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.2),
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.videocam, color: Colors.white, size: 24),
                  ),
                  title: const Text(
                    'Video Status',
                    style: TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                      fontSize: 16,
                    ),
                  ),
                  subtitle: const Text(
                    'Share videos up to 3 minutes',
                    style: TextStyle(
                      color: Colors.white70,
                      fontSize: 14,
                    ),
                  ),
                  trailing: Container(
                    padding: const EdgeInsets.all(4),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.2),
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.play_arrow, color: Colors.white, size: 20),
                  ),
                  onTap: () {
                    Navigator.pop(context);
                    _pickAndUploadVideo();
                  },
                ),
              ),
              const SizedBox(height: 20),
            ],
          ),
        ),
      ),
    );
  }

  void _createTextStatus() {
    showDialog(
      context: context,
      builder: (context) => TextStatusDialog(
        onStatusCreated: _addTextStatus,
      ),
    );
  }

  void _addTextStatus(String content, String backgroundColor) async {
    debugPrint('[StatusScreen] Creating text status: $content');
    
    try {
      // Call API to create text status
      final response = await serviceProvider.apiService.createStatus(
        text: content,
      );
      
      debugPrint('[StatusScreen] Status created: ${response['id']}');
      
      if (mounted) {
        Navigator.pop(context);
        
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Status posted successfully! ✓'),
            backgroundColor: AppTheme.successGreen,
            duration: Duration(seconds: 2),
          ),
        );
        
        // Refresh status list to show new status
        await _loadStatusData();
      }
    } catch (e) {
      debugPrint('[StatusScreen] Error creating text status: $e');
      
      String errorMessage = 'Failed to post status';
      if (e.toString().contains('403')) {
        errorMessage = 'Please login to post status';
      } else if (e.toString().contains('400')) {
        errorMessage = 'Invalid status content. Please try again.';
      } else if (e.toString().contains('Network')) {
        errorMessage = 'Network error. Check your internet connection.';
      }
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(errorMessage),
            backgroundColor: AppTheme.errorRed,
          ),
        );
      }
    } finally {
      if (mounted) {
        _loadStatusData();
      }
    }
  }

  Future<void> _pickAndUploadImage() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.image,
        allowMultiple: false,
      );

      if (result != null && result.files.isNotEmpty) {
        final file = result.files.first;
        await _uploadImageStatus(file);
      }
    } catch (e) {
      debugPrint('[StatusScreen] Error picking image: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to pick image: $e'),
            backgroundColor: AppTheme.errorRed,
          ),
        );
      }
    }
  }

  Future<void> _pickAndUploadVideo() async {
    try {
      debugPrint('[StatusScreen] Opening video picker...');
      
      final result = await FilePicker.platform.pickFiles(
        type: FileType.video,
        allowMultiple: false,
      );

      if (result != null && result.files.isNotEmpty) {
        final file = result.files.first;
        debugPrint('[StatusScreen] Video selected: ${file.name}, size: ${file.size}');
        
        // Validate file size before upload (50MB max)
        if (file.size > 50 * 1024 * 1024) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('Video file is too large. Maximum size is 50MB.'),
                backgroundColor: AppTheme.errorRed,
                duration: Duration(seconds: 3),
              ),
            );
          }
          return;
        }
        
        // Validate file extension
        final validExtensions = ['.mp4', '.3gp', '.mov', '.avi'];
        final fileExtension = file.name.toLowerCase().split('.').last;
        if (!validExtensions.contains('.$fileExtension')) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('Invalid video format. Supported formats: ${validExtensions.join(', ')}'),
                backgroundColor: AppTheme.errorRed,
                duration: Duration(seconds: 3),
              ),
            );
          }
          return;
        }
        
        await _uploadVideoStatus(file);
      } else {
        debugPrint('[StatusScreen] No video selected');
      }
    } catch (e) {
      debugPrint('[StatusScreen] Error picking video: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to pick video: ${e.toString()}'),
            backgroundColor: AppTheme.errorRed,
            duration: const Duration(seconds: 3),
          ),
        );
      }
    }
  }

  Future<void> _uploadVideoStatus(PlatformFile file) async {
    try {
      debugPrint('[StatusScreen] Uploading video status: ${file.name}');
      
      // For native: convert path to File
      // For web: use file.bytes directly
      late Uint8List fileBytes;
      
      if (file.bytes != null) {
        fileBytes = file.bytes!;
      } else if (file.readStream != null) {
        final chunks = <int>[];
        await for (final chunk in file.readStream!) {
          chunks.addAll(chunk);
        }
        fileBytes = Uint8List.fromList(chunks);
      } else {
        throw Exception('File bytes not available');
      }

      if (mounted) {
        // Show detailed upload progress
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('Uploading video status...'),
                      Text(
                        'Processing: ${file.name}',
                        style: const TextStyle(
                          fontSize: 12,
                          color: Colors.white70,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            backgroundColor: Colors.orange[600],
            duration: const Duration(seconds: 10),
          ),
        );
      }

      // Step 1: Upload media to get file_key
      debugPrint('[StatusScreen] Uploading video bytes (${fileBytes.length} bytes)');
      final uploadResponse = await serviceProvider.apiService.uploadStatusMedia(
        fileBytes,
        filename: file.name,
      );
      
      // Handle both camelCase (uploadId) and snake_case (file_key, upload_id) from backend
      final fileKey = (uploadResponse['uploadId'] as String?) ?? 
                     (uploadResponse['file_key'] as String?) ??
                     (uploadResponse['upload_id'] as String?);
      if (fileKey == null || fileKey.isEmpty) {
        throw Exception('No file_key returned from upload');
      }
      
      debugPrint('[StatusScreen] Video uploaded with file_key: $fileKey');

      // Step 2: Create status with file_key
      debugPrint('[StatusScreen] Creating status with file_key: $fileKey');
      final statusResponse = await serviceProvider.apiService.createStatus(
        fileKey: fileKey,
      );
      
      debugPrint('[StatusScreen] Status created: ${statusResponse['id']}');

      if (mounted) {
        // Hide any existing upload progress
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        
        // Show success message with video icon
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                const Icon(Icons.videocam, color: Colors.white, size: 20),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Video status posted successfully!',
                        style: TextStyle(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        'Your video will be visible for 24 hours',
                        style: const TextStyle(
                          fontSize: 12,
                          color: Colors.white70,
                        ),
                      ),
                    ],
                  ),
                ),
                const Icon(Icons.check_circle, color: Colors.white, size: 20),
              ],
            ),
            backgroundColor: const Color(0xFF4CAF50),
            duration: const Duration(seconds: 4),
            behavior: SnackBarBehavior.floating,
          ),
        );
        
        // Refresh status list to show new status
        await _loadStatusData();
      }
    } catch (e) {
      debugPrint('[StatusScreen] Error uploading video status: $e');
      
      // Extract user-friendly error message
      String errorMessage = 'Failed to upload video';
      if (e.toString().contains('403')) {
        errorMessage = 'Please login to upload status';
      } else if (e.toString().contains('413')) {
        if (e.toString().contains('duration')) {
          errorMessage = 'Video is too long. Maximum duration is 3 minutes.';
        } else {
          errorMessage = 'Video is too large. Please choose a smaller video.';
        }
      } else if (e.toString().contains('Network')) {
        errorMessage = 'Network error. Check your internet connection.';
      } else if (e.toString().contains('No file_key')) {
        errorMessage = 'Upload failed. Server error.';
      }
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(errorMessage),
            backgroundColor: AppTheme.errorRed,
          ),
        );
      }
    } finally {
      if (mounted) {
        _loadStatusData();
      }
    }
  }

  Future<void> _uploadImageStatus(PlatformFile file) async {
    try {
      debugPrint('[StatusScreen] Uploading image status: ${file.name}');
      
      // For native: convert path to File
      // For web: use file.bytes directly
      late Uint8List fileBytes;
      
      if (file.bytes != null) {
        fileBytes = file.bytes!;
      } else if (file.readStream != null) {
        final chunks = <int>[];
        await for (final chunk in file.readStream!) {
          chunks.addAll(chunk);
        }
        fileBytes = Uint8List.fromList(chunks);
      } else {
        throw Exception('File bytes not available');
      }

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Uploading image...'),
            duration: Duration(seconds: 2),
          ),
        );
      }

      // Step 1: Upload media to get file_key
      debugPrint('[StatusScreen] Uploading media bytes (${fileBytes.length} bytes)');
      final uploadResponse = await serviceProvider.apiService.uploadStatusMedia(
        fileBytes,
        filename: file.name,
      );
      
      // Handle both camelCase (uploadId) and snake_case (file_key, upload_id) from backend
      final fileKey = (uploadResponse['uploadId'] as String?) ?? 
                     (uploadResponse['file_key'] as String?) ??
                     (uploadResponse['upload_id'] as String?);
      if (fileKey == null || fileKey.isEmpty) {
        throw Exception('No file_key returned from upload');
      }
      
      debugPrint('[StatusScreen] Media uploaded with file_key: $fileKey');

      // Step 2: Create status with file_key
      debugPrint('[StatusScreen] Creating status with file_key: $fileKey');
      final statusResponse = await serviceProvider.apiService.createStatus(
        fileKey: fileKey,
      );
      
      debugPrint('[StatusScreen] Status created: ${statusResponse['id']}');

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Image status posted! ✓'),
            backgroundColor: AppTheme.successGreen,
            duration: Duration(seconds: 2),
          ),
        );
        
        // Refresh status list to show new status
        await _loadStatusData();
      }
    } catch (e) {
      debugPrint('[StatusScreen] Error uploading image status: $e');
      
      // Extract user-friendly error message
      String errorMessage = 'Failed to upload image';
      if (e.toString().contains('403')) {
        errorMessage = 'Please login to upload status';
      } else if (e.toString().contains('413')) {
        errorMessage = 'Image is too large. Please choose a smaller image.';
      } else if (e.toString().contains('Network')) {
        errorMessage = 'Network error. Check your internet connection.';
      } else if (e.toString().contains('No file_key')) {
        errorMessage = 'Upload failed. Server error.';
      }
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(errorMessage),
            backgroundColor: AppTheme.errorRed,
          ),
        );
      }
    } finally {
      if (mounted) {
        _loadStatusData();
      }
    }
  }

  void _viewStatus(Map<String, dynamic> status) async {
    debugPrint('[StatusScreen] Viewing status: ${status['id']}');
    
    // Initialize video controller if it's a video status
    if (status['type'] == 'video' && _statusMediaUrl(status) != null) {
      try {
        await _initializeVideoPlayer(_statusMediaUrl(status)!);
      } catch (e) {
        debugPrint('[StatusScreen] Error initializing video player: $e');
        // Fall back to showing as non-video status
      }
    } else {
      // Dispose video controller if not a video status
      _videoController?.dispose();
      _videoController = null;
      _isVideoInitialized = false;
    }
    
    // Show full-screen status viewer
    await showDialog(
      context: context,
      builder: (context) => Dialog(
        backgroundColor: Colors.transparent,
        insetPadding: EdgeInsets.zero,
        child: Container(
          width: MediaQuery.of(context).size.width * 0.9,
          height: MediaQuery.of(context).size.height * 0.7,
          decoration: _getStatusDecoration(status),
          child: Stack(
            children: [
              // For video statuses, show video player
              if (status['type'] == 'video' && _isVideoInitialized && _videoController != null)
                Center(
                  child: AspectRatio(
                    aspectRatio: _videoController!.value.aspectRatio,
                    child: VideoPlayer(_videoController!),
                  ),
                ),
              // For image statuses, the background image is already set by _getStatusDecoration
              // For text statuses, show the text content
              if (status['type'] == 'text')
                Center(
                  child: Padding(
                    padding: const EdgeInsets.all(32),
                    child: Text(
                      status['content'],
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 24,
                        fontWeight: FontWeight.w500,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ),
                ),
              
              // Video controls overlay
              if (status['type'] == 'video' && _isVideoInitialized && _videoController != null)
                Positioned(
                  bottom: 40,
                  left: 20,
                  right: 20,
                  child: ValueListenableBuilder<VideoPlayerValue>(
                    valueListenable: _videoController!,
                    builder: (context, snapshot, child) {
                      return Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Colors.black.withValues(alpha: 0.6),
                          borderRadius: BorderRadius.circular(30),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            // Play/Pause button
                            IconButton(
                              onPressed: () {
                                if (snapshot.isPlaying) {
                                  _videoController!.pause();
                                } else {
                                  _videoController!.play();
                                }
                              },
                              icon: Icon(
                                snapshot.isPlaying ? Icons.pause : Icons.play_arrow,
                                color: Colors.white,
                                size: 32,
                              ),
                            ),
                            
                            // Progress indicator
                            Expanded(
                              child: Padding(
                                padding: const EdgeInsets.symmetric(horizontal: 16),
                                child: VideoProgressIndicator(
                                  _videoController!,
                                  allowScrubbing: true,
                                  colors: const VideoProgressColors(
                                    playedColor: Colors.orange,
                                    bufferedColor: Colors.grey,
                                    backgroundColor: Colors.white24,
                                  ),
                                ),
                              ),
                            ),
                            
                            // Duration display
                            Text(
                              _formatVideoDuration(snapshot.position),
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      );
                    },
                  ),
                ),
              
              // Close button
              Positioned(
                top: 40,
                right: 20,
                child: IconButton(
                  onPressed: () => Navigator.pop(context),
                  icon: const Icon(Icons.close, color: Colors.white, size: 28),
                ),
              ),
              
              // Bottom info section
              Positioned(
                bottom: 40,
                left: 20,
                right: 20,
                child: Column(
                  children: [
                    if (status['user'] != null) ...[
                      Row(
                        children: [
                          Container(
                            width: 40,
                            height: 40,
                            decoration: BoxDecoration(
                              color: Color(int.parse(status['user']['avatar_color'].replaceFirst('#', '0xFF'))),
                              shape: BoxShape.circle,
                            ),
                            child: Center(
                              child: Text(
                                status['user']['avatar'],
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  status['user']['name'],
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontWeight: FontWeight.w600,
                                    fontSize: 16,
                                  ),
                                ),
                                Text(
                                  _formatTimestamp(status['timestamp']),
                                  style: const TextStyle(
                                    color: Colors.white70,
                                    fontSize: 14,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),
                    ],
                    Text(
                      '${status['views']} views',
                      style: const TextStyle(
                        color: Colors.white70,
                        fontSize: 14,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );

    // Clean up video controller after dialog closes
    try {
      _videoController?.dispose();
    } catch (e) {
      debugPrint('[StatusScreen] Error disposing video controller: $e');
    } finally {
      _videoController = null;
      _isVideoInitialized = false;
    }

    // Update views count only for other users' statuses
    final isMyStatus = _myStatus.any((myStatus) => myStatus['id'] == status['id']);
    if (!isMyStatus) {
      setState(() {
        status['views'] = (status['views'] as int) + 1;
      });
    }
  }

  Future<void> _initializeVideoPlayer(String videoUrl) async {
    try {
      _videoController = VideoPlayerController.networkUrl(Uri.parse(videoUrl));
      await _videoController!.initialize();
      setState(() {
        _isVideoInitialized = true;
      });
      await _videoController!.play(); // Auto-play video
    } catch (e) {
      debugPrint('[StatusScreen] Error initializing video player: $e');
      _videoController?.dispose();
      _videoController = null;
      _isVideoInitialized = false;
      rethrow;
    }
  }

  Decoration _getStatusDecoration(Map<String, dynamic> status) {
    if (status['type'] == 'image' && _statusMediaUrl(status) != null) {
      return BoxDecoration(
        image: DecorationImage(
          image: NetworkImage(_statusMediaUrl(status)!),
          fit: BoxFit.cover,
        ),
        borderRadius: BorderRadius.circular(16),
      );
    } else {
      return BoxDecoration(
        color: _parseBackgroundColor(status['background_color']),
        borderRadius: BorderRadius.circular(16),
      );
    }
  }

  String _formatTimestamp(DateTime timestamp) {
    final now = DateTime.now();
    final difference = now.difference(timestamp);

    if (difference.inMinutes < 1) {
      return 'Just now';
    } else if (difference.inMinutes < 60) {
      return '${difference.inMinutes}m ago';
    } else if (difference.inHours < 24) {
      return '${difference.inHours}h ago';
    } else {
      return '${difference.inDays}d ago';
    }
  }

  String _formatVideoDuration(Duration duration) {
    String twoDigits(int n) => n.toString().padLeft(2, '0');
    final minutes = twoDigits(duration.inMinutes.remainder(60));
    final seconds = twoDigits(duration.inSeconds.remainder(60));
    return '$minutes:$seconds';
  }

  Color _parseBackgroundColor(dynamic colorValue) {
    try {
      if (colorValue == null || colorValue.toString().isEmpty) {
        return const Color(0xFF1E88E5);
      }
      final colorStr = colorValue.toString().trim();
      final hexColor = colorStr.startsWith('#') ? colorStr : '#$colorStr';
      final parsedValue = int.parse(hexColor.replaceFirst('#', '0xFF'), radix: 16);
      return Color(parsedValue);
    } catch (e) {
      return const Color(0xFF1E88E5);
    }
  }

  Widget _buildMyStatusItem() {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Column(
        children: [
          Row(
            children: [
              // Add status button
              GestureDetector(
                onTap: _showStatusOptions,
                child: Container(
                  width: 60,
                  height: 60,
                  decoration: BoxDecoration(
                    color: Colors.grey[200],
                    shape: BoxShape.circle,
                    border: Border.all(color: Colors.grey[400]!, width: 2),
                  ),
                  child: const Icon(Icons.add, color: Colors.grey, size: 30),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'My Status',
                      style: TextStyle(
                        fontWeight: FontWeight.w600,
                        fontSize: 16,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Tap to add status update',
                      style: TextStyle(
                        color: Colors.grey[600],
                        fontSize: 14,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          // Show my existing statuses
          if (_myStatus.isNotEmpty) ...[
            const SizedBox(height: 12),
            SizedBox(
              height: 80,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                itemCount: _myStatus.length,
                itemBuilder: (context, index) {
                  final status = _myStatus[index];
                  return Container(
                    width: 60,
                    height: 60,
                    margin: const EdgeInsets.only(right: 12),
                    child: GestureDetector(
                      onTap: () => _viewStatus(status),
                      child: Container(
                        decoration: BoxDecoration(
                          color: Color(int.parse(status['background_color'].replaceFirst('#', '0xFF'))),
                          shape: BoxShape.circle,
                          border: Border.all(color: Colors.grey[300]!, width: 1),
                        ),
                        child: Center(
                          child: Text(
                            status['content'].length > 15 
                                ? '${status['content'].substring(0, 15)}...'
                                : status['content'],
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 10,
                              fontWeight: FontWeight.w500,
                            ),
                            textAlign: TextAlign.center,
                          ),
                        ),
                      ),
                    ),
                  );
                },
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildStatusItem(Map<String, dynamic> status) {
    final user = status['user'];
    final timestamp = _formatTimestamp(status['timestamp']);
    
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: ListTile(
        contentPadding: EdgeInsets.zero,
        leading: GestureDetector(
          onTap: () => _viewStatus(status),
          child: Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: Color(int.parse(user['avatar_color'].replaceFirst('#', '0xFF'))),
              shape: BoxShape.circle,
              border: Border.all(
                color: status['views'] == 0 ? Colors.green : Colors.grey[300]!,
                width: status['views'] == 0 ? 3 : 1,
              ),
            ),
            child: Stack(
              children: [
                Center(
                  child: Text(
                    user['avatar'],
                    style: const TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                      fontSize: 20,
                    ),
                  ),
                ),
                // Show indicator for new/unviewed statuses
                if (status['views'] == 0)
                  Positioned(
                    right: 0,
                    bottom: 0,
                    child: Container(
                      width: 12,
                      height: 12,
                      decoration: const BoxDecoration(
                        color: Colors.green,
                        shape: BoxShape.circle,
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
        title: Text(
          user['name'],
          style: const TextStyle(
            fontWeight: FontWeight.w600,
            fontSize: 16,
          ),
        ),
        subtitle: Row(
          children: [
            if (status['type'] == 'image') ...[
              const Icon(Icons.photo, size: 16, color: Colors.grey),
              const SizedBox(width: 4),
              const Text('Photo'),
            ] else if (status['type'] == 'video') ...[
              const Icon(Icons.videocam, size: 16, color: Colors.orange),
              const SizedBox(width: 4),
              const Text('Video'),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: Colors.orange.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.orange.withValues(alpha: 0.3)),
                ),
                child: Text(
                  status['duration'] != null ? _formatVideoDuration(Duration(seconds: status['duration'])) : '0:00',
                  style: TextStyle(
                    color: Colors.orange[700],
                    fontSize: 11,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ),
            ] else ...[
              const Icon(Icons.text_fields, size: 16, color: Colors.grey),
              const SizedBox(width: 4),
              Expanded(
                child: Text(
                  status['content'] != null && (status['content'] as String).length > 30 
                      ? '${(status['content'] as String).substring(0, 30)}...'
                      : status['content'] ?? 'Text status',
                ),
              ),
            ],
          ],
        ),
        trailing: Text(
          timestamp,
          style: TextStyle(
            color: Colors.grey[500],
            fontSize: 12,
          ),
        ),
        onTap: () => _viewStatus(status),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Status'),
        elevation: 0,
        actions: [
          IconButton(
            onPressed: _loadStatusData,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _loadStatusData,
        child: Column(
          children: [
            TabBar(
              controller: _tabController,
              tabs: const [
                Tab(text: 'RECENT'),
                Tab(text: 'VIEWED'),
              ],
            ),
            Expanded(
              child: TabBarView(
                controller: _tabController,
                children: [
                  // Recent Updates Tab
                  _loading
                      ? const Center(child: CircularProgressIndicator())
                      : _error != null
                          ? Center(
                              child: Padding(
                                padding: const EdgeInsets.all(24),
                                child: Column(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    const Icon(Icons.error_outline, color: AppTheme.errorRed, size: 48),
                                    const SizedBox(height: 12),
                                    Text(
                                      'Failed to load statuses',
                                      style: Theme.of(context).textTheme.titleMedium,
                                    ),
                                    const SizedBox(height: 8),
                                    Text(
                                      _error!,
                                      textAlign: TextAlign.center,
                                      style: Theme.of(context).textTheme.bodySmall,
                                    ),
                                    const SizedBox(height: 16),
                                    ElevatedButton(
                                      onPressed: _loadStatusData,
                                      child: const Text('Retry'),
                                    ),
                                  ],
                                ),
                              ),
                            )
                          : Column(
                              children: [
                                _buildMyStatusItem(),
                                const Divider(height: 32),
                                // Video Status Feature Banner
                                Container(
                                  margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                                  padding: const EdgeInsets.all(16),
                                  decoration: BoxDecoration(
                                    gradient: LinearGradient(
                                      colors: [Colors.orange[400]!, Colors.deepOrange[400]!],
                                      begin: Alignment.centerLeft,
                                      end: Alignment.centerRight,
                                    ),
                                    borderRadius: BorderRadius.circular(12),
                                    boxShadow: [
                                      BoxShadow(
                                        color: Colors.orange.withValues(alpha: 0.3),
                                        blurRadius: 8,
                                        offset: const Offset(0, 2),
                                      ),
                                    ],
                                  ),
                                  child: Row(
                                    children: [
                                      const Icon(Icons.videocam, color: Colors.white, size: 24),
                                      const SizedBox(width: 12),
                                      Expanded(
                                        child: Column(
                                          crossAxisAlignment: CrossAxisAlignment.start,
                                          children: [
                                            const Text(
                                              'Video Status Available!',
                                              style: TextStyle(
                                                color: Colors.white,
                                                fontWeight: FontWeight.bold,
                                                fontSize: 16,
                                              ),
                                            ),
                                            const SizedBox(height: 2),
                                            Text(
                                              'Share videos up to 3 minutes long',
                                              style: TextStyle(
                                                color: Colors.white.withValues(alpha: 0.9),
                                                fontSize: 14,
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),
                                      Icon(
                                        Icons.play_circle_filled,
                                        color: Colors.white.withValues(alpha: 0.8),
                                        size: 28,
                                      ),
                                    ],
                                  ),
                                ),
                                Expanded(
                                  child: _recentUpdates.isEmpty
                                      ? Center(
                                          child: Column(
                                            mainAxisAlignment: MainAxisAlignment.center,
                                            children: [
                                              Icon(
                                                Icons.videocam,
                                                size: 64,
                                                color: Colors.orange[400],
                                              ),
                                              const SizedBox(height: 16),
                                              Text(
                                                'No recent updates',
                                                style: TextStyle(
                                                  color: Colors.grey[600],
                                                  fontSize: 16,
                                                ),
                                              ),
                                              const SizedBox(height: 8),
                                              Text(
                                                'Tap the + button to share a video status',
                                                style: TextStyle(
                                                  color: Colors.grey[500],
                                                  fontSize: 14,
                                                ),
                                              ),
                                            ],
                                          ),
                                        )
                                      : ListView.builder(
                                          itemCount: _recentUpdates.length,
                                          itemBuilder: (context, index) {
                                            return _buildStatusItem(_recentUpdates[index]);
                                          },
                                        ),
                                ),
                              ],
                            ),
                  // Viewed Updates Tab
                  _loading
                      ? const Center(child: CircularProgressIndicator())
                      : _viewedUpdates.isEmpty
                          ? Center(
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Icon(
                                    Icons.check_circle_outline,
                                    size: 64,
                                    color: Colors.grey[400],
                                  ),
                                  const SizedBox(height: 16),
                                  Text(
                                    'No viewed updates',
                                    style: TextStyle(
                                      color: Colors.grey[600],
                                      fontSize: 16,
                                    ),
                                  ),
                                ],
                              ),
                            )
                          : ListView.builder(
                              itemCount: _viewedUpdates.length,
                              itemBuilder: (context, index) {
                                return _buildStatusItem(_viewedUpdates[index]);
                              },
                            ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class TextStatusDialog extends StatefulWidget {
  final Function(String content, String backgroundColor) onStatusCreated;

  const TextStatusDialog({
    super.key,
    required this.onStatusCreated,
  });

  @override
  State<TextStatusDialog> createState() => _TextStatusDialogState();
}

class _TextStatusDialogState extends State<TextStatusDialog> {
  late TextEditingController _controller;
  final List<Map<String, String>> _backgroundColors = [
    {'color': '#1E88E5', 'name': 'Blue'},
    {'color': '#4CAF50', 'name': 'Green'},
    {'color': '#E91E63', 'name': 'Pink'},
    {'color': '#FF9800', 'name': 'Orange'},
    {'color': '#9C27B0', 'name': 'Purple'},
    {'color': '#795548', 'name': 'Brown'},
  ];
  String _selectedColor = '#1E88E5';

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController();
    _controller.addListener(() {
      setState(() {}); // Trigger rebuild for live preview
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Create Text Status'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: _controller,
              maxLines: 3,
              decoration: const InputDecoration(
                hintText: 'Type your status...',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            const Text('Background Color:'),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: _backgroundColors.map((colorData) {
                final color = Color(int.parse(colorData['color']!.replaceFirst('#', '0xFF')));
                return GestureDetector(
                  onTap: () {
                    setState(() {
                      _selectedColor = colorData['color']!;
                    });
                  },
                  child: Container(
                    width: 40,
                    height: 40,
                    decoration: BoxDecoration(
                      color: color,
                      shape: BoxShape.circle,
                      border: _selectedColor == colorData['color']
                          ? Border.all(color: Colors.black, width: 2)
                          : null,
                    ),
                  ),
                );
              }).toList(),
            ),
            const SizedBox(height: 16),
            Container(
              width: double.infinity,
              height: 80,
              decoration: BoxDecoration(
                color: Color(int.parse(_selectedColor.replaceFirst('#', '0xFF'))),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Center(
                child: Text(
                  _controller.text.isEmpty ? 'Preview' : _controller.text,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                  textAlign: TextAlign.center,
                ),
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: () {
            if (_controller.text.trim().isNotEmpty) {
              Navigator.pop(context);
              widget.onStatusCreated(_controller.text.trim(), _selectedColor);
            }
          },
          child: const Text('Post'),
        ),
      ],
    );
  }
}
