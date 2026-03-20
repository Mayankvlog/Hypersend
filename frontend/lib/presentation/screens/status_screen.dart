import 'package:flutter/material.dart';
import 'package:flutter/material.dart' as material;
import 'package:go_router/go_router.dart';
import 'package:file_picker/file_picker.dart';
import 'dart:io' as io;
import '../../core/theme/app_theme.dart';
import '../../core/constants/app_strings.dart';
import '../../data/services/service_provider.dart';
import '../../data/models/user.dart';

class StatusScreen extends StatefulWidget {
  const StatusScreen({super.key});

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  List<Map<String, dynamic>> _myStatus = [];
  List<Map<String, dynamic>> _recentUpdates = [];
  List<Map<String, dynamic>> _viewedUpdates = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadStatusData();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadStatusData() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      // Load all statuses from other users
      final response = await serviceProvider.apiService.getAllStatuses();
      
      if (mounted) {
        setState(() {
          _recentUpdates = List<Map<String, dynamic>>.from(
            response['statuses']?.map((status) => {
              'id': status['id'],
              'user': {
                'id': status['user_id'],
                'name': 'User ${status['user_id']}', // TODO: Get actual user name
                'avatar': 'U${status['user_id'][0]}', // TODO: Get actual avatar
                'avatar_color': '#2196F3', // TODO: Get actual avatar color
              },
              'content': status['text'] ?? 'Media status',
              'timestamp': DateTime.parse(status['created_at']),
              'type': status['file_url'] != null ? 'image' : 'text',
              'background_color': status['file_url'] != null ? '#4CAF50' : '#1E88E5',
              'views': status['views'] ?? 0,
              'file_url': status['file_url'],
              'file_type': status['file_type'],
            }) ?? []
          );
          _viewedUpdates = []; // TODO: Implement viewed status tracking
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _loading = false;
          _error = e.toString();
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
              ListTile(
                leading: const Icon(Icons.videocam, color: AppTheme.primaryCyan),
                title: const Text('Video Status'),
                subtitle: const Text('Share a video as status'),
                onTap: () {
                  Navigator.pop(context);
                  _showComingSoon('Video status');
                },
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

  void _addTextStatus(String content, String backgroundColor) {
    final newStatus = {
      'id': DateTime.now().millisecondsSinceEpoch.toString(),
      'content': content,
      'timestamp': DateTime.now(),
      'type': 'text',
      'background_color': backgroundColor,
      'views': 0,
    };

    setState(() {
      _myStatus.insert(0, newStatus);
    });

    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Status posted successfully!'),
        backgroundColor: Colors.green,
      ),
    );
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

  Future<void> _uploadImageStatus(PlatformFile file) async {
    try {
      // Handle PlatformFile: convert path to dart:io File for native platforms
      if (file.path == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Failed to get file path'),
            backgroundColor: AppTheme.errorRed,
          ),
        );
        return;
      }
      
      // Import dart:io for native File
      // For web, this would need different handling (use file.bytes)
      final imageFile = io.File(file.path!);

      // Show loading indicator
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Uploading status...'),
            duration: Duration(seconds: 1),
          ),
        );
      }

      // Upload image to backend
      final uploadResponse = await serviceProvider.apiService.uploadStatusMedia(imageFile);
      
      // Create status with uploaded file
      await serviceProvider.apiService.createStatus(
        fileKey: uploadResponse['upload_id']?.toString(),
      );

      // Refresh status list
      await _loadStatusData();

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Image status uploaded successfully!'),
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to upload image: $e'),
            backgroundColor: AppTheme.errorRed,
          ),
        );
      }
    }
  }

  void _showComingSoon(String feature) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('$feature coming soon!'),
        backgroundColor: Colors.orange,
      ),
    );
  }

  void _viewStatus(Map<String, dynamic> status) async {
    // Show full-screen status viewer
    await showDialog(
      context: context,
      builder: (context) => Dialog(
        backgroundColor: Colors.transparent,
        insetPadding: EdgeInsets.zero,
        child: Container(
          width: MediaQuery.of(context).size.width * 0.9,
          height: MediaQuery.of(context).size.height * 0.7,
          decoration: status['type'] == 'image' && status['file_url'] != null
              ? BoxDecoration(
                  image: DecorationImage(
                    image: NetworkImage(status['file_url']),
                    fit: BoxFit.cover,
                  ),
                  borderRadius: BorderRadius.circular(16),
                )
              : BoxDecoration(
                  color: _parseBackgroundColor(status['background_color']),
                  borderRadius: BorderRadius.circular(16),
                ),
          child: Stack(
            children: [
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

    // Update views count only for other users' statuses
    final isMyStatus = _myStatus.any((myStatus) => myStatus['id'] == status['id']);
    if (!isMyStatus) {
      setState(() {
        status['views'] = (status['views'] as int) + 1;
      });
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
        subtitle: Text(
          status['type'] == 'image' 
              ? '📷 Photo'
              : (status['content'] != null && (status['content'] as String).length > 30 
                  ? '${(status['content'] as String).substring(0, 30)}...'
                  : status['content'] ?? ''),
          style: TextStyle(
            color: Colors.grey[600],
            fontSize: 14,
          ),
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
                                Expanded(
                                  child: _recentUpdates.isEmpty
                                      ? Center(
                                          child: Column(
                                            mainAxisAlignment: MainAxisAlignment.center,
                                            children: [
                                              Icon(
                                                Icons.visibility_off,
                                                size: 64,
                                                color: Colors.grey[400],
                                              ),
                                              const SizedBox(height: 16),
                                              Text(
                                                'No recent updates',
                                                style: TextStyle(
                                                  color: Colors.grey[600],
                                                  fontSize: 16,
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
