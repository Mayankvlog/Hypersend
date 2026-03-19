import 'package:flutter/material.dart';
import 'package:flutter/material.dart' as material;
import 'package:go_router/go_router.dart';
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
    });

    try {
      // Simulate loading status data
      await Future.delayed(const Duration(milliseconds: 500));
      
      // Mock data for my status
      _myStatus = [
        {
          'id': '1',
          'content': 'Hello World! 🌍',
          'timestamp': DateTime.now().subtract(const Duration(hours: 2)),
          'type': 'text',
          'background_color': '#1E88E5',
          'views': 12,
        }
      ];

      // Mock data for recent updates (unviewed)
      _recentUpdates = [
        {
          'id': '2',
          'user': {
            'id': 'user1',
            'name': 'Alice Johnson',
            'avatar': 'AJ',
            'avatar_color': '#E91E63',
          },
          'content': 'Having a great day! 😊',
          'timestamp': DateTime.now().subtract(const Duration(minutes: 30)),
          'type': 'text',
          'background_color': '#4CAF50',
          'views': 5,
        },
        {
          'id': '3',
          'user': {
            'id': 'user2',
            'name': 'Bob Smith',
            'avatar': 'BS',
            'avatar_color': '#2196F3',
          },
          'content': 'Working on new projects',
          'timestamp': DateTime.now().subtract(const Duration(hours: 1)),
          'type': 'text',
          'background_color': '#FF9800',
          'views': 8,
        },
      ];

      // Mock data for viewed updates
      _viewedUpdates = [
        {
          'id': '4',
          'user': {
            'id': 'user3',
            'name': 'Carol Davis',
            'avatar': 'CD',
            'avatar_color': '#9C27B0',
          },
          'content': 'Weekend vibes 🎉',
          'timestamp': DateTime.now().subtract(const Duration(hours: 3)),
          'type': 'text',
          'background_color': '#795548',
          'views': 15,
        },
      ];

      setState(() {
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _loading = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to load status updates'),
            backgroundColor: AppTheme.errorRed,
          ),
        );
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
                  _showComingSoon('Image status');
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

  void _showComingSoon(String feature) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('$feature coming soon!'),
        backgroundColor: Colors.orange,
      ),
    );
  }

  void _viewStatus(Map<String, dynamic> status) async {
    // Simulate viewing status
    await showDialog(
      context: context,
      builder: (context) => Dialog(
        backgroundColor: Colors.transparent,
        insetPadding: EdgeInsets.zero,
        child: Container(
          width: MediaQuery.of(context).size.width * 0.9,
          height: MediaQuery.of(context).size.height * 0.7,
          decoration: BoxDecoration(
            color: Color(int.parse(status['background_color'].replaceFirst('#', '0xFF'))),
            borderRadius: BorderRadius.circular(16),
          ),
          child: Stack(
            children: [
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
              Positioned(
                top: 40,
                right: 20,
                child: IconButton(
                  onPressed: () => Navigator.pop(context),
                  icon: const Icon(Icons.close, color: Colors.white, size: 28),
                ),
              ),
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
            child: Center(
              child: Text(
                user['avatar'],
                style: const TextStyle(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 20,
                ),
              ),
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
          status['content'].length > 30 
              ? '${status['content'].substring(0, 30)}...'
              : status['content'],
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
