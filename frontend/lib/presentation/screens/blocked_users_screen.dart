import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/theme/app_theme.dart';
import '../../data/services/service_provider.dart';

class BlockedUsersScreen extends StatefulWidget {
  const BlockedUsersScreen({super.key});

  @override
  State<BlockedUsersScreen> createState() => _BlockedUsersScreenState();
}

class _BlockedUsersScreenState extends State<BlockedUsersScreen> {
  late Future<Map<String, dynamic>> _blockedUsersFuture;

  @override
  void initState() {
    super.initState();
    _blockedUsersFuture = serviceProvider.apiService.getBlockedUsers();
  }

  void _unblockUser(Map<String, dynamic> user) {
    final userId = user['id'] as String?;
    final userName = user['name'] as String? ?? 'User';
    
    if (userId == null) return;
    
    showDialog(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Unblock User'),
        content: Text(
          'Are you sure you want to unblock $userName?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () async {
              Navigator.of(dialogContext).pop();
              try {
                await serviceProvider.apiService.unblockUser(userId);
                if (!mounted) return;
                setState(() {
                  _blockedUsersFuture = serviceProvider.apiService.getBlockedUsers();
                });
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('User unblocked'),
                    backgroundColor: AppTheme.successGreen,
                  ),
                );
              } catch (e) {
                if (!mounted) return;
                print('Error unblocking user: $e'); // Log the actual exception
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('Could not unblock user. Please try again.'),
                    backgroundColor: AppTheme.errorRed,
                  ),
                );
              }
            },
            child: const Text('Unblock'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('Blocked Users'),
      ),
      body: FutureBuilder<Map<String, dynamic>>(
        future: _blockedUsersFuture,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }

          if (snapshot.hasError) {
            return Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.error_outline,
                    size: 64,
                    color: AppTheme.errorRed,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'Error loading blocked users',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    snapshot.error.toString(),
                    style: Theme.of(context).textTheme.bodySmall,
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
            );
          }

          final blockedUsers = (snapshot.data?['data']?['blocked_users'] as List?) ?? [];

          if (blockedUsers.isEmpty) {
            return Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.block_outlined,
                    size: 64,
                    color: AppTheme.textSecondary,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'No blocked users',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'You haven\'t blocked anyone yet',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ),
            );
          }

          return ListView.builder(
            itemCount: blockedUsers.length,
            itemBuilder: (context, index) {
              final item = blockedUsers[index];
              if (item is! Map<String, dynamic>) {
                print('Invalid user data at index $index: $item');
                return const SizedBox.shrink(); // Skip invalid entries
              }
              
              final user = item;
              final userName = user['name'] as String? ?? 'Unknown';

              return Padding(
                padding:
                    const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                child: Container(
                  decoration: BoxDecoration(
                    color: AppTheme.cardDark,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: Row(
                      children: [
                        // Avatar with initials
                        CircleAvatar(
                          radius: 24,
                          backgroundColor: AppTheme.primaryCyan,
                          child: (userName.isNotEmpty)
                              ? Text(
                                  userName[0].toUpperCase(),
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontWeight: FontWeight.bold,
                                  ),
                                )
                              : null,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                userName,
                                style: const TextStyle(
                                  fontWeight: FontWeight.w600,
                                  fontSize: 14,
                                ),
                              ),
                              const SizedBox(height: 2),
                              Text(
                                user['username'] as String? ?? 'No username',
                                style: Theme.of(context).textTheme.bodySmall,
                              ),
                            ],
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.close),
                          onPressed: () => _unblockUser(user),
                          color: AppTheme.errorRed,
                          tooltip: 'Unblock',
                        ),
                      ],
                    ),
                  ),
                ),
              );
            },
          );
        },
      ),
    );
  }
}
