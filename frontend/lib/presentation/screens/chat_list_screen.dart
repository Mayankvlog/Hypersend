import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/constants/app_strings.dart';
import '../../core/theme/app_theme.dart';
import '../../data/models/chat.dart';
import '../../data/services/service_provider.dart';
import '../widgets/chat_list_item.dart';

class ChatListScreen extends StatefulWidget {
  const ChatListScreen({super.key});

  @override
  State<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends State<ChatListScreen> {
  int _selectedIndex = 0;
  final TextEditingController _searchController = TextEditingController();
  List<Chat> _filteredChats = [];
  List<Chat> _allChats = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadChats();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _onSearchChanged(String query) {
    setState(() {
      if (query.isEmpty) {
        _filteredChats = _allChats;
      } else {
        _filteredChats = _allChats
            .where((chat) =>
                chat.name.toLowerCase().contains(query.toLowerCase()) ||
                chat.lastMessage.toLowerCase().contains(query.toLowerCase()))
            .toList();
      }
    });
  }

  void _onBottomNavTap(int index) {
    setState(() {
      _selectedIndex = index;
    });
    
    if (index == 1) {
      // Navigate to file transfer
      context.push('/file-transfer');
    } else if (index == 2) {
      // Navigate to settings
      context.push('/settings');
    }
  }

  void _onChatTap(Chat chat) {
    context.push('/chat/${chat.id}');
  }

  Future<void> _loadChats() async {
    if (!serviceProvider.authService.isLoggedIn) {
      if (!mounted) return;
      context.go('/auth');
      return;
    }

    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final raw = await serviceProvider.apiService.getChats();
      final chats = raw.map(Chat.fromApi).toList();
      if (!mounted) return;
      setState(() {
        _allChats = chats;
        _filteredChats = chats;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.menu),
          onPressed: _openMainMenu,
        ),
        title: Row(
          children: [
            Container(
              width: 32,
              height: 32,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: LinearGradient(
                  colors: [AppTheme.primaryCyan, AppTheme.primaryCyan.withValues(alpha: 0.7)],
                ),
              ),
              child: const Center(
                child: Text(
                  'H',
                  style: TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 18,
                  ),
                ),
              ),
            ),
            const SizedBox(width: 12),
            const Text(AppStrings.appName),
          ],
        ),
         actions: [
           IconButton(
             icon: const Icon(Icons.group_add),
             onPressed: () async {
               await context.push('/group-create');
               if (!mounted) return;
               await _loadChats();
             },
           ),
          IconButton(
            icon: const Icon(Icons.edit_outlined),
            onPressed: () {},
          ),
        ],
      ),
      body: Column(
        children: [
          // Search bar
          Padding(
            padding: const EdgeInsets.all(AppTheme.spacing16),
            child: TextField(
              controller: _searchController,
              onChanged: _onSearchChanged,
              decoration: InputDecoration(
                hintText: AppStrings.searchChats,
                prefixIcon: const Icon(
                  Icons.search,
                  color: AppTheme.textSecondary,
                ),
                suffixIcon: _searchController.text.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear),
                        onPressed: () {
                          _searchController.clear();
                          _onSearchChanged('');
                        },
                      )
                    : null,
              ),
            ),
          ),
          // Chat list
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                    ? Center(
                        child: Padding(
                          padding: const EdgeInsets.all(24),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Icon(Icons.error_outline, color: AppTheme.errorRed, size: 48),
                              const SizedBox(height: 12),
                              Text(
                                'Failed to load chats',
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
                                onPressed: _loadChats,
                                child: const Text('Retry'),
                              ),
                            ],
                          ),
                        ),
                      )
                    : _filteredChats.isEmpty
                ? Center(
                    child: Text(
                      'No chats found',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  )
                : ListView.builder(
                    itemCount: _filteredChats.length,
                    itemBuilder: (context, index) {
                      return ChatListItem(
                        chat: _filteredChats[index],
                        onTap: () => _onChatTap(_filteredChats[index]),
                      );
                    },
                  ),
          ),
        ],
      ),
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _selectedIndex,
        onTap: _onBottomNavTap,
        items: [
          BottomNavigationBarItem(
            icon: Stack(
              children: [
                const Icon(Icons.chat_bubble),
                if (_selectedIndex == 0)
                  Positioned(
                    right: 0,
                    top: 0,
                    child: Container(
                      padding: const EdgeInsets.all(4),
                      decoration: const BoxDecoration(
                        color: AppTheme.errorRed,
                        shape: BoxShape.circle,
                      ),
                      constraints: const BoxConstraints(
                        minWidth: 16,
                        minHeight: 16,
                      ),
                      child: const Center(
                        child: Text(
                          '7',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ),
                  ),
              ],
            ),
            label: AppStrings.chats,
          ),
          const BottomNavigationBarItem(
            icon: Icon(Icons.cloud_upload_outlined),
            label: 'Files',
          ),
          const BottomNavigationBarItem(
            icon: Icon(Icons.settings_outlined),
            label: AppStrings.settings,
          ),
        ],
      ),
    );
  }

  void _openMainMenu() {
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: AppTheme.backgroundDark,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) {
        return SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(
                  Icons.edit_outlined,
                  color: AppTheme.primaryCyan,
                ),
                title: const Text('Edit Profile'),
                onTap: () {
                  Navigator.of(context).pop();
                  context.push('/profile-edit');
                },
              ),
              const Divider(height: 0),
              ListTile(
                leading: const Icon(
                  Icons.settings_outlined,
                  color: AppTheme.primaryCyan,
                ),
                title: const Text(AppStrings.settings),
                onTap: () {
                  Navigator.of(context).pop();
                  context.push('/settings');
                },
              ),
              const Divider(height: 0),
              ListTile(
                leading: const Icon(
                  Icons.cloud_upload_outlined,
                  color: AppTheme.primaryCyan,
                ),
                title: const Text('File Transfer'),
                onTap: () {
                  Navigator.of(context).pop();
                  context.push('/file-transfer');
                },
              ),
              const Divider(height: 0),
              ListTile(
                leading: const Icon(
                  Icons.logout,
                  color: AppTheme.errorRed,
                ),
                title: const Text(AppStrings.logout),
                onTap: () {
                  Navigator.of(context).pop();
                  serviceProvider.authService.logout();
                  context.go('/auth');
                },
              ),
            ],
          ),
        );
      },
    );
  }
}