import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/constants/app_strings.dart';
import '../../core/theme/app_theme.dart';
import '../../data/models/chat.dart';
import '../../data/services/service_provider.dart';
import '../widgets/chat_list_item.dart';

class ChatListScreen extends StatefulWidget {
  final String? initialSearchQuery;
  
  const ChatListScreen({super.key, this.initialSearchQuery});

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
    if (widget.initialSearchQuery != null && widget.initialSearchQuery!.isNotEmpty) {
      _searchController.text = widget.initialSearchQuery!;
    }
    _loadChats();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _showAddContactDialog() async {
    final emailController = TextEditingController();
    final usernameController = TextEditingController();
    final nameController = TextEditingController();
    int selectedTab = 0; // 0 = Gmail, 1 = Username
    
    try {
      final result = await showDialog<Map<String, dynamic>>(
        context: context,
        barrierDismissible: false,
        builder: (context) => StatefulBuilder(
          builder: (context, setState) => AlertDialog(
            title: const Text('New Contact'),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Add a new contact',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  const SizedBox(height: 16),
                  // Contact name field
                  TextField(
                    controller: nameController,
                    autofocus: true,
                    decoration: InputDecoration(
                      hintText: 'Contact name (optional)',
                      prefixIcon: const Icon(Icons.person_outlined),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                    ),
                  ),
                  const SizedBox(height: 16),
                  // Tab selection buttons
                  SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: Row(
                      children: [
                        Expanded(
                          child: GestureDetector(
                            onTap: () => setState(() => selectedTab = 0),
                            child: Container(
                              padding: const EdgeInsets.symmetric(vertical: 12),
                              decoration: BoxDecoration(
                                border: Border(
                                  bottom: BorderSide(
                                    color: selectedTab == 0 
                                      ? AppTheme.primaryCyan 
                                      : AppTheme.dividerColor,
                                    width: selectedTab == 0 ? 2 : 1,
                                  ),
                                ),
                              ),
                              child: Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  const Icon(Icons.mail_outlined, size: 18),
                                  const SizedBox(width: 6),
                                  Text(
                                    'Gmail',
                                    style: TextStyle(
                                      fontWeight: selectedTab == 0 
                                        ? FontWeight.w600 
                                        : FontWeight.w400,
                                      color: selectedTab == 0 
                                        ? AppTheme.primaryCyan 
                                        : AppTheme.textSecondary,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                         Expanded(
                           child: GestureDetector(
                             onTap: () => setState(() => selectedTab = 1),
                             child: Container(
                               padding: const EdgeInsets.symmetric(vertical: 12),
                               decoration: BoxDecoration(
                                 border: Border(
                                   bottom: BorderSide(
                                     color: selectedTab == 1 
                                       ? AppTheme.primaryCyan 
                                       : AppTheme.dividerColor,
                                     width: selectedTab == 1 ? 2 :1,
                                   ),
                                 ),
                               ),
                               child: Row(
                                 mainAxisAlignment: MainAxisAlignment.center,
                                 children: [
                                   const Icon(Icons.alternate_email, size: 18),
                                   const SizedBox(width: 6),
                                   Text(
                                     '@Username',
                                     style: TextStyle(
                                       fontWeight: selectedTab == 1 
                                         ? FontWeight.w600 
                                         : FontWeight.w400,
                                       color: selectedTab == 1 
                                         ? AppTheme.primaryCyan 
                                         : AppTheme.textSecondary,
                                     ),
                                   ),
                                 ],
                               ),
                             ),
                           ),
                         ),
                        
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),
                  // Input field based on selected tab
                  if (selectedTab == 0) ...[
                    TextField(
                      controller: emailController,
                      decoration: InputDecoration(
                        hintText: 'Email address',
                        prefixIcon: const Icon(Icons.mail_outlined),
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(8),
                        ),
                        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      ),
                      keyboardType: TextInputType.emailAddress,
                    ),
                   ] else if (selectedTab == 1) ...[
                     TextField(
                       controller: usernameController,
                       decoration: InputDecoration(
                         hintText: 'Username',
                         prefixIcon: const Icon(Icons.alternate_email),
                         border: OutlineInputBorder(
                           borderRadius: BorderRadius.circular(8),
                         ),
                         contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                       ),
                       keyboardType: TextInputType.text,
                     ),
                   ],
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Cancel'),
              ),
              ElevatedButton(
                 onPressed: () async {
                   final name = nameController.text.trim();
                   final email = emailController.text.trim();
                   final username = usernameController.text.trim();
                  
                   // Validation
                   if (selectedTab == 0 && email.isEmpty) {
                     _showErrorSnackBar('Please enter email address');
                     return;
                   }
                   
                   if (selectedTab == 1 && username.isEmpty) {
                     _showErrorSnackBar('Please enter username');
                     return;
                   }
                  
                  
                  
                  // Email validation for Gmail tab
                  if (selectedTab == 0) {
                    final emailRegex = RegExp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$');
                    if (!emailRegex.hasMatch(email)) {
                      _showErrorSnackBar('Please enter a valid email address');
                      return;
                    }
                  }
                  
                   // Username validation
                   if (selectedTab == 1) {
                     // Remove @ if user added it
                     final cleanUsername = username.startsWith('@') ? username.substring(1) : username;
                     
                     // Validate: 3+ characters, alphanumeric + underscore only
                     final usernameRegex = RegExp(r'^[a-zA-Z0-9_]{3,}$');
                     if (!usernameRegex.hasMatch(cleanUsername)) {
                       _showErrorSnackBar('Username must be 3+ characters with only letters, numbers, and underscore');
                       return;
                     }
                     usernameController.text = cleanUsername;
                   }
                  

                  
                   try {
 // Search for user
                      List<dynamic> users;
                      if (selectedTab == 0) {
                        // Search by email
                        users = await serviceProvider.apiService.searchUsersByEmail(email);
                      } else {
                        // Search by username
                        users = await serviceProvider.apiService.searchUsersByUsername(username);
                      }
                     
                     if (!mounted) return;
                     
                     if (users.isEmpty) {
                       Navigator.pop(context);
                       final searchType = selectedTab == 0 ? 'email' : 'username';
                       _showErrorSnackBar('User with this $searchType not found. Please check and try again.');
                       return;
                     }
                    
                    final user = users.first;
                    // Pop with user object and name user wants to assign
                    if (mounted) {
                      Navigator.pop(context, {
                        ...user,
                        'display_name': name.isNotEmpty ? name : (user['name'] ?? user['username']),
                      });
                    }
                  } catch (e) {
                    if (!mounted) return;
                    Navigator.pop(context);
                    final searchType = selectedTab == 0 ? 'email' : 'username';
                    _showErrorSnackBar('Error searching by $searchType: ${e.toString()}');
                  }
                },
                child: const Text('Add'),
              ),
            ],
          ),
        ),
      );

      if (result != null && mounted) {
        try {
          final targetId = result['id']?.toString() ?? result['_id']?.toString();
          if (targetId != null) {
            final chat = await serviceProvider.apiService.createChat(targetUserId: targetId);
            if (mounted) {
              context.push('/chat/${chat['_id'] ?? chat['id']}');
              await _loadChats();
            }
          } else {
            _showErrorSnackBar('User ID missing from search results');
          }
        } catch (e) {
          if (mounted) {
            _showErrorSnackBar('Could not start chat with this contact');
          }
        }
      }
    } catch (e) {
      _showErrorSnackBar('An error occurred');
    } finally {
                    emailController.dispose();
                    usernameController.dispose();
                    
      nameController.dispose();
    }
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

  List<dynamic> _filteredListWithSaved() {
    final items = <dynamic>[];
    
    // Add Saved Messages entry as header
    if (_filteredChats.isNotEmpty || _searchController.text.isEmpty) {
      items.add('header_saved');
    }
    
    // Add filtered chats
    items.addAll(_filteredChats);
    
    return items;
  }

  Widget _buildSavedMessagesEntry() {
    return Container(
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: AppTheme.dividerColor, width: 0.5)),
      ),
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        leading: Container(
          width: 56,
          height: 56,
          decoration: const BoxDecoration(
            color: AppTheme.primaryPurple,
            shape: BoxShape.circle,
          ),
          child: const Center(
            child: Icon(Icons.bookmark, color: Colors.white, size: 28),
          ),
        ),
        title: const Text(
          'Saved Messages',
          style: TextStyle(
            fontWeight: FontWeight.w600,
            color: Colors.white,
            fontSize: 16,
          ),
        ),
        subtitle: const Text(
          'Your private notes',
          style: TextStyle(
            color: AppTheme.textSecondary,
            fontSize: 14,
          ),
        ),
        trailing: null,
        onTap: () async {
          try {
            final savedChatData = await serviceProvider.apiService.getSavedChat();
            if (!mounted) return;
            final chatId = savedChatData['chat_id'];
            context.push('/chat/$chatId');
          } catch (e) {
            if (!mounted) return;
            _showErrorSnackBar('Failed to open Saved Messages');
          }
        },
      ),
    );
  }

  void _showErrorSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: AppTheme.errorRed,
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  /// Get app logo letter based on app state
  /// Logic: Show 'Z' by default (zaply)
  /// Could be extended to show different letters based on app state/features
  String _getAppLogo() {
    // Default: Show 'Z' for zaply
    // You can extend this logic to show different letters based on:
    // - Current tab/page
    // - User status
    // - Unread messages count
    // - Other app states
    return 'Z'; // Z for zaply
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
      final filtered = chats.where((chat) {
        // Only filter out official saved type
        if (chat.type == ChatType.saved) return false;
        // Keep all other chats including groups, channels, direct messages
        return true;
      }).toList();
      if (!mounted) return;
      setState(() {
        _allChats = filtered;
        _filteredChats = filtered;
        _loading = false;
      });
    } catch (e) {
      debugPrint('[CHAT_LIST] Failed to load chats: $e');
      setState(() {
        _loading = false;
        _error = e.toString();
      });
      
      // Handle specific error types with user-friendly messages
      if (e.toString().contains('401') || e.toString().contains('Unauthorized')) {
        debugPrint('[CHAT_LIST] Authentication error detected');
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Session expired. Please login again.'),
            backgroundColor: Colors.orange,
            duration: const Duration(seconds: 4),
            action: SnackBarAction(
              label: 'Login',
              textColor: Colors.white,
              onPressed: () {
                debugPrint('[CHAT_LIST] Redirecting to login');
                context.go('/auth');
              },
            ),
          ),
        );
      }
    }
  }

  void _openMainMenu() {
    debugPrint('[CHAT_LIST] Main menu opened');
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
                  'Menu',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Colors.black87,
                  ),
                ),
              ),
              ListTile(
                leading: const Icon(Icons.person, color: AppTheme.primaryCyan),
                title: const Text('Profile'),
                onTap: () {
                  Navigator.pop(context);
                  context.push('/profile-edit');
                },
              ),
              Container(
                margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                child: ElevatedButton.icon(
                  onPressed: () {
                    debugPrint('[CHAT_LIST] Group creation from menu pressed');
                    context.push('/group-create');
                  },
                  icon: const Icon(Icons.group_add),
                  label: const Text('Create Group'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.primaryCyan,
                    foregroundColor: Colors.white,
                    minimumSize: const Size(double.infinity, 48),
                  ),
                ),
              ),
              ListTile(
                leading: const Icon(Icons.settings, color: AppTheme.primaryCyan),
                title: const Text('Settings'),
                onTap: () {
                  Navigator.pop(context);
                  context.push('/settings');
                },
              ),
              const SizedBox(height: 20),
            ],
          ),
        ),
      ),
    );
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
              child: Center(
                child: Text(
                  _getAppLogo(),
                  style: const TextStyle(
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
          Container(
            margin: const EdgeInsets.only(right: 8),
            child: ElevatedButton.icon(
              onPressed: () {
                debugPrint('[CHAT_LIST] Group creation button pressed');
                context.push('/group-create');
              },
              icon: const Icon(Icons.group_add, size: 20),
              label: const Text('Group', style: TextStyle(fontSize: 12)),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.primaryCyan,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                minimumSize: const Size(80, 36),
              ),
            ),
          ),
          Container(
            margin: const EdgeInsets.only(right: 8),
            child: ElevatedButton.icon(
              onPressed: () {
                debugPrint('[CHAT_LIST] Add contact button pressed');
                _showAddContactDialog();
              },
              icon: const Icon(Icons.person_add, size: 20),
              label: const Text('Contact', style: TextStyle(fontSize: 12)),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.primaryCyan,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                minimumSize: const Size(80, 36),
              ),
            ),
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
                    : _filteredListWithSaved().isEmpty
                ? Center(
                    child: Text(
                      'No chats found',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  )
                : ListView.builder(
                    itemCount: _filteredListWithSaved().length,
                    itemBuilder: (context, index) {
                      final item = _filteredListWithSaved()[index];
                      if (item is String && item == 'header_saved') {
                        return _buildSavedMessagesEntry();
                      }
                      final chat = item as Chat;
                      return ChatListItem(
                        chat: chat,
                        onTap: () => _onChatTap(chat),
                      );
                    },
                  ),
          ),
        ],
      ),
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _selectedIndex,
        onTap: _onBottomNavTap,
        type: BottomNavigationBarType.fixed,
        selectedItemColor: AppTheme.primaryCyan,
        unselectedItemColor: Colors.grey,
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.message),
            label: 'Chats',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.swap_horiz),
            label: 'Transfer',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.settings),
            label: 'Settings',
          ),
        ],
      ),
    );
  }
}