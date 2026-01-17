import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import '../../core/theme/app_theme.dart';
import '../../data/services/service_provider.dart';

class GroupCreationScreen extends StatefulWidget {
  const GroupCreationScreen({super.key});

  @override
  State<GroupCreationScreen> createState() => _GroupCreationScreenState();
}

class _GroupCreationScreenState extends State<GroupCreationScreen> {
  final _groupNameController = TextEditingController();
  final _groupDescriptionController = TextEditingController();
  final _searchController = TextEditingController();
  final Set<String> _selectedMemberIds = {};
  bool _loading = true;
  bool _searching = false;
  String? _error;
  List<Map<String, dynamic>> _users = [];
  List<Map<String, dynamic>> _filteredUsers = [];
  int _currentOffset = 0;
  final int _pageSize = 50;
  bool _hasMore = true;
  final ScrollController _scrollController = ScrollController();

  Uint8List? _pickedGroupAvatarBytes;
  String? _pickedGroupAvatarName;

  @override
  void dispose() {
    _groupNameController.dispose();
    _groupDescriptionController.dispose();
    _searchController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    _loadContacts();
    _scrollController.addListener(_onScroll);
    _searchController.addListener(_onSearchChanged);
  }

  void _onScroll() {
    if (_scrollController.position.pixels == _scrollController.position.maxScrollExtent) {
      if (_hasMore && !_searching && !_loading) {
        _currentOffset += _pageSize;
        _loadContacts(loadMore: true);
      }
    }
  }

  void _onSearchChanged() {
    _filterUsers();
  }

  void _filterUsers() {
    final query = _searchController.text.trim().toLowerCase();
    
    setState(() {
      if (query.isEmpty) {
        _filteredUsers = List.from(_users);
      } else {
        _filteredUsers = _users.where((user) {
          final name = user['name']?.toString().toLowerCase() ?? '';
          final email = user['email']?.toString().toLowerCase() ?? '';
          final username = user['username']?.toString().toLowerCase() ?? '';
          return name.contains(query) || 
                 email.contains(query) || 
                 username.contains(query);
        }).toList();
      }
    });
  }

  Future<void> _loadContacts({bool loadMore = false}) async {
    debugPrint('[GROUP_CREATE] Loading contacts for group creation (loadMore: $loadMore)');
    
    if (!serviceProvider.authService.isLoggedIn) {
      debugPrint('[GROUP_CREATE] User not logged in, redirecting to auth');
      if (!mounted) return;
      context.go('/auth');
      return;
    }
    
    if (loadMore) {
      setState(() {
        _searching = true;
      });
    } else {
      setState(() {
        _loading = true;
        _error = null;
        _currentOffset = 0;
        _hasMore = true;
        _users = [];
        _filteredUsers = [];
      });
    }
    
    try {
      // First try to contacts endpoint (user's saved contacts)
      final contacts = await serviceProvider.apiService.getContacts(
        limit: _pageSize,
        offset: _currentOffset,
      );
      debugPrint('[GROUP_CREATE] Loaded ${contacts.length} contacts for group creation');

      List<Map<String, dynamic>> users = contacts;

      // If there are no contacts, fall back to simple users list so group can still be created
      if (users.isEmpty && !loadMore) {
        debugPrint('[GROUP_CREATE] No contacts found, falling back to /users/simple');
        users = await serviceProvider.apiService.getSimpleUsers(
          limit: _pageSize,
          offset: _currentOffset,
        );
        debugPrint('[GROUP_CREATE] Loaded ${users.length} simple users for group creation');
      }
      
      if (!mounted) return;
      
      setState(() {
        if (loadMore) {
          _users.addAll(users);
        } else {
          _users = users;
        }
        _hasMore = users.length == _pageSize;
        _loading = false;
        _searching = false;
        
        // Update filtered list based on current search
        _filterUsers();
      });
    } catch (e) {
      debugPrint('[GROUP_CREATE] Error loading contacts/users: $e');
      if (!mounted) return;
      setState(() {
        _error = 'Failed to load users. Please try again.';
        _loading = false;
        _searching = false;
      });
    }
  }

  Future<void> _pickGroupAvatar() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.image,
        withData: true,
        allowMultiple: false,
      );
      if (result == null || result.files.isEmpty) return;
      final file = result.files.single;
      if (file.bytes == null) return;

      if (file.bytes != null && file.bytes!.length > 10 * 1024 * 1024) {
        throw Exception('Image size must be less than 10MB');
      }

      if (!mounted) return;
      setState(() {
        _pickedGroupAvatarBytes = file.bytes;
        _pickedGroupAvatarName = file.name;
      });
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to select image: $e')),
      );
    }
  }

  Future<void> _createGroup() async {
    final name = _groupNameController.text.trim();
    debugPrint('[GROUP_CREATE] Creating group with name: "$name"');
    debugPrint('[GROUP_CREATE] Available users in UI: ${_users.length}');
    debugPrint('[GROUP_CREATE] Selected members: ${_selectedMemberIds.toList()}');
    debugPrint('[GROUP_CREATE] Current user: ${serviceProvider.authService.isLoggedIn}');
    
    if (name.isEmpty) {
      debugPrint('[GROUP_CREATE] Error: Group name is empty');
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Group name is required')),
      );
      return;
    }

    // Ensure at least 1 other member besides current user
    if (_selectedMemberIds.isEmpty) {
      debugPrint('[GROUP_CREATE] Error: No members selected');
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Select at least 1 member')),
      );
      return;
    }
    
    debugPrint('[GROUP_CREATE] Proceeding to create group with selected members');

    try {
      debugPrint('[GROUP_CREATE] Calling API to create group...');
      final res = await serviceProvider.apiService.createGroup(
        name: name,
        description: _groupDescriptionController.text.trim(),
        // Backend automatically adds current user; send only the selected member IDs.
        memberIds: _selectedMemberIds.toList(),
      );
      debugPrint('[GROUP_CREATE] API response: $res');
      final groupId = (res['group_id'] ?? res['groupId'] ?? '').toString();
      debugPrint('[GROUP_CREATE] Group created with ID: $groupId');

      if (groupId.isNotEmpty && _pickedGroupAvatarBytes != null && (_pickedGroupAvatarName ?? '').isNotEmpty) {
        try {
          final uploadRes = await serviceProvider.apiService.uploadGroupAvatar(
            groupId: groupId,
            bytes: _pickedGroupAvatarBytes!,
            filename: _pickedGroupAvatarName!,
          );
          final avatarUrl = (uploadRes['avatar_url'] ?? '').toString();
          if (avatarUrl.isNotEmpty) {
            await serviceProvider.apiService.updateGroup(groupId, {'avatar_url': avatarUrl});
          }
        } catch (e) {
          debugPrint('[GROUP_CREATE] Group avatar upload failed: $e');
        }
      }
      
      if (!mounted) return;
      context.pop();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Group created successfully')),
      );
      if (groupId.isNotEmpty) {
        debugPrint('[GROUP_CREATE] Navigating to chat: /chat/$groupId');
        context.push('/chat/$groupId');
      }
    } catch (e) {
      debugPrint('[GROUP_CREATE] Error creating group: $e');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e')),
      );
    }
  }

  Widget _buildUserAvatar(Map<String, dynamic> user) {
    final avatarUrl = user['avatar_url']?.toString();
    final name = user['name']?.toString() ?? 'User';
    final firstLetter = name.isNotEmpty ? name[0].toUpperCase() : '?';
    
    if (avatarUrl != null && avatarUrl.isNotEmpty) {
      return CircleAvatar(
        radius: 20,
        backgroundImage: NetworkImage(avatarUrl),
        backgroundColor: AppTheme.cardDark,
        onBackgroundImageError: (exception, stackTrace) {
          // Fallback to initials if image fails to load
        },
        child: null,
      );
    } else {
      return CircleAvatar(
        radius: 20,
        backgroundColor: AppTheme.primaryCyan.withValues(alpha: 0.8),
        child: Text(
          firstLetter,
          style: const TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.w600,
            fontSize: 16,
          ),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('Create Group'),
        actions: [
          if (_selectedMemberIds.isNotEmpty)
            TextButton(
              onPressed: _createGroup,
              child: Text(
                'Create (${_selectedMemberIds.length})',
                style: const TextStyle(
                  color: AppTheme.primaryCyan,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
        ],
      ),
      body: _loading
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
                        Text('Failed to load users', style: Theme.of(context).textTheme.titleMedium),
                        const SizedBox(height: 8),
                        Text(_error!, textAlign: TextAlign.center, style: Theme.of(context).textTheme.bodySmall),
                        const SizedBox(height: 16),
                        ElevatedButton(onPressed: () => _loadContacts(), child: const Text('Retry')),
                      ],
                    ),
                  ),
                )
              : Column(
                  children: [
                    // Group Info Section
                    Container(
                      padding: const EdgeInsets.all(AppTheme.spacing16),
                      child: Column(
                        children: [
                          // Group Avatar
                          Center(
                            child: Stack(
                              children: [
                                CircleAvatar(
                                  radius: 44,
                                  backgroundColor: AppTheme.cardDark,
                                  backgroundImage: _pickedGroupAvatarBytes != null ? MemoryImage(_pickedGroupAvatarBytes!) : null,
                                  child: _pickedGroupAvatarBytes == null
                                      ? const Icon(Icons.group, size: 44, color: AppTheme.textSecondary)
                                      : null,
                                ),
                                Positioned(
                                  right: 0,
                                  bottom: 0,
                                  child: InkWell(
                                    onTap: _pickGroupAvatar,
                                    borderRadius: BorderRadius.circular(20),
                                    child: Container(
                                      padding: const EdgeInsets.all(8),
                                      decoration: BoxDecoration(
                                        color: AppTheme.primaryCyan,
                                        borderRadius: BorderRadius.circular(20),
                                        border: Border.all(color: AppTheme.dividerColor),
                                      ),
                                      child: const Icon(Icons.camera_alt, size: 18, color: Colors.white),
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(height: 18),
                          // Group Name
                          TextField(
                            controller: _groupNameController,
                            decoration: const InputDecoration(
                              labelText: 'Group Name *',
                              prefixIcon: Icon(Icons.group),
                              hintText: 'Enter group name',
                            ),
                          ),
                          const SizedBox(height: 16),
                          // Group Description
                          TextField(
                            controller: _groupDescriptionController,
                            maxLines: 2,
                            decoration: const InputDecoration(
                              labelText: 'Group Description (Optional)',
                              prefixIcon: Icon(Icons.description_outlined),
                              hintText: 'What\'s this group about?',
                            ),
                          ),
                        ],
                      ),
                    ),
                    
                    // Search Bar
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: AppTheme.spacing16),
                      child: TextField(
                        controller: _searchController,
                        decoration: InputDecoration(
                          labelText: 'Search contacts',
                          prefixIcon: const Icon(Icons.search),
                          suffixIcon: _searchController.text.isNotEmpty
                              ? IconButton(
                                  icon: const Icon(Icons.clear),
                                  onPressed: () {
                                    _searchController.clear();
                                  },
                                )
                              : null,
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(12),
                            borderSide: BorderSide(color: AppTheme.dividerColor),
                          ),
                          focusedBorder: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(12),
                            borderSide: const BorderSide(color: AppTheme.primaryCyan),
                          ),
                          filled: true,
                          fillColor: AppTheme.cardDark.withValues(alpha: 0.5),
                        ),
                      ),
                    ),
                    
                    const SizedBox(height: 8),
                    
                    // Members Section Header
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: AppTheme.spacing16),
                      child: Row(
                        children: [
                          Text(
                            'Select Members',
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                          const Spacer(),
                          if (_selectedMemberIds.isNotEmpty)
                            TextButton(
                              onPressed: () {
                                setState(() {
                                  _selectedMemberIds.clear();
                                });
                              },
                              child: const Text(
                                'Clear All',
                                style: TextStyle(color: AppTheme.errorRed),
                              ),
                            ),
                        ],
                      ),
                    ),
                    
                    // Members List
                    Expanded(
                      child: _filteredUsers.isEmpty && !_loading
                          ? Center(
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Icon(
                                    Icons.people_outline,
                                    size: 64,
                                    color: AppTheme.textSecondary,
                                  ),
                                  const SizedBox(height: 16),
                                  Text(
                                    _searchController.text.isNotEmpty
                                        ? 'No contacts found matching "${_searchController.text}"'
                                        : 'No contacts available',
                                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                                      color: AppTheme.textSecondary,
                                    ),
                                    textAlign: TextAlign.center,
                                  ),
                                  if (_searchController.text.isEmpty) ...[
                                    const SizedBox(height: 8),
                                    Text(
                                      'Add contacts first, then create a group',
                                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                        color: AppTheme.textSecondary,
                                      ),
                                    ),
                                  ],
                                ],
                              ),
                            )
                          : ListView.builder(
                              controller: _scrollController,
                              itemCount: _filteredUsers.length + (_searching ? 1 : 0),
                              itemBuilder: (context, index) {
                                if (index >= _filteredUsers.length) {
                                  return const Padding(
                                    padding: EdgeInsets.all(16),
                                    child: Center(child: CircularProgressIndicator()),
                                  );
                                }
                                
                                final user = _filteredUsers[index];
                                final id = user['id']?.toString() ?? '';
                                final name = user['name']?.toString() ?? 'Unknown User';
                                final email = user['email']?.toString() ?? '';
                                final username = user['username']?.toString();
                                final selected = _selectedMemberIds.contains(id);
                                
                                return ListTile(
                                  leading: _buildUserAvatar(user),
                                  title: Text(
                                    name,
                                    style: const TextStyle(fontWeight: FontWeight.w500),
                                  ),
                                  subtitle: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      if (email.isNotEmpty)
                                        Text(
                                          email,
                                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                            color: AppTheme.textSecondary,
                                          ),
                                        ),
                                      if (username != null && username.isNotEmpty)
                                        Text(
                                          '@$username',
                                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                            color: AppTheme.primaryCyan,
                                          ),
                                        ),
                                    ],
                                  ),
                                  trailing: Checkbox(
                                    value: selected,
                                    onChanged: id.isEmpty
                                        ? null
                                        : (value) {
                                            setState(() {
                                              if (value == true) {
                                                _selectedMemberIds.add(id);
                                              } else {
                                                _selectedMemberIds.remove(id);
                                              }
                                            });
                                          },
                                    activeColor: AppTheme.primaryCyan,
                                    checkColor: Colors.white,
                                  ),
                                  onTap: id.isEmpty
                                      ? null
                                      : () {
                                          setState(() {
                                            if (selected) {
                                              _selectedMemberIds.remove(id);
                                            } else {
                                              _selectedMemberIds.add(id);
                                            }
                                          });
                                        },
                                );
                              },
                            ),
                    ),
                    
                    // Bottom Padding
                    const SizedBox(height: 16),
                  ],
                ),
    );
  }
}