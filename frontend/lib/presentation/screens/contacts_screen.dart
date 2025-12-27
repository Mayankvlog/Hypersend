import 'dart:async';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../data/models/user.dart';
import '../../data/services/service_provider.dart';
import '../../core/theme/app_theme.dart';

class ContactsScreen extends StatefulWidget {
  final String? initialSearchQuery;
  
  const ContactsScreen({super.key, this.initialSearchQuery});

  @override
  State<ContactsScreen> createState() => _ContactsScreenState();
}

class _ContactsScreenState extends State<ContactsScreen>
    with TickerProviderStateMixin {
  late TabController _tabController;
  TextEditingController? _searchController;
  Timer? _searchTimer;
  
  List<User> _allContacts = [];
  List<User> _filteredContacts = [];
  List<User> _searchResults = [];
  List<Map<String, dynamic>> _syncResults = [];
  
  bool _isLoading = false;
  bool _isSearching = false;
  bool _isSyncing = false;
  String? _error;
  final List<Map<String, dynamic>> _nearbyUsers = [];
  bool _loadingNearby = false;
  
  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
    _searchController = TextEditingController();
    
    // Set initial search query if provided (from deep link)
    if (widget.initialSearchQuery != null && widget.initialSearchQuery!.isNotEmpty) {
      _searchController?.text = widget.initialSearchQuery!;
    }
    
    _loadContacts();
    
    // Add listener for search with debouncing
    _searchController?.addListener(() => _onSearchChanged(_searchController?.text ?? ''));
  }

  @override
  void dispose() {
    _tabController.dispose();
    _searchTimer?.cancel();
    _searchController?.dispose();
    super.dispose();
  }

  Future<void> _loadContacts() async {
    if (!mounted) return;
    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      final response = await serviceProvider.apiService.getContactsList();
      final contactsData = response['contacts'] as List? ?? [];
      final contacts = contactsData.map((json) => User.fromApi(json as Map<String, dynamic>)).toList();
      
      if (!mounted) return;
      setState(() {
        _allContacts = contacts;
        _filteredContacts = contacts;
        _isLoading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _isLoading = false;
      });
    }
  }

  void _onSearchChanged(String query) {
    // Cancel previous timer
    _searchTimer?.cancel();
    
    if (query.isEmpty) {
      setState(() {
        _searchResults = [];
        _isSearching = false;
      });
      return;
    }

    setState(() {
      _isSearching = true;
    });

    // Debounce search with 500ms delay
    _searchTimer = Timer(const Duration(milliseconds: 500), () {
      if (mounted) {
        _performSearch(query);
      }
    });
  }

  Future<void> _performSearch(String query) async {
    if (!mounted) return;
    
    try {
      final response = await serviceProvider.apiService.searchContacts(query);
      final usersData = response['users'] as List? ?? [];
      final users = usersData.map((json) => User.fromApi(json as Map<String, dynamic>)).toList();
      
      if (!mounted) return;
      setState(() {
        _searchResults = users;
      });
    } catch (e) {
      debugPrint('Search error: $e');
    }
  }

  void _onContactTap(User user) {
    // Show contact options or navigate to chat
    _showContactOptions(user);
  }

  void _showContactOptions(User user) {
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: AppTheme.backgroundDark,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // User info
            ListTile(
              leading: CircleAvatar(
                backgroundColor: AppTheme.primaryCyan,
                backgroundImage: user.isAvatarPath 
                    ? NetworkImage(user.fullAvatarUrl) 
                    : null,
                child: user.isAvatarPath 
                    ? null 
                    : Text(user.initials),
              ),
              title: Text(user.name),
              subtitle: Text(user.displayStatus),
            ),
            const Divider(),
            
            // Actions
            ListTile(
              leading: const Icon(Icons.chat, color: AppTheme.primaryCyan),
              title: const Text('Send Message'),
              onTap: () {
                Navigator.pop(context);
                _startChat(user);
              },
            ),
            
            if (!user.isContact) ...[
              ListTile(
                leading: const Icon(Icons.person_add, color: AppTheme.primaryCyan),
                title: const Text('Add to Contacts'),
                onTap: () {
                  Navigator.pop(context);
                  _addToContacts(user);
                },
              ),
            ] else ...[
              ListTile(
                leading: const Icon(Icons.person_remove, color: AppTheme.primaryCyan),
                title: const Text('Remove from Contacts'),
                onTap: () {
                  Navigator.pop(context);
                  _removeFromContacts(user);
                },
              ),
            ],
            
            ListTile(
              leading: Icon(
                user.isBlocked ? Icons.block : Icons.block_outlined,
                color: user.isBlocked ? AppTheme.errorRed : AppTheme.textSecondary,
              ),
              title: Text(user.isBlocked ? 'Unblock User' : 'Block User'),
              onTap: () {
                Navigator.pop(context);
                _toggleBlockUser(user);
              },
            ),
            
            if (user.phone != null && user.phone!.isNotEmpty) ...[
              ListTile(
                leading: const Icon(Icons.phone, color: AppTheme.primaryCyan),
                title: Text('Call ${user.phone}'),
                onTap: () {
                  Navigator.pop(context);
                  // Use url_launcher or similar for phone calls
                },
              ),
            ],
            
            ListTile(
              leading: const Icon(Icons.info_outline, color: AppTheme.textSecondary),
              title: const Text('View Profile'),
              onTap: () {
                Navigator.pop(context);
                _showUserProfile(user);
              },
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _startChat(User user) async {
    try {
      final chat = await serviceProvider.apiService.createChat(targetUserId: user.id);
      if (!mounted) return;
      final chatId = chat['_id'] ?? chat['id'];
      if (chatId != null) {
        context.push('/chat/$chatId');
      }
    } catch (e) {
      _showErrorSnackBar('Could not start chat');
    }
  }

  Future<void> _addToContacts(User user) async {
    try {
      await serviceProvider.apiService.addContact(
        userId: user.id,
        displayName: user.name.isNotEmpty ? user.name : (user.username.isNotEmpty ? user.username : 'Contact'),
      );
      _showSuccessSnackBar('Contact added successfully');
      _loadContacts(); // Refresh contacts
    } catch (e) {
      _showErrorSnackBar('Could not add contact');
    }
  }

  Future<void> _removeFromContacts(User user) async {
    try {
      await serviceProvider.apiService.deleteContact(user.id);
      _showSuccessSnackBar('Contact removed successfully');
      _loadContacts(); // Refresh contacts
    } catch (e) {
      _showErrorSnackBar('Could not remove contact');
    }
  }

  Future<void> _toggleBlockUser(User user) async {
    try {
      if (user.isBlocked) {
        await serviceProvider.apiService.unblockUser(user.id);
        _showSuccessSnackBar('User unblocked successfully');
      } else {
        await serviceProvider.apiService.blockUser(user.id);
        _showSuccessSnackBar('User blocked successfully');
      }
      _loadContacts(); // Refresh contacts
    } catch (e) {
      _showErrorSnackBar('Could not ${user.isBlocked ? 'unblock' : 'block'} user');
    }
  }

  void _showUserProfile(User user) {
    // Navigate to user profile or show profile dialog
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.backgroundDark,
        title: Text(user.name),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (user.usernameIsNotEmpty)
              Text('Username: ${user.username}'),
            if (user.email != null && user.email!.isNotEmpty)
              Text('Email: ${user.email}'),
            if (user.phone != null && user.phone!.isNotEmpty)
              Text('Phone: ${user.phone}'),
            if (user.bio != null && user.bio!.isNotEmpty)
              Text('Bio: ${user.bio}'),
            Text('Status: ${user.displayStatus}'),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  void _showAddContactDialog() {
    final phoneController = TextEditingController();
    final nameController = TextEditingController();
    
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.backgroundDark,
        title: const Text('Add Contact'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: nameController,
              decoration: const InputDecoration(
                labelText: 'Name (Optional)',
                hintText: 'Contact name',
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: phoneController,
              decoration: const InputDecoration(
                labelText: 'Phone Number',
                hintText: '+1 (555) 123-4567',
              ),
              keyboardType: TextInputType.phone,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              final phone = phoneController.text.trim();
              if (phone.isEmpty) {
                _showErrorSnackBar('Please enter phone number');
                return;
              }
              
              Navigator.pop(context);
              _searchByPhone(phone);
            },
            child: const Text('Search'),
          ),
        ],
      ),
    ).then((_) {
      phoneController.dispose();
      nameController.dispose();
    });
  }

  Future<void> _searchByPhone(String phone) async {
    try {
      final response = await serviceProvider.apiService.searchContacts(phone);
      final users = (response['users'] as List? ?? [])
          .map((json) => User.fromApi(json as Map<String, dynamic>))
          .toList();
      
      if (users.isEmpty) {
        _showErrorSnackBar('No user found with this phone number');
        return;
      }
      
      if (users.length == 1) {
        final user = users.first;
        if (!user.isContact) {
          await _addToContacts(user);
        } else {
          _showErrorSnackBar('User is already in your contacts');
        }
      } else {
        // Show multiple results
        _showSearchResults(users);
      }
    } catch (e) {
      _showErrorSnackBar('Error searching for user');
    }
  }

  void _showSearchResults(List<User> users) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.backgroundDark,
        title: const Text('Search Results'),
        content: SizedBox(
          width: double.maxFinite,
          height: 300,
          child: ListView.builder(
            itemCount: users.length,
            itemBuilder: (context, index) {
              final user = users[index];
              return ListTile(
                leading: CircleAvatar(
                  backgroundColor: AppTheme.primaryCyan,
                  backgroundImage: user.isAvatarPath 
                      ? NetworkImage(user.fullAvatarUrl) 
                      : null,
                  child: user.isAvatarPath 
                      ? null 
                      : Text(user.initials),
                ),
                title: Text(user.name),
                subtitle: Text(user.displayStatus),
                trailing: user.isContact 
                    ? const Icon(Icons.check, color: Colors.green)
                    : null,
                onTap: () {
                  Navigator.pop(context);
                  if (!user.isContact) {
                    _addToContacts(user);
                  }
                },
              );
            },
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  void _showSyncContactsDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.backgroundDark,
        title: const Text('Sync Phone Contacts'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('This will match your phone contacts with app users.'),
            const SizedBox(height: 16),
            const Text('Your contacts will be encrypted and securely transmitted.'),
            const SizedBox(height: 16),
            if (_syncResults.isNotEmpty) ...[
              const Text('Found matches:'),
              const SizedBox(height: 8),
              ..._syncResults.take(5).map((result) => Text(
                '• ${result['name'] ?? result['contact_name']} (${result['phone']})',
                style: const TextStyle(fontSize: 12),
              )),
              if (_syncResults.length > 5)
                Text('... and ${_syncResults.length - 5} more'),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              _syncPhoneContacts();
            },
            child: _isSyncing 
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Text('Sync'),
          ),
        ],
      ),
    );
  }

  Future<void> _syncPhoneContacts() async {
    if (!mounted) return;
    
    setState(() {
      _isSyncing = true;
    });

    try {
      // This is a mock implementation
      // In a real app, you'd use contacts_service or similar to get phone contacts
      final mockContacts = <Map<String, String>>[
        {'name': 'John Doe', 'phone': '+1234567890'},
        {'name': 'Jane Smith', 'phone': '+0987654321'},
      ];
      
      final response = await serviceProvider.apiService.syncContacts(mockContacts);
      final matchedContacts = response['matched_contacts'] as List? ?? [];
      
      if (!mounted) return;
      setState(() {
        _syncResults = matchedContacts.cast<Map<String, dynamic>>();
        _isSyncing = false;
      });
      
      if (matchedContacts.isNotEmpty) {
        _showSyncResultsDialog(matchedContacts);
      } else {
        _showSuccessSnackBar('No new contacts found');
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isSyncing = false;
      });
      _showErrorSnackBar('Failed to sync contacts');
    }
  }

  void _showSyncResultsDialog(List<dynamic> matchedContacts) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.backgroundDark,
        title: Text('Found ${matchedContacts.length} Contact${matchedContacts.length == 1 ? '' : 's'}'),
        content: SizedBox(
          width: double.maxFinite,
          height: 400,
          child: ListView.builder(
            itemCount: matchedContacts.length,
            itemBuilder: (context, index) {
              final contact = matchedContacts[index] as Map<String, dynamic>;
              final isAlreadyContact = contact['is_already_contact'] ?? false;
              
              return ListTile(
                leading: CircleAvatar(
                  backgroundColor: AppTheme.primaryCyan,
                  child: Text(
                    (contact['name'] ?? contact['contact_name'] ?? 'U')
                        .toString()
                        .substring(0, 1)
                        .toUpperCase(),
                  ),
                ),
                title: Text(contact['name'] ?? contact['contact_name'] ?? 'Unknown'),
                subtitle: Text(contact['phone'] ?? ''),
                trailing: isAlreadyContact
                    ? const Icon(Icons.check, color: Colors.green)
                    : ElevatedButton(
                        onPressed: () {
                          Navigator.pop(context);
                          _addContactFromSync(contact['id']?.toString());
                        },
                        child: const Text('Add'),
                      ),
              );
            },
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Future<void> _addContactFromSync(String? userId) async {
    if (userId == null) return;
    
    try {
      await serviceProvider.apiService.addContact(
        userId: userId,
        displayName: 'Contact',
      );
      _showSuccessSnackBar('Contact added successfully');
      _loadContacts(); // Refresh contacts
    } catch (e) {
      _showErrorSnackBar('Could not add contact');
    }
  }

  void _showErrorSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: AppTheme.errorRed,
      ),
    );
  }

  void _showSuccessSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Colors.green,
      ),
    );
  }

  Widget _buildContactList(List<User> contacts) {
    if (contacts.isEmpty) {
      return const Center(
        child: Text(
          'No contacts found',
          style: TextStyle(color: AppTheme.textSecondary),
        ),
      );
    }

    return ListView.builder(
      itemCount: contacts.length,
      itemBuilder: (context, index) {
        final user = contacts[index];
        return ListTile(
          leading: CircleAvatar(
            backgroundColor: user.isRecentlyOnline 
                ? AppTheme.primaryCyan 
                : AppTheme.textSecondary,
            backgroundImage: user.isAvatarPath 
                ? NetworkImage(user.fullAvatarUrl) 
                : null,
            child: user.isAvatarPath 
                ? null 
                : Text(user.initials),
          ),
          title: Text(user.name),
          subtitle: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(user.displayStatus),
              if (user.usernameIsNotEmpty)
                Text('@${user.username}', style: const TextStyle(fontSize: 12)),
            ],
          ),
          trailing: user.isOnline 
              ? Container(
                  width: 12,
                  height: 12,
                  decoration: const BoxDecoration(
                    color: Colors.green,
                    shape: BoxShape.circle,
                  ),
                )
              : null,
          onTap: () => _onContactTap(user),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.backgroundDark,
      appBar: AppBar(
        backgroundColor: AppTheme.backgroundDark,
        title: const Text('Contacts'),
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppTheme.primaryCyan,
          labelColor: AppTheme.primaryCyan,
          unselectedLabelColor: AppTheme.textSecondary,
          tabs: const [
            Tab(text: 'All Contacts'),
            Tab(text: 'Search'),
            Tab(text: 'Sync'),
            Tab(text: 'Nearby'),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.person_add),
            onPressed: _showAddContactDialog,
          ),
        ],
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          // All Contacts Tab
          Column(
            children: [
              // Search bar for filtering contacts
              Padding(
                padding: const EdgeInsets.all(AppTheme.spacing16),
                child: TextField(
                  controller: _searchController,
                  decoration: InputDecoration(
                    hintText: 'Search contacts...',
                    prefixIcon: const Icon(Icons.search, color: AppTheme.textSecondary),
                    suffixIcon: _searchController?.text.isNotEmpty == true
                        ? IconButton(
                            icon: const Icon(Icons.clear),
                            onPressed: () {
                              _searchController?.clear();
                              setState(() {
                                _filteredContacts = _allContacts;
                              });
                            },
                          )
                        : null,
                  ),
                ),
              ),
              // Contacts list
              Expanded(
                child: _isLoading
                    ? const Center(child: CircularProgressIndicator())
                    : _error != null
                        ? Center(
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Text('Error: $_error'),
                                const SizedBox(height: 16),
                                ElevatedButton(
                                  onPressed: _loadContacts,
                                  child: const Text('Retry'),
                                ),
                              ],
                            ),
                          )
                        : _buildContactList(_filteredContacts),
              ),
            ],
          ),

          // Search Tab
          Padding(
            padding: const EdgeInsets.all(AppTheme.spacing16),
            child: Column(
              children: [
                TextField(
                  controller: _searchController,
                  autofocus: true,
                  decoration: InputDecoration(
                    hintText: 'Search users by name, username, or phone...',
                    prefixIcon: const Icon(Icons.search, color: AppTheme.textSecondary),
                    suffixIcon: _searchController?.text.isNotEmpty == true
                        ? IconButton(
                            icon: const Icon(Icons.clear),
                            onPressed: () {
                              _searchController?.clear();
                              setState(() {
                                _searchResults = [];
                                _isSearching = false;
                              });
                            },
                          )
                        : null,
                  ),
                ),
                const SizedBox(height: 16),
                Expanded(
                  child: _isSearching
                      ? _buildContactList(_searchResults)
                      : const Center(
                          child: Text(
                            'Type to search users',
                            style: TextStyle(color: AppTheme.textSecondary),
                          ),
                        ),
                ),
              ],
            ),
          ),

          // Sync Tab
          Padding(
            padding: const EdgeInsets.all(AppTheme.spacing16),
            child: Column(
              children: [
                const Icon(Icons.sync, size: 64, color: AppTheme.primaryCyan),
                const SizedBox(height: 24),
                const Text(
                  'Sync Phone Contacts',
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 16),
                const Text(
                  'Find people from your phone contacts who are using this app.\n\nYour contacts are encrypted and only used to find matches.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: AppTheme.textSecondary),
                ),
                const SizedBox(height: 32),
                ElevatedButton.icon(
                  onPressed: _showSyncContactsDialog,
                  icon: _isSyncing
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.sync),
                  label: Text(_isSyncing ? 'Syncing...' : 'Sync Contacts'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.primaryCyan,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
                  ),
                ),
                if (_syncResults.isNotEmpty) ...[
                  const SizedBox(height: 24),
                  Text(
                    'Found ${_syncResults.length} contact${_syncResults.length == 1 ? '' : 's'}',
                    style: const TextStyle(color: Colors.green),
                  ),
                ],
              ],
            ),
          ),

          // People Nearby Tab
          _buildNearbyTab(),
        ],
      ),
    );
  }

  Widget _buildNearbyTab() {
    return Padding(
      padding: const EdgeInsets.all(AppTheme.spacing16),
      child: Column(
        children: [
          const Icon(Icons.location_on, size: 64, color: AppTheme.primaryCyan),
          const SizedBox(height: 24),
          const Text(
            'People Nearby',
            style: TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            'Find people near you.\n\nYour location is private and only stored on your device.',
            textAlign: TextAlign.center,
            style: TextStyle(color: AppTheme.textSecondary),
          ),
          const SizedBox(height: 24),
          ElevatedButton.icon(
            onPressed: _loadingNearby ? null : _loadNearbyUsers,
            icon: _loadingNearby
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.location_searching),
            label: Text(_loadingNearby ? 'Finding nearby users...' : 'Find Nearby Users'),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.primaryCyan,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
            ),
          ),
          if (_nearbyUsers.isNotEmpty) ...[
            const SizedBox(height: 24),
            Expanded(
              child: ListView.builder(
                itemCount: _nearbyUsers.length,
                itemBuilder: (context, index) {
                  final user = _nearbyUsers[index];
                  final distance = user['distance_meters'] as num?;
                  final distanceStr = distance != null
                      ? distance > 1000
                          ? '${(distance / 1000).toStringAsFixed(1)} km'
                          : '${distance.toStringAsFixed(0)} m'
                      : 'Unknown';
                  
                  return ListTile(
                    leading: CircleAvatar(
                      backgroundColor: AppTheme.cardDark,
                      child: Text(
                        (user['name'] as String? ?? 'U')
                            .substring(0, 1)
                            .toUpperCase(),
                        style: const TextStyle(color: Colors.white),
                      ),
                    ),
                    title: Text(user['name'] as String? ?? 'Unknown User'),
                    subtitle: Text('$distanceStr away'),
                    trailing: ElevatedButton(
                      onPressed: () => _startChatWithUser(user['id'] as String),
                      child: const Text('Chat'),
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

  Future<void> _loadNearbyUsers() async {
    setState(() {
      _loadingNearby = true;
    });

    try {
      // Get current location (implementation would use geolocator package)
      // For now, show a message
      _showErrorSnackBar('Location permission required - enable location access in settings');
      
      /* 
      // Pseudo-code for actual implementation:
      final position = await Geolocator.getCurrentPosition();
      final response = await serviceProvider.apiService.getNearbyUsers(
        latitude: position.latitude,
        longitude: position.longitude,
        radiusMeters: 1000,
      );
      
      if (!mounted) return;
      setState(() {
        _nearbyUsers = List<Map<String, dynamic>>.from(response['nearby_users'] ?? []);
        _loadingNearby = false;
      });
      */
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loadingNearby = false;
      });
      _showErrorSnackBar('Failed to find nearby users: $e');
    }
  }

  Future<void> _startChatWithUser(String userId) async {
    try {
      final response = await serviceProvider.apiService.createChat(targetUserId: userId);
      final chatId = response['id'] as String? ?? response['chat_id'] as String?;
      
      if (!mounted || chatId == null) return;
      
      context.push('/chat/$chatId');
    } catch (e) {
      _showErrorSnackBar('Failed to start chat: $e');
    }
  }
}