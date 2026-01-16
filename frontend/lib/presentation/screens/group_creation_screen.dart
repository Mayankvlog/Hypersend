import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
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
  final Set<String> _selectedMemberIds = {};
  bool _loading = true;
  String? _error;
  List<Map<String, dynamic>> _users = [];

  @override
  void dispose() {
    _groupNameController.dispose();
    _groupDescriptionController.dispose();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    _loadContacts();
  }

  Future<void> _loadContacts() async {
    debugPrint('[GROUP_CREATE] Loading contacts for group creation');
    
    if (!serviceProvider.authService.isLoggedIn) {
      debugPrint('[GROUP_CREATE] User not logged in, redirecting to auth');
      if (!mounted) return;
      context.go('/auth');
      return;
    }
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      // FIXED: Use contacts endpoint instead of search for group creation
      final contacts = await serviceProvider.apiService.getContacts(limit: 100);
      debugPrint('[GROUP_CREATE] Loaded ${contacts.length} contacts for group creation');
      // If user has no saved contacts yet, fallback to all users so group creation works.
      if (contacts.isEmpty) {
        debugPrint('[GROUP_CREATE] No contacts found, loading all users via search');
        final users = await serviceProvider.apiService.searchUsers('');
        debugPrint('[GROUP_CREATE] Loaded ${users.length} users from search fallback');

        if (!mounted) return;
        setState(() {
          _users = users;
          _loading = false;
        });
        return;
      }
      
      if (!mounted) return;
      setState(() {
        _users = contacts;
        _loading = false;
      });
    } catch (e) {
      debugPrint('[GROUP_CREATE] Error loading contacts: $e');
      // Fallback to searchUsers if contacts endpoint fails
      try {
        debugPrint('[GROUP_CREATE] Falling back to searchUsers for available users');
        final users = await serviceProvider.apiService.searchUsers('');
        debugPrint('[GROUP_CREATE] Loaded ${users.length} users from search fallback');
        
        if (!mounted) return;
        setState(() {
          _users = users;
          _loading = false;
        });
      } catch (fallbackError) {
        debugPrint('[GROUP_CREATE] Both contacts and search failed: $fallbackError');
        if (!mounted) return;
        setState(() {
          _error = 'Failed to load contacts. Please try again.';
          _loading = false;
        });
      }
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('Create Group'),
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
                        ElevatedButton(onPressed: _loadContacts, child: const Text('Retry')),
                      ],
                    ),
                  ),
                )
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(AppTheme.spacing16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      TextField(
                        controller: _groupNameController,
                        decoration: const InputDecoration(
                          labelText: 'Group Name *',
                          prefixIcon: Icon(Icons.group),
                        ),
                      ),
                      const SizedBox(height: 16),
                      TextField(
                        controller: _groupDescriptionController,
                        maxLines: 3,
                        decoration: const InputDecoration(
                          labelText: 'Group Description',
                          prefixIcon: Icon(Icons.description_outlined),
                        ),
                      ),
                      const SizedBox(height: 22),
                      Text(
                        'Add Members (${_selectedMemberIds.length} selected)',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 12),
                      Container(
                        height: 360,
                        decoration: BoxDecoration(
                          color: AppTheme.cardDark.withValues(alpha: 0.35),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: AppTheme.dividerColor),
                        ),
                        child: ListView.separated(
                          itemCount: _users.length,
                          separatorBuilder: (_, __) => const Divider(height: 0),
                          itemBuilder: (context, index) {
                            final u = _users[index];
                            final id = u['id']?.toString() ?? '';
                            final name = u['name']?.toString() ?? id;
                            final email = u['email']?.toString() ?? '';
                            final selected = _selectedMemberIds.contains(id);
                            return CheckboxListTile(
                              value: selected,
                              onChanged: id.isEmpty
                                  ? null
                                  : (v) {
                                      setState(() {
                                        if (v == true) {
                                          _selectedMemberIds.add(id);
                                        } else {
                                          _selectedMemberIds.remove(id);
                                        }
                                      });
                                    },
                              title: Text(name),
                              subtitle: Text(email),
                              activeColor: AppTheme.primaryCyan,
                              checkColor: Colors.white,
                            );
                          },
                        ),
                      ),
                      const SizedBox(height: 20),
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton(
                          onPressed: _selectedMemberIds.isEmpty ? null : _createGroup,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: _selectedMemberIds.isEmpty 
                                ? Colors.grey.shade300 
                                : AppTheme.primaryCyan,
                            foregroundColor: _selectedMemberIds.isEmpty 
                                ? Colors.grey.shade600 
                                : Colors.white,
                          ),
                          child: Text(
                            _selectedMemberIds.isEmpty 
                                ? 'Select at least 1 member'
                                : 'Create Group',
                            style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
    );
  }
}


