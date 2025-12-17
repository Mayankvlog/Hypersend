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
  List<Map<String, dynamic>> _contacts = [];

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
      final contacts = await serviceProvider.apiService.getContacts();
      if (!mounted) return;
      setState(() {
        _contacts = contacts;
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

  Future<void> _createGroup() async {
    final name = _groupNameController.text.trim();
    if (name.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Group name is required')),
      );
      return;
    }

    // Ensure at least 1 other member besides current user
    if (_selectedMemberIds.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Select at least 1 member')),
      );
      return;
    }

    try {
      final res = await serviceProvider.apiService.createGroup(
        name: name,
        description: _groupDescriptionController.text.trim(),
        memberIds: _selectedMemberIds.toList(),
      );
      final groupId = (res['group_id'] ?? res['groupId'] ?? '').toString();
      if (!mounted) return;
      context.pop();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Group created successfully')),
      );
      if (groupId.isNotEmpty) {
        context.push('/chat/$groupId');
      }
    } catch (e) {
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
                        Text('Failed to load contacts', style: Theme.of(context).textTheme.titleMedium),
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
                          itemCount: _contacts.length,
                          separatorBuilder: (_, __) => const Divider(height: 0),
                          itemBuilder: (context, index) {
                            final u = _contacts[index];
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
                          onPressed: _createGroup,
                          child: const Text(
                            'Create Group',
                            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
    );
  }
}


