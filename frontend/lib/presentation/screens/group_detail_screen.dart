import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import '../../core/theme/app_theme.dart';
import '../../core/constants/api_constants.dart';
import '../../data/services/service_provider.dart';

class GroupDetailScreen extends StatefulWidget {
  final String groupId;

  const GroupDetailScreen({super.key, required this.groupId});

  @override
  State<GroupDetailScreen> createState() => _GroupDetailScreenState();
}

class _GroupDetailScreenState extends State<GroupDetailScreen> {
  bool _loading = true;
  String? _error;

  bool _avatarUploading = false;
  Uint8List? _pickedGroupAvatarBytes;

  String _meId = '';
  bool _isAdmin = false;
  Map<String, dynamic>? _group;
  List<Map<String, dynamic>> _members = [];
  List<Map<String, dynamic>> _activity = [];
  bool _muted = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
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
      final me = await serviceProvider.apiService.getMe();
      final meId = me['id']?.toString() ?? '';

      final groupRes = await serviceProvider.apiService.getGroup(widget.groupId);
      final group = (groupRes['group'] as Map?)?.cast<String, dynamic>();
      if (group == null) {
        throw Exception('Group not found');
      }

      final members = List<Map<String, dynamic>>.from(group['members_detail'] ?? const []);
      final mutedBy = List<String>.from(group['muted_by'] ?? const []);

      final activityRes = await serviceProvider.apiService.getGroupActivity(widget.groupId);
      final events = List<Map<String, dynamic>>.from(activityRes['events'] ?? const []);

      if (!mounted) return;
      setState(() {
        _meId = meId;
        _group = group;
        _members = members;
        _activity = events;
        _isAdmin = group['is_admin'] == true;
        _muted = mutedBy.contains(meId);
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

  Future<void> _toggleMute(bool value) async {
    await serviceProvider.apiService.muteGroup(widget.groupId, mute: value);
    await _load();
  }

  Future<void> _addMembers() async {
    if (!_isAdmin) return;
    final users = await serviceProvider.apiService.getContacts(limit: 200);
    final existing = _members.map((m) => (m['user_id'] ?? '').toString()).toSet();
    final candidates = users.where((u) => !existing.contains((u['id'] ?? '').toString())).toList();
    if (candidates.isEmpty) return;

    final selected = <String>{};
    final added = await showModalBottomSheet<List<String>>(
      context: context,
      backgroundColor: AppTheme.backgroundDark,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      isScrollControlled: true,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setModalState) {
            return SafeArea(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Row(
                      children: [
                        const Text('Add Members', style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
                        const Spacer(),
                        TextButton(
                          onPressed: selected.isEmpty ? null : () => Navigator.of(context).pop(selected.toList()),
                          child: Text('Add (${selected.length})'),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    SizedBox(
                      height: 360,
                      child: ListView.separated(
                        itemCount: candidates.length,
                        separatorBuilder: (_, __) => const Divider(height: 0),
                        itemBuilder: (context, index) {
                          final u = candidates[index];
                          final id = (u['id'] ?? '').toString();
                          final name = (u['name'] ?? id).toString();
                          final email = (u['email'] ?? '').toString();
                          final isSelected = selected.contains(id);
                          return CheckboxListTile(
                            value: isSelected,
                            onChanged: (v) {
                              setModalState(() {
                                if (v == true) {
                                  selected.add(id);
                                } else {
                                  selected.remove(id);
                                }
                              });
                            },
                            title: Text(name),
                            subtitle: Text(email),
                            activeColor: AppTheme.primaryCyan,
                          );
                        },
                      ),
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );

    if (added == null || added.isEmpty) return;
    await serviceProvider.apiService.addGroupMembers(widget.groupId, added);
    await _load();
  }

  Future<void> _changeGroupAvatar() async {
    if (!_isAdmin || _avatarUploading) return;
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
        _avatarUploading = true;
        _pickedGroupAvatarBytes = file.bytes;
      });

      final uploadRes = await serviceProvider.apiService.uploadGroupAvatar(
        groupId: widget.groupId,
        bytes: file.bytes!,
        filename: file.name,
      );
      final avatarUrl = (uploadRes['avatar_url'] ?? '').toString();
      if (avatarUrl.isNotEmpty) {
        await serviceProvider.apiService.updateGroup(widget.groupId, {'avatar_url': avatarUrl});
      }

      await _load();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to update group photo: $e')),
      );
    } finally {
      if (mounted) {
        setState(() {
          _avatarUploading = false;
        });
      }
    }
  }

  Future<void> _toggleAdmin(String memberId, String currentRole) async {
    final nextRole = currentRole == 'admin' ? 'member' : 'admin';
    await serviceProvider.apiService.updateGroupMemberRole(widget.groupId, memberId, nextRole);
    await _load();
  }

  Future<void> _removeMember(String memberId) async {
    await serviceProvider.apiService.removeGroupMember(widget.groupId, memberId);
    await _load();
  }

  Future<void> _leaveGroup() async {
    final confirm = await showDialog<bool>(
          context: context,
          builder: (dialogContext) => AlertDialog(
            title: const Text('Leave Group?'),
            content: const Text('Are you sure you want to leave this group?'),
            actions: [
              TextButton(onPressed: () => Navigator.of(dialogContext).pop(false), child: const Text('Cancel')),
              TextButton(onPressed: () => Navigator.of(dialogContext).pop(true), child: const Text('Leave')),
            ],
          ),
        ) ??
        false;
    if (!confirm) return;
    await serviceProvider.apiService.leaveGroup(widget.groupId);
    if (!mounted) return;
    context.go('/chats');
  }

  Future<void> _deleteGroup() async {
    if (!_isAdmin) return;
    final confirm = await showDialog<bool>(
          context: context,
          builder: (dialogContext) => AlertDialog(
            title: const Text('Delete Group?'),
            content: const Text('This action cannot be undone.'),
            actions: [
              TextButton(onPressed: () => Navigator.of(dialogContext).pop(false), child: const Text('Cancel')),
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(true),
                child: const Text('Delete', style: TextStyle(color: AppTheme.errorRed)),
              ),
            ],
          ),
        ) ??
        false;
    if (!confirm) return;
    await serviceProvider.apiService.deleteGroup(widget.groupId);
    if (!mounted) return;
    context.go('/chats');
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (_error != null) {
      return Scaffold(
        appBar: AppBar(
          leading: IconButton(icon: const Icon(Icons.arrow_back), onPressed: () => context.pop()),
          title: const Text('Group Info'),
        ),
        body: Center(child: Text(_error!)),
      );
    }

final g = _group!;
    final name = (g['name'] ?? 'Group').toString();
    final description = (g['description'] ?? '').toString();
    final avatarUrl = (g['avatar_url'] ?? g['avatar'] ?? '').toString();

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(icon: const Icon(Icons.arrow_back), onPressed: () => context.pop()),
        title: const Text('Group Info'),
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppTheme.cardDark.withValues(alpha: 0.35),
                border: const Border(bottom: BorderSide(color: AppTheme.dividerColor)),
              ),
              child: Column(
                children: [
                  Stack(
                    children: [
                      CircleAvatar(
                        radius: 48,
                        backgroundColor: AppTheme.cardDark,
                        backgroundImage: _pickedGroupAvatarBytes != null
                            ? MemoryImage(_pickedGroupAvatarBytes!)
                            : (avatarUrl.isNotEmpty && !avatarUrl.endsWith('/') && (avatarUrl.startsWith('http') || avatarUrl.startsWith('/'))
                                ? NetworkImage(avatarUrl.startsWith('http') ? avatarUrl : '${ApiConstants.serverBaseUrl}$avatarUrl')
                                : null),
                        onBackgroundImageError: (exception, stackTrace) {
                          debugPrint('Group avatar load failed: $exception');
                        },
                        child: null,
                      ),
                      if (_isAdmin)
                        Positioned(
                          right: 0,
                          bottom: 0,
                          child: InkWell(
                            onTap: _avatarUploading ? null : _changeGroupAvatar,
                            borderRadius: BorderRadius.circular(20),
                            child: Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: AppTheme.primaryCyan,
                                borderRadius: BorderRadius.circular(20),
                                border: Border.all(color: AppTheme.dividerColor),
                              ),
                              child: _avatarUploading
                                  ? const SizedBox(
                                      width: 18,
                                      height: 18,
                                      child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                                    )
                                  : const Icon(Icons.camera_alt, size: 18, color: Colors.white),
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text(name, style: Theme.of(context).textTheme.titleLarge),
                  const SizedBox(height: 6),
                  Text(
                    '${_members.length} members',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(color: AppTheme.textSecondary),
                  ),
                  if (description.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    Text(description, textAlign: TextAlign.center, style: Theme.of(context).textTheme.bodyMedium),
                  ],
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    decoration: BoxDecoration(
                      color: AppTheme.inputBackground.withValues(alpha: 0.5),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: AppTheme.dividerColor.withValues(alpha: 0.7)),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.notifications_off_outlined, color: AppTheme.primaryCyan, size: 18),
                        const SizedBox(width: 10),
                        const Expanded(child: Text('Mute notifications')),
                        Switch(
                          value: _muted,
                          onChanged: (v) => _toggleMute(v),
                          activeTrackColor: AppTheme.primaryCyan,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            // Admin controls row
            if (_isAdmin)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                child: Row(
                  children: [
                    Expanded(
                      child: ElevatedButton.icon(
                        onPressed: _addMembers,
                        icon: const Icon(Icons.person_add, size: 18),
                        label: const Text('Add Members'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppTheme.primaryCyan,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 12),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: _deleteGroup,
                        icon: const Icon(Icons.delete_forever, size: 18, color: AppTheme.errorRed),
                        label: const Text('Delete Group', style: TextStyle(color: AppTheme.errorRed)),
                        style: OutlinedButton.styleFrom(
                          foregroundColor: AppTheme.errorRed,
                          side: const BorderSide(color: AppTheme.errorRed),
                          padding: const EdgeInsets.symmetric(vertical: 12),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            
            // Member controls row (visible to all members)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              child: SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: _leaveGroup,
                  icon: const Icon(Icons.exit_to_app, size: 18),
                  label: const Text('Leave Group'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppTheme.errorRed,
                    side: const BorderSide(color: AppTheme.errorRed),
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                ),
              ),
            ),
            const SizedBox(height: 12),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 10, 16, 6),
              child: Row(
                children: [
                  Text('Members', style: Theme.of(context).textTheme.titleMedium),
                  const Spacer(),
                  if (_isAdmin)
                    Text('Long-press to manage', style: Theme.of(context).textTheme.bodySmall?.copyWith(color: AppTheme.textSecondary)),
                ],
              ),
            ),
            for (final m in _members)
              ListTile(
                // FIXED: Never show initials to prevent 2 words avatar
                leading: CircleAvatar(
                  backgroundColor: AppTheme.cardDark,
                  child: null, // No initials - just empty circle
                ),
                title: Text((m['name'] ?? m['user_id'] ?? '').toString()),
                subtitle: Text((m['role'] ?? 'member').toString() == 'admin' ? 'Admin' : 'Member'),
                trailing: (m['role'] ?? 'member').toString() == 'admin'
                    ? const Icon(Icons.shield, color: AppTheme.primaryCyan)
                    : null,
                onLongPress: !_isAdmin
                    ? null
                    : () async {
                        final memberId = (m['user_id'] ?? '').toString();
                        if (memberId.isEmpty || memberId == _meId) return;
                        await showModalBottomSheet<void>(
                          context: context,
                          backgroundColor: AppTheme.backgroundDark,
                          shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(16))),
                          builder: (context) {
                            final currentRole = (m['role'] ?? 'member').toString();
                            return SafeArea(
                              child: Column(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  ListTile(
                                    leading: const Icon(Icons.admin_panel_settings, color: AppTheme.primaryCyan),
                                    title: Text(currentRole == 'admin' ? 'Demote to Member' : 'Promote to Admin'),
                                    onTap: () async {
                                      Navigator.of(context).pop();
                                      await _toggleAdmin(memberId, currentRole);
                                    },
                                  ),
                                  const Divider(height: 0),
                                  ListTile(
                                    leading: const Icon(Icons.person_remove, color: AppTheme.errorRed),
                                    title: const Text('Remove Member'),
                                    onTap: () async {
                                      Navigator.of(context).pop();
                                      await _removeMember(memberId);
                                    },
                                  ),
                                ],
                              ),
                            );
                          },
                        );
                      },
              ),
            const SizedBox(height: 12),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text('Activity Log', style: Theme.of(context).textTheme.titleMedium),
              ),
            ),
            if (_activity.isEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
                child: Text('No activity yet.', style: Theme.of(context).textTheme.bodySmall?.copyWith(color: AppTheme.textSecondary)),
              )
            else
              for (final e in _activity.reversed.take(20))
                ListTile(
                  dense: true,
                  leading: const Icon(Icons.history, color: AppTheme.textSecondary, size: 18),
                  title: Text((e['event'] ?? '').toString()),
                  subtitle: Text('${e['created_at'] ?? ''} • actor: ${e['actor_id'] ?? ''}'),
                ),
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }
}


