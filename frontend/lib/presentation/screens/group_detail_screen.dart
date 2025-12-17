import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/theme/app_theme.dart';
import '../../data/mock/mock_data.dart';
import '../../data/models/chat.dart';
import '../../data/models/group.dart';
import '../../data/models/group_activity.dart';
import '../../data/models/group_member.dart';
import '../../data/models/user.dart';

class GroupDetailScreen extends StatefulWidget {
  final String groupId;

  const GroupDetailScreen({super.key, required this.groupId});

  @override
  State<GroupDetailScreen> createState() => _GroupDetailScreenState();
}

class _GroupDetailScreenState extends State<GroupDetailScreen> {
  Group? _group;

  @override
  void initState() {
    super.initState();
    _group = MockData.groups.where((g) => g.id == widget.groupId).isNotEmpty
        ? MockData.groups.firstWhere((g) => g.id == widget.groupId)
        : null;
  }

  User? _userById(String id) {
    final all = MockData.contacts;
    return all.where((u) => u.id == id).isNotEmpty ? all.firstWhere((u) => u.id == id) : null;
  }

  bool get _isAdmin {
    final g = _group;
    if (g == null) return false;
    final me = MockData.currentUser.id;
    return g.members.any((m) => m.userId == me && m.role == GroupRole.admin);
  }

  void _replaceGroup(Group updated) {
    final idx = MockData.groups.indexWhere((g) => g.id == updated.id);
    if (idx >= 0) {
      MockData.groups[idx] = updated;
    }
    setState(() {
      _group = updated;
    });
  }

  void _syncChatMuted(bool muted) {
    final idx = MockData.chats.indexWhere((c) => c.id == widget.groupId);
    if (idx < 0) return;
    final old = MockData.chats[idx];
    MockData.chats[idx] = Chat(
      id: old.id,
      type: old.type,
      name: old.name,
      avatar: old.avatar,
      lastMessage: old.lastMessage,
      lastMessageTime: old.lastMessageTime,
      unreadCount: old.unreadCount,
      isMuted: muted,
      isOnline: old.isOnline,
      senderName: old.senderName,
    );
  }

  Future<void> _addMembers() async {
    final g = _group;
    if (g == null) return;
    if (!_isAdmin) return;

    final existing = g.members.map((m) => m.userId).toSet();
    final candidates = MockData.contacts
        .where((u) => !existing.contains(u.id))
        .toList();

    if (candidates.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No more contacts to add')),
      );
      return;
    }

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
                        const Text(
                          'Add Members',
                          style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700),
                        ),
                        const Spacer(),
                        TextButton(
                          onPressed: selected.isEmpty
                              ? null
                              : () => Navigator.of(context).pop(selected.toList()),
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
                          final isSelected = selected.contains(u.id);
                          return CheckboxListTile(
                            value: isSelected,
                            onChanged: (v) {
                              setModalState(() {
                                if (v == true) {
                                  selected.add(u.id);
                                } else {
                                  selected.remove(u.id);
                                }
                              });
                            },
                            title: Text(u.name),
                            subtitle: Text(u.username),
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
    final now = DateTime.now();
    final newMembers = [
      ...g.members,
      for (final id in added) GroupMember(userId: id, role: GroupRole.member, joinedAt: now),
    ];
    _replaceGroup(
      g.copyWith(
        members: newMembers,
        activity: [
          ...g.activity,
          for (final id in added)
            GroupActivity(
              id: 'ga_${DateTime.now().millisecondsSinceEpoch}_$id',
              event: 'member_added',
              actorId: MockData.currentUser.id,
              timestamp: now,
              meta: {'user_id': id},
            ),
        ],
      ),
    );
  }

  Future<void> _editGroup() async {
    final g = _group;
    if (g == null) return;

    final nameController = TextEditingController(text: g.name);
    final descController = TextEditingController(text: g.description);

    final updated = await showDialog<Group>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          title: const Text('Edit Group'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nameController,
                decoration: const InputDecoration(
                  labelText: 'Group Name',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: descController,
                maxLines: 3,
                decoration: const InputDecoration(
                  labelText: 'Description',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(),
              child: const Text('Cancel'),
            ),
            TextButton(
              onPressed: () {
                final name = nameController.text.trim();
                if (name.isEmpty) return;
                Navigator.of(dialogContext).pop(
                  g.copyWith(
                    name: name,
                    description: descController.text.trim(),
                    activity: [
                      ...g.activity,
                      GroupActivity(
                        id: 'ga_${DateTime.now().millisecondsSinceEpoch}',
                        event: 'group_updated',
                        actorId: MockData.currentUser.id,
                        timestamp: DateTime.now(),
                        meta: const {},
                      ),
                    ],
                  ),
                );
              },
              child: const Text('Save'),
            ),
          ],
        );
      },
    );

    if (updated != null) {
      // Update chat list entry too
      final chatIdx = MockData.chats.indexWhere((c) => c.id == updated.id);
      if (chatIdx >= 0) {
        final old = MockData.chats[chatIdx];
        MockData.chats[chatIdx] = Chat(
          id: old.id,
          type: old.type,
          name: updated.name,
          avatar: updated.avatar,
          lastMessage: old.lastMessage,
          lastMessageTime: old.lastMessageTime,
          unreadCount: old.unreadCount,
          isMuted: old.isMuted,
          isOnline: old.isOnline,
          senderName: old.senderName,
        );
      }
      _replaceGroup(updated);
    }
  }

  void _promoteOrDemote(String memberId) {
    final g = _group;
    if (g == null) return;
    final members = g.members.map((m) {
      if (m.userId != memberId) return m;
      return m.role == GroupRole.admin
          ? m.copyWith(role: GroupRole.member)
          : m.copyWith(role: GroupRole.admin);
    }).toList();
    _replaceGroup(
      g.copyWith(
        members: members,
        activity: [
          ...g.activity,
          GroupActivity(
            id: 'ga_${DateTime.now().millisecondsSinceEpoch}',
            event: 'role_changed',
            actorId: MockData.currentUser.id,
            timestamp: DateTime.now(),
            meta: {'user_id': memberId},
          ),
        ],
      ),
    );
  }

  void _removeMember(String memberId) {
    final g = _group;
    if (g == null) return;
    final members = g.members.where((m) => m.userId != memberId).toList();
    _replaceGroup(
      g.copyWith(
        members: members,
        activity: [
          ...g.activity,
          GroupActivity(
            id: 'ga_${DateTime.now().millisecondsSinceEpoch}',
            event: 'member_removed',
            actorId: MockData.currentUser.id,
            timestamp: DateTime.now(),
            meta: {'user_id': memberId},
          ),
        ],
      ),
    );
  }

  Future<void> _showMemberOptions(GroupMember member) async {
    if (!_isAdmin) return;
    if (member.userId == MockData.currentUser.id) return;

    await showModalBottomSheet<void>(
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
                leading: const Icon(Icons.admin_panel_settings, color: AppTheme.primaryCyan),
                title: Text(member.role == GroupRole.admin ? 'Demote to Member' : 'Promote to Admin'),
                onTap: () {
                  Navigator.of(context).pop();
                  _promoteOrDemote(member.userId);
                },
              ),
              const Divider(height: 0),
              ListTile(
                leading: const Icon(Icons.person_remove, color: AppTheme.errorRed),
                title: const Text('Remove Member'),
                onTap: () {
                  Navigator.of(context).pop();
                  _removeMember(member.userId);
                },
              ),
            ],
          ),
        );
      },
    );
  }

  Future<void> _leaveGroup() async {
    final g = _group;
    if (g == null) return;
    final me = MockData.currentUser.id;
    if (g.createdBy == me) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Creator must delete the group')),
      );
      return;
    }

    final confirm = await showDialog<bool>(
          context: context,
          builder: (dialogContext) => AlertDialog(
            title: const Text('Leave Group?'),
            content: const Text('Are you sure you want to leave this group?'),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(false),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(true),
                child: const Text('Leave'),
              ),
            ],
          ),
        ) ??
        false;

    if (!confirm) return;

    _replaceGroup(
      g.copyWith(
        members: g.members.where((m) => m.userId != me).toList(),
        activity: [
          ...g.activity,
          GroupActivity(
            id: 'ga_${DateTime.now().millisecondsSinceEpoch}',
            event: 'member_left',
            actorId: me,
            timestamp: DateTime.now(),
            meta: {'user_id': me},
          ),
        ],
      ),
    );

    if (!mounted) return;
    context.pop();
  }

  Future<void> _deleteGroup() async {
    final g = _group;
    if (g == null) return;
    final me = MockData.currentUser.id;
    if (g.createdBy != me && !_isAdmin) return;

    final confirm = await showDialog<bool>(
          context: context,
          builder: (dialogContext) => AlertDialog(
            title: const Text('Delete Group?'),
            content: const Text('This action cannot be undone.'),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(false),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(true),
                child: const Text('Delete', style: TextStyle(color: AppTheme.errorRed)),
              ),
            ],
          ),
        ) ??
        false;

    if (!confirm) return;

    MockData.groups.removeWhere((x) => x.id == widget.groupId);
    MockData.chats.removeWhere((x) => x.id == widget.groupId);
    MockData.messages.removeWhere((m) => m.chatId == widget.groupId);

    if (!mounted) return;
    context.go('/chats');
  }

  @override
  Widget build(BuildContext context) {
    final g = _group;
    if (g == null) {
      return Scaffold(
        appBar: AppBar(
          leading: IconButton(
            icon: const Icon(Icons.arrow_back),
            onPressed: () => context.pop(),
          ),
          title: const Text('Group'),
        ),
        body: const Center(child: Text('Group not found')),
      );
    }

    final pinned = MockData.messages
        .where((m) => m.chatId == g.id && m.isPinned && !m.isDeleted)
        .toList();

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('Group Info'),
        actions: [
          if (_isAdmin)
            PopupMenuButton<String>(
              onSelected: (value) {
                if (value == 'edit') _editGroup();
                if (value == 'add_members') _addMembers();
                if (value == 'leave') _leaveGroup();
                if (value == 'delete') _deleteGroup();
              },
              itemBuilder: (context) => [
                const PopupMenuItem(value: 'edit', child: Text('Edit Group')),
                const PopupMenuItem(value: 'add_members', child: Text('Add Members')),
                const PopupMenuItem(value: 'leave', child: Text('Leave Group')),
                const PopupMenuItem(value: 'delete', child: Text('Delete Group')),
              ],
            )
          else
            PopupMenuButton<String>(
              onSelected: (value) {
                if (value == 'leave') _leaveGroup();
              },
              itemBuilder: (context) => [
                const PopupMenuItem(value: 'leave', child: Text('Leave Group')),
              ],
            ),
        ],
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppTheme.cardDark.withValues(alpha: 0.35),
                border: const Border(
                  bottom: BorderSide(color: AppTheme.dividerColor),
                ),
              ),
              child: Column(
                children: [
                  CircleAvatar(
                    radius: 48,
                    backgroundColor: AppTheme.cardDark,
                    child: Text(
                      g.avatar,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 22,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    g.name,
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                  const SizedBox(height: 6),
                  Text(
                    '${g.members.length} members',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: AppTheme.textSecondary,
                        ),
                  ),
                  if (g.description.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    Text(
                      g.description,
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
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
                          value: g.notificationsMuted,
                          onChanged: (v) {
                            final updated = g.copyWith(
                              notificationsMuted: v,
                              activity: [
                                ...g.activity,
                                GroupActivity(
                                  id: 'ga_${DateTime.now().millisecondsSinceEpoch}',
                                  event: v ? 'notifications_muted' : 'notifications_unmuted',
                                  actorId: MockData.currentUser.id,
                                  timestamp: DateTime.now(),
                                  meta: const {},
                                ),
                              ],
                            );
                            _syncChatMuted(v);
                            _replaceGroup(updated);
                          },
                          activeTrackColor: AppTheme.primaryCyan,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            if (pinned.isNotEmpty)
              Container(
                width: double.infinity,
                margin: const EdgeInsets.all(16),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.amber.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.amber.withValues(alpha: 0.35)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Pinned Messages',
                      style: TextStyle(
                        fontWeight: FontWeight.w700,
                        color: Colors.amber,
                      ),
                    ),
                    const SizedBox(height: 8),
                    for (final m in pinned.take(3))
                      Text(
                        m.content ?? '',
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                  ],
                ),
              ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 10, 16, 6),
              child: Row(
                children: [
                  Text(
                    'Members',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const Spacer(),
                  if (_isAdmin)
                    Text(
                      'Long-press to manage',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: AppTheme.textSecondary,
                          ),
                    ),
                ],
              ),
            ),
            for (final member in g.members)
              ListTile(
                leading: CircleAvatar(
                  backgroundColor: AppTheme.cardDark,
                  backgroundImage: (_userById(member.userId)?.avatar ?? '').startsWith('http')
                      ? NetworkImage(_userById(member.userId)!.avatar)
                      : null,
                  child: (_userById(member.userId)?.avatar ?? '').startsWith('http')
                      ? null
                      : Text(
                          (_userById(member.userId)?.name ?? member.userId)
                              .substring(0, 1)
                              .toUpperCase(),
                          style: const TextStyle(color: Colors.white),
                        ),
                ),
                title: Text(_userById(member.userId)?.name ?? member.userId),
                subtitle: Text(member.role == GroupRole.admin ? 'Admin' : 'Member'),
                trailing: member.role == GroupRole.admin
                    ? const Icon(Icons.shield, color: AppTheme.primaryCyan)
                    : null,
                onLongPress: () => _showMemberOptions(member),
              ),
            const SizedBox(height: 12),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  'Activity Log',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
              ),
            ),
            if (g.activity.isEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
                child: Text(
                  'No activity yet.',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(color: AppTheme.textSecondary),
                ),
              )
            else
              for (final e in g.activity.reversed.take(20))
                ListTile(
                  dense: true,
                  leading: const Icon(Icons.history, color: AppTheme.textSecondary, size: 18),
                  title: Text(e.event),
                  subtitle: Text('${e.timestamp} • actor: ${e.actorId}'),
                ),
            const SizedBox(height: 24),
            if (g.createdBy == MockData.currentUser.id || _isAdmin)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: SizedBox(
                  width: double.infinity,
                  child: OutlinedButton(
                    onPressed: _deleteGroup,
                    style: OutlinedButton.styleFrom(
                      foregroundColor: AppTheme.errorRed,
                      side: const BorderSide(color: AppTheme.errorRed),
                    ),
                    child: const Text('Delete Group'),
                  ),
                ),
              ),
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }
}


