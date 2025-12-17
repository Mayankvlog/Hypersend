import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/theme/app_theme.dart';
import '../../data/mock/mock_data.dart';
import '../../data/models/chat.dart';
import '../../data/models/group.dart';
import '../../data/models/group_activity.dart';
import '../../data/models/group_member.dart';

class GroupCreationScreen extends StatefulWidget {
  const GroupCreationScreen({super.key});

  @override
  State<GroupCreationScreen> createState() => _GroupCreationScreenState();
}

class _GroupCreationScreenState extends State<GroupCreationScreen> {
  final _groupNameController = TextEditingController();
  final _groupDescriptionController = TextEditingController();
  final Set<String> _selectedMemberIds = {};

  @override
  void dispose() {
    _groupNameController.dispose();
    _groupDescriptionController.dispose();
    super.dispose();
  }

  String _avatarFromName(String name) {
    final trimmed = name.trim();
    if (trimmed.isEmpty) return 'GR';
    final parts = trimmed.split(RegExp(r'\s+')).where((p) => p.isNotEmpty).toList();
    if (parts.length == 1) return parts.first.substring(0, parts.first.length >= 2 ? 2 : 1).toUpperCase();
    return (parts[0].substring(0, 1) + parts[1].substring(0, 1)).toUpperCase();
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

    final groupId = DateTime.now().millisecondsSinceEpoch.toString();
    final me = MockData.currentUser.id;
    final now = DateTime.now();

    final members = <GroupMember>[
      GroupMember(userId: me, role: GroupRole.admin, joinedAt: now),
      for (final uid in _selectedMemberIds)
        GroupMember(userId: uid, role: GroupRole.member, joinedAt: now),
    ];

    final group = Group(
      id: groupId,
      name: name,
      description: _groupDescriptionController.text.trim(),
      avatar: _avatarFromName(name),
      createdBy: me,
      members: members,
      activity: [
        GroupActivity(
          id: 'ga_${groupId}_1',
          event: 'group_created',
          actorId: me,
          timestamp: now,
          meta: {'name': name},
        ),
      ],
    );

    MockData.groups.insert(0, group);
    MockData.chats.insert(
      0,
      Chat(
        id: groupId,
        type: ChatType.group,
        name: name,
        avatar: group.avatar,
        lastMessage: 'Group created',
        lastMessageTime: now,
        unreadCount: 0,
        isMuted: false,
        isOnline: false,
      ),
    );

    if (!mounted) return;
    context.pop();
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Group created successfully'),
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final contacts = MockData.contacts.where((u) => u.id != MockData.currentUser.id).toList();
    final previewName = _groupNameController.text.trim();
    final previewAvatar = _avatarFromName(previewName);

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('Create Group'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(AppTheme.spacing16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: CircleAvatar(
                radius: 44,
                backgroundColor: AppTheme.cardDark,
                child: Text(
                  previewAvatar,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 22,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ),
            const SizedBox(height: 20),
            TextField(
              controller: _groupNameController,
              decoration: const InputDecoration(
                labelText: 'Group Name *',
                prefixIcon: Icon(Icons.group),
              ),
              onChanged: (_) => setState(() {}),
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
              height: 320,
              decoration: BoxDecoration(
                color: AppTheme.cardDark.withValues(alpha: 0.35),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppTheme.dividerColor),
              ),
              child: ListView.separated(
                itemCount: contacts.length,
                separatorBuilder: (_, __) => const Divider(height: 0),
                itemBuilder: (context, index) {
                  final u = contacts[index];
                  final selected = _selectedMemberIds.contains(u.id);
                  return CheckboxListTile(
                    value: selected,
                    onChanged: (v) {
                      setState(() {
                        if (v == true) {
                          _selectedMemberIds.add(u.id);
                        } else {
                          _selectedMemberIds.remove(u.id);
                        }
                      });
                    },
                    title: Text(u.name),
                    subtitle: Text(u.username),
                    secondary: CircleAvatar(
                      backgroundColor: AppTheme.inputBackground,
                      backgroundImage: u.avatar.startsWith('http') ? NetworkImage(u.avatar) : null,
                      child: u.avatar.startsWith('http')
                          ? null
                          : Text(
                              u.avatar.length > 2 ? u.avatar.substring(0, 2).toUpperCase() : u.avatar.toUpperCase(),
                              style: const TextStyle(color: Colors.white),
                            ),
                    ),
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


