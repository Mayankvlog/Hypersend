import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';
import '../../data/services/service_provider.dart';

class SecretChatScreen extends StatefulWidget {
  const SecretChatScreen({super.key});

  @override
  State<SecretChatScreen> createState() => _SecretChatScreenState();
}

class _SecretChatScreenState extends State<SecretChatScreen> {
  final _searchCtrl = TextEditingController();
  List<Map<String, dynamic>> _results = [];
  bool _loading = false;

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  Future<void> _search(String q) async {
    if (q.trim().isEmpty) return;
    setState(() => _loading = true);
    try {
      final res = await serviceProvider.apiService.searchUsers(q.trim());
      if (!mounted) return;
      setState(() => _results = res);
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Search failed: $e')));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _startSecretChat(Map<String, dynamic> user) async {
    final userId = (user['_id'] ?? user['id'] ?? '').toString();
    if (userId.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Unable to determine user id')));
      return;
    }

    setState(() => _loading = true);
    try {
      final resp = await serviceProvider.apiService.createGroup(
        name: 'Secret chat',
        description: 'Secret chat',
        memberIds: [userId],
        avatarUrl: null,
      );
      final chatId = (resp['_id'] ?? resp['group_id'] ?? resp['id'] ?? '').toString();
      if (chatId.isEmpty) throw Exception('Invalid response');
      if (!mounted) return;
      context.go('/chat/$chatId');
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed to start secret chat: $e')));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('New Secret Chat')),
      body: Padding(
        padding: const EdgeInsets.all(AppTheme.spacing16),
        child: Column(
          children: [
            TextField(
              controller: _searchCtrl,
              decoration: InputDecoration(
                hintText: 'Search users by name or username',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searchCtrl.text.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear),
                        onPressed: () {
                          _searchCtrl.clear();
                          setState(() => _results = []);
                        },
                      )
                    : null,
              ),
              onSubmitted: _search,
            ),
            const SizedBox(height: 12),
            _loading
                ? const Center(child: CircularProgressIndicator())
                : Expanded(
                    child: ListView.builder(
                      itemCount: _results.length,
                      itemBuilder: (context, index) {
                        final u = _results[index];
                        final display = (u['name'] ?? u['username'] ?? u['email'] ?? '').toString();
                        final sub = (u['username'] ?? u['email'] ?? '').toString();
                        return ListTile(
                          title: Text(display.isEmpty ? sub : display),
                          subtitle: sub.isNotEmpty ? Text(sub) : null,
                          onTap: () => _startSecretChat(u),
                        );
                      },
                    ),
                  ),
          ],
        ),
      ),
    );
  }
}
