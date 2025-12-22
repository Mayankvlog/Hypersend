import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';
import '../../data/services/service_provider.dart';

class ChannelCreationScreen extends StatefulWidget {
  const ChannelCreationScreen({super.key});

  @override
  State<ChannelCreationScreen> createState() => _ChannelCreationScreenState();
}

class _ChannelCreationScreenState extends State<ChannelCreationScreen> {
  final _nameCtrl = TextEditingController();
  final _descCtrl = TextEditingController();
  final _usernameCtrl = TextEditingController();
  final _avatarCtrl = TextEditingController();
  bool _loading = false;

  @override
  void dispose() {
    _nameCtrl.dispose();
    _descCtrl.dispose();
    _usernameCtrl.dispose();
    _avatarCtrl.dispose();
    super.dispose();
  }

  Future<void> _createChannel() async {
    final name = _nameCtrl.text.trim();
    if (name.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Channel name is required')));
      return;
    }

    setState(() => _loading = true);
    try {
      final resp = await serviceProvider.apiService.createChannel(
        name: name,
        description: _descCtrl.text.trim(),
        avatarUrl: _avatarCtrl.text.trim().isEmpty ? null : _avatarCtrl.text.trim(),
        username: _usernameCtrl.text.trim().isEmpty ? null : _usernameCtrl.text.trim(),
      );

      final channelId = (resp['_id'] ?? resp['channel_id'] ?? resp['id'] ?? '').toString();
      if (channelId.isEmpty) throw Exception('Invalid channel response');
      if (!mounted) return;
      // Navigate to chat view for the new channel
      context.go('/chat/$channelId');
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed to create channel: $e')));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Create Channel'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(AppTheme.spacing16),
        child: Column(
          children: [
            TextField(
              controller: _nameCtrl,
              decoration: const InputDecoration(labelText: 'Channel Name'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _usernameCtrl,
              decoration: const InputDecoration(labelText: 'Username (optional)'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _descCtrl,
              decoration: const InputDecoration(labelText: 'Description (optional)'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _avatarCtrl,
              decoration: const InputDecoration(labelText: 'Avatar URL (optional)'),
            ),
            const SizedBox(height: 20),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: _loading ? null : _createChannel,
                child: Text(_loading ? 'Creating…' : 'Create Channel'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
