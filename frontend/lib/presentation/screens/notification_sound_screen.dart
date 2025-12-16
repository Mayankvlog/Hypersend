import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/theme/app_theme.dart';

class NotificationSoundScreen extends StatefulWidget {
  const NotificationSoundScreen({super.key});

  @override
  State<NotificationSoundScreen> createState() => _NotificationSoundScreenState();
}

class _NotificationSoundScreenState extends State<NotificationSoundScreen> {
  late String _selectedSound;
  final List<Map<String, String>> sounds = [
    {'name': 'Default', 'file': 'default.mp3'},
    {'name': 'Chime', 'file': 'chime.mp3'},
    {'name': 'Bell', 'file': 'bell.mp3'},
    {'name': 'Notification', 'file': 'notification.mp3'},
    {'name': 'Pop', 'file': 'pop.mp3'},
    {'name': 'Ping', 'file': 'ping.mp3'},
    {'name': 'Silence', 'file': 'silence.mp3'},
  ];

  @override
  void initState() {
    super.initState();
    _selectedSound = 'default.mp3';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('Notification Sound'),
      ),
      body: ListView.builder(
        itemCount: sounds.length,
        itemBuilder: (context, index) {
          final sound = sounds[index];
          final isSelected = _selectedSound == sound['file'];

          return InkWell(
            onTap: () {
              setState(() {
                _selectedSound = sound['file']!;
              });
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('${sound['name']} selected'),
                  backgroundColor: AppTheme.successGreen,
                  duration: const Duration(milliseconds: 800),
                ),
              );
            },
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Row(
                children: [
                  Icon(
                    Icons.music_note,
                    color: isSelected ? AppTheme.primaryCyan : AppTheme.textSecondary,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      sound['name']!,
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                        color: isSelected ? AppTheme.primaryCyan : AppTheme.textPrimary,
                      ),
                    ),
                  ),
                  if (isSelected)
                    const Icon(
                      Icons.check_circle,
                      color: AppTheme.primaryCyan,
                    ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}
