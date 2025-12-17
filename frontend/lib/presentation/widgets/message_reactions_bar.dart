import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';

class MessageReactionsBar extends StatelessWidget {
  final Map<String, List<String>> reactions;
  final void Function(String emoji) onToggleReaction;
  final VoidCallback onAddReaction;

  const MessageReactionsBar({
    super.key,
    required this.reactions,
    required this.onToggleReaction,
    required this.onAddReaction,
  });

  @override
  Widget build(BuildContext context) {
    final entries = reactions.entries.toList()
      ..sort((a, b) => b.value.length.compareTo(a.value.length));

    return Wrap(
      spacing: 6,
      runSpacing: 6,
      children: [
        for (final entry in entries)
          InkWell(
            onTap: () => onToggleReaction(entry.key),
            borderRadius: BorderRadius.circular(14),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: AppTheme.cardDark.withValues(alpha: 0.65),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(
                  color: AppTheme.dividerColor.withValues(alpha: 0.7),
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(entry.key, style: const TextStyle(fontSize: 14)),
                  const SizedBox(width: 6),
                  Text(
                    entry.value.length.toString(),
                    style: const TextStyle(
                      fontSize: 12,
                      color: AppTheme.textSecondary,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ),
        InkWell(
          onTap: onAddReaction,
          borderRadius: BorderRadius.circular(14),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: AppTheme.cardDark.withValues(alpha: 0.35),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(
                color: AppTheme.dividerColor.withValues(alpha: 0.6),
              ),
            ),
            child: const Icon(
              Icons.add,
              size: 16,
              color: AppTheme.textSecondary,
            ),
          ),
        ),
      ],
    );
  }
}


