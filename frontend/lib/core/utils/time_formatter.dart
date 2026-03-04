import 'package:intl/intl.dart';

class TimeFormatter {
  /// Safety helper: if we accidentally receive a UTC DateTime, convert it.
  ///
  /// Message.fromApi now performs `.toLocal()` immediately after parsing
  /// incoming ISO strings, so this function mostly guards against any
  /// remaining UTC values that slipped through.
  static DateTime _ensureLocalTime(DateTime date) {
    if (date.isUtc) {
      return date.toLocal();
    }
    return date;
  }

  static String formatChatListTime(DateTime date) {
    final localDate = _ensureLocalTime(date);
    final now = DateTime.now();
    final difference = now.difference(localDate);

    if (difference.inDays == 0) {
      return DateFormat('h:mm a').format(localDate);
    } else if (difference.inDays == 1) {
      return 'Yesterday';
    } else if (difference.inDays < 7) {
      return DateFormat('EEE').format(localDate);
    } else if (difference.inDays < 14) {
      return 'Last week';
    } else if (difference.inDays < 60) {
      final weeks = (difference.inDays / 7).floor();
      return '$weeks weeks ago';
    } else {
      final months = (difference.inDays / 30).floor();
      return '$months mo ago';
    }
  }

  static String formatMessageTime(DateTime date) {
    final localDate = _ensureLocalTime(date);
    return DateFormat('h:mm a').format(localDate);
  }

  static String formatDateDivider(DateTime date) {
    final localDate = _ensureLocalTime(date);
    final now = DateTime.now();
    final difference = now.difference(localDate);

    if (difference.inDays == 0) {
      return 'Today';
    } else if (difference.inDays == 1) {
      return 'Yesterday';
    } else {
      return DateFormat('MMMM d, yyyy').format(localDate);
    }
  }

  /// Format file transfer time duration (e.g., "2.5 MB/s", "00:45 remaining")
  static String formatTransferSpeed(double bytesPerSecond) {
    if (bytesPerSecond < 1024) {
      return '${bytesPerSecond.toStringAsFixed(2)} B/s';
    } else if (bytesPerSecond < 1024 * 1024) {
      return '${(bytesPerSecond / 1024).toStringAsFixed(2)} KB/s';
    } else {
      return '${(bytesPerSecond / (1024 * 1024)).toStringAsFixed(2)} MB/s';
    }
  }

  /// Format remaining time in human-readable format
  static String formatRemainingTime(Duration remaining) {
    final hours = remaining.inHours;
    final minutes = remaining.inMinutes % 60;
    final seconds = remaining.inSeconds % 60;

    if (hours > 0) {
      return '${hours}h ${minutes}m remaining';
    } else if (minutes > 0) {
      return '${minutes}m ${seconds}s remaining';
    } else {
      return '${seconds}s remaining';
    }
  }
}