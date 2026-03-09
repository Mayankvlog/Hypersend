// Platform-specific IO operations for file transfer on mobile/desktop platforms
import 'dart:io';
import 'dart:typed_data';
import 'package:path_provider/path_provider.dart';

// Re-export dart:io classes with proper namespace
export 'dart:io' show Directory, File, Platform, HttpClient, HttpClientRequest, HttpClientResponse;

// ContentType re-export
class ContentType {
  static ContentType parse(String mimeType) {
    return ContentType._(mimeType);
  }
  
  final String mimeType;
  ContentType._(this.mimeType);
}

// Platform-specific directory getters
Future<Directory> getApplicationDocumentsDirectory() async {
  return await getApplicationSupportDirectory();
}

Future<Directory?> getDownloadsDirectory() async {
  if (Platform.isAndroid) {
    // For Android, use the external storage directory
    final externalDir = await getExternalStorageDirectory();
    if (externalDir != null) {
      return Directory('${externalDir.path}/Download');
    }
  } else if (Platform.isIOS) {
    // For iOS, use the documents directory
    return await getApplicationDocumentsDirectory();
  } else {
    // For desktop platforms, try to get the downloads directory
    try {
      if (Platform.isWindows) {
        return Directory('${Platform.environment['USERPROFILE']}\\Downloads');
      } else if (Platform.isMacOS) {
        return Directory('${Platform.environment['HOME']}/Downloads');
      } else if (Platform.isLinux) {
        return Directory('${Platform.environment['HOME']}/Downloads');
      }
    } catch (e) {
      // Fallback to documents directory
      return await getApplicationDocumentsDirectory();
    }
  }
  return null;
}

Future<Directory?> getExternalStorageDirectory() async {
  return await getExternalStorageDirectory();
}

// Platform-specific file operations
Future<void> saveFileToDownloads(String fileName, Uint8List bytes) async {
  final downloadsDir = await getDownloadsDirectory();
  if (downloadsDir != null) {
    final file = File('${downloadsDir.path}/$fileName');
    await file.writeAsBytes(bytes);
  } else {
    throw Exception('Could not access downloads directory');
  }
}

Future<void> openFile(String filePath) async {
  final file = File(filePath);
  if (!await file.exists()) {
    throw Exception('File does not exist: $filePath');
  }

  if (Platform.isAndroid || Platform.isIOS) {
    // For mobile platforms, you might want to use a plugin like url_launcher
    // This is a placeholder implementation
    throw UnsupportedError('File opening not implemented for mobile platforms');
  } else if (Platform.isWindows) {
    await Process.run('start', [filePath], runInShell: true);
  } else if (Platform.isMacOS) {
    await Process.run('open', [filePath]);
  } else if (Platform.isLinux) {
    await Process.run('xdg-open', [filePath]);
  } else {
    throw Exception('Unsupported platform for file opening: ${Platform.operatingSystem}');
  }
}
