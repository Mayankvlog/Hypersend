// Stub implementation for web platform
// This file provides web-compatible stubs for dart:io functionality

@pragma('dart:web')
import 'package:web/web.dart' as html;
import 'dart:typed_data';
import 'dart:js_interop';
import 'package:flutter/foundation.dart' show debugPrint;

// Re-export path for compatibility - not used in web stub

// Stub Directory class
class Directory {
  final String _path;
  Directory(this._path);
  
  String get path => _path;
  Directory get parent {
    final idx = _path.lastIndexOf('/');
    if (idx == -1) {
      // No parent directory
      return Directory('');
    } else if (idx == 0) {
      // Root parent
      return Directory('/');
    } else {
      return Directory(_path.substring(0, idx));
    }
  }
  
  Future<bool> exists() async => false;
  Future<void> create({bool recursive = false}) async {}
  String get name => _path.split('/').last;
}

// Stub File class
class File {
  final String path;
  File(this.path);
  
  Directory get parent => Directory(path.substring(0, path.lastIndexOf('/')));
  
  Future<bool> exists() async => false;
  Future<void> writeAsBytes(List<int> bytes) async {}
  Future<void> writeAsString(String content) async {}
  Future<Uint8List> readAsBytes() async => Uint8List(0);
  Future<String> readAsString() async => '';
  String get name => path.split('/').last;
  Future<void> delete() async {}
  Future<int> length() async => 0;
}

// Stub Platform class
class Platform {
  static bool get isAndroid => false;
  static bool get isIOS => false;
  static bool get isWindows => false;
  static bool get isLinux => false;
  static bool get isMacOS => false;
  static String get operatingSystem => 'web';
}

// Stub Process class
class Process {
  static Future<ProcessResult> run(String command, List<String> args, {bool runInShell = false}) async {
    throw UnsupportedError('Process.run is not supported on web platform');
  }
}

class ProcessResult {
  final int exitCode;
  final String stdout;
  final String stderr;
  
  ProcessResult(this.exitCode, this.stdout, this.stderr);
}

// Stub HttpClient class
class HttpClient {
  HttpClientRequest get(Uri url, {Map<String, String>? headers}) => HttpClientRequest();
  HttpClientRequest post(Uri url, {Map<String, String>? headers}) => HttpClientRequest();
  Future<HttpClientRequest> putUrl(Uri url) async => HttpClientRequest();
  void close() {}
}

class HttpClientRequest {
  Map<String, String> headers = {};
  
  set contentType(String type) {
    headers['content-type'] = type;
  }
  
  void add(List<int> data) {}
  
  Future<HttpClientResponse> addStream(Stream<List<int>> stream) async => HttpClientResponse();
  Future<HttpClientResponse> close() async => HttpClientResponse();
}

class HttpClientResponse {
  Stream<List<int>> get stream => Stream.empty();
  int get statusCode => 200;
}

// Stub ContentType class
class ContentType {
  static ContentType parse(String mimeType) => ContentType();
}

// Stub path functions
Directory getApplicationDocumentsDirectory() {
  throw UnsupportedError('getApplicationDocumentsDirectory is not supported on web platform');
}

Directory getDownloadsDirectory() {
  throw UnsupportedError('getDownloadsDirectory is not supported on web platform');
}

Directory getExternalStorageDirectory() {
  throw UnsupportedError('getExternalStorageDirectory is not supported on web platform');
}

Future<void> saveFileToDownloads(String fileName, Uint8List bytes) async {
  // Create a blob and download it using modern web API
  final jsArray = [bytes.toJS].toJS;
  final blob = html.Blob(jsArray);
  final url = html.URL.createObjectURL(blob);
  final anchor = html.document.createElement('a') as html.HTMLAnchorElement;
  anchor.href = url;
  anchor.download = fileName;
  
  // Append anchor to DOM, click it, then clean up after delay
  html.document.body?.append(anchor);
  anchor.click();
  
  // Delay cleanup to ensure download starts
  await Future.delayed(const Duration(milliseconds: 100));
  html.URL.revokeObjectURL(url);
  anchor.remove();
}

Future<void> openFile(String filePath) async {
  throw UnsupportedError('openFile is not supported on web platform');
}

/// **CRITICAL FIX**: Direct URL-based download 
/// This method triggers a native browser download without loading bytes into memory
/// Properly respects Content-Disposition: attachment header from backend
/// Better for large files and ensures proper file saving behavior
Future<void> saveFileDirectFromUrl(String fileName, String downloadUrl) async {
  debugPrint('[FILE_WEB] Direct URL download: $fileName');
  debugPrint('[FILE_WEB] URL: $downloadUrl');
  
  try {
    // Validate URL before processing
    if (downloadUrl.isEmpty) {
      throw Exception('Download URL is empty');
    }
    
    final uri = Uri.tryParse(downloadUrl);
    if (uri == null) {
      throw Exception('Invalid download URL: $downloadUrl');
    }
    
    // Check if URI has absolute path (safe null check)
    if (!uri.hasAbsolutePath) {
      throw Exception('URL must be absolute: $downloadUrl');
    }
    
    // Create anchor element with direct link
    final anchor = html.document.createElement('a') as html.HTMLAnchorElement;
    anchor.href = downloadUrl;
    anchor.download = fileName;
    
    // Enhanced cross-origin and security attributes
    anchor.setAttribute('rel', 'noopener noreferrer');
    anchor.setAttribute('crossorigin', 'anonymous');
    
    // Set target for better compatibility
    anchor.target = '_blank';
    
    // Add download attribute for force download
    anchor.setAttribute('download', fileName);
    
    // Append to body (required in some browsers)
    if (html.document.body != null) {
      html.document.body!.appendChild(anchor);
    }
    
    debugPrint('[FILE_WEB] Triggering download click');
    
    // Trigger the download
    anchor.click();
    
    // Delay cleanup to ensure download starts
    await Future.delayed(const Duration(milliseconds: 200));
    
    // Clean up
    try {
      if (anchor.parentNode != null) {
        anchor.parentNode!.removeChild(anchor);
      }
    } catch (cleanupError) {
      debugPrint('[FILE_WEB_ERROR] Cleanup failed: $cleanupError');
    }
    
    debugPrint('[FILE_WEB] Download initiated for: $fileName');
  } catch (e) {
    debugPrint('[FILE_WEB_ERROR] saveFileDirectFromUrl failed: $e');
    
    // Fallback: try to open URL in new tab if direct download fails
    try {
      debugPrint('[FILE_WEB] Fallback: opening URL in new tab');
      html.window.open(downloadUrl, '_blank', 'noopener,noreferrer');
    } catch (fallbackError) {
      debugPrint('[FILE_WEB_ERROR] Fallback also failed: $fallbackError');
      rethrow;
    }
  }
}
