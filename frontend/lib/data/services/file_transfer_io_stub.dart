// Stub implementation for web platform
// This file provides web-compatible stubs for dart:io functionality

@pragma('dart:web')
import 'package:web/web.dart' as html;
import 'dart:typed_data';
import 'dart:js_interop';
import 'package:flutter/foundation.dart' show debugPrint;

// Import Blob type from web package
typedef Blob = html.Blob;

// Re-export path for compatibility - not used in web stub

// Stub Directory class
class Directory {
  final String _path;
  Directory(this._path);
  
  String get path => _path;
  Directory get parent {
    final idx = _path.lastIndexOf('/');
    if (idx == -1) {
      // No parent directory, return current directory as fallback
      return Directory(_path);
    }
    return Directory(_path.substring(0, idx));
  }
  
  Future<bool> exists() async => false;
  Future<void> create({bool recursive = false}) async {}
  String get name => _path.split('/').last;
  
  // Add list() method for web compatibility
  Stream<FileSystemEntity> list({bool recursive = false}) async* {
    // Return empty stream for web platform
    return;
  }
}

// Stub FileSystemEntity for list() method return type
abstract class FileSystemEntity {
  String get path;
}

// Stub File class extending FileSystemEntity for list() method
class File extends FileSystemEntity {
  @override
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

// Stub HttpClient class
class HttpClient {
  HttpClientRequest get(Uri url, {Map<String, String>? headers}) => HttpClientRequest();
  HttpClientRequest post(Uri url, {Map<String, String>? headers}) => HttpClientRequest();
  Future<HttpClientRequest> putUrl(Uri url) async => HttpClientRequest();
  void close() {}
}

// Stub HttpHeaders class
class HttpHeaders {
  final Map<String, String> _headers = {};
  
  void set(String name, String value) {
    _headers[name] = value;
  }
  
  String? operator[](String name) => _headers[name];
  
  void operator[]=(String name, String value) {
    _headers[name] = value;
  }
  
  // Add direct assignment method for web compatibility
  void assign(String name, String value) {
    _headers[name] = value;
  }
}

class HttpClientRequest {
  HttpHeaders headers = HttpHeaders();
  
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
  // DEPRECATED: Use saveFileDirectFromUrl instead for better memory management
  // This method loads entire file into memory, which can fail for large files
  
  debugPrint('[FILE_WEB_STUB] saveFileToDownloads (memory-based): $fileName');
  
  try {
    // Create a blob and download it using modern web API
    final jsArray = [bytes.toJS].toJS;
    final blob = html.Blob(jsArray);
    final url = html.URL.createObjectURL(blob);
    final anchor = html.document.createElement('a') as html.HTMLAnchorElement;
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    html.URL.revokeObjectURL(url);
    debugPrint('[FILE_WEB_STUB] File download initiated: $fileName');
  } catch (e) {
    debugPrint('[FILE_WEB_STUB_ERROR] saveFileToDownloads failed: $e');
    rethrow;
  }
}

/// **CRITICAL FIX**: Direct URL-based download 
/// This method triggers a native browser download without loading bytes into memory
/// Properly respects Content-Disposition: attachment header from backend
/// Better for large files and ensures proper file saving behavior
Future<void> saveFileDirectFromUrl(String fileName, String downloadUrl) async {
  debugPrint('[FILE_WEB_STUB] Fetch-based download: $fileName');
  debugPrint('[FILE_WEB_STUB] URL: $downloadUrl');
  
  try {
    // Use fetch API to properly handle the download with authentication
    debugPrint('[FILE_WEB_STUB] Starting fetch request...');
    
    // Use fetch to get the response as a blob
    final result = await html.window.fetch(downloadUrl, {
      'method': 'GET',
      'credentials': 'include', // Include cookies for authentication
      'headers': {'Accept': '*/*'},
    });
    
    // Check response status
    final fetchResponse = result as html.Response;
    if (!fetchResponse.ok) {
      print('[FILE_WEB_STUB_ERROR] Fetch failed with status: ${fetchResponse.status}');
      if (fetchResponse.status == 404) {
        throw Exception('Media file not found (404)');
      } else if (fetchResponse.status == 403) {
        throw Exception('Access denied - please login (403)');
      } else {
        throw Exception('Download failed: ${fetchResponse.statusText}');
      }
    }
    
    debugPrint('[FILE_WEB_STUB] Fetch successful, status: ${fetchResponse.status}');
    
    // Convert response to blob
    debugPrint('[FILE_WEB_STUB] Converting response to blob...');
    final blob = await fetchResponse.blob();
    
    debugPrint('[FILE_WEB_STUB] Blob size: ${blob.size} bytes');
    
    if (blob.size == 0) {
      throw Exception('Downloaded file is empty');
    }
    
    // Create blob URL
    debugPrint('[FILE_WEB_STUB] Creating blob URL...');
    final blobUrl = html.Url.createObjectUrl(blob);
    
    try {
      // Create anchor element
      final anchor = html.document.createElement('a') as html.HTMLAnchorElement;
      anchor.href = blobUrl;
      anchor.download = fileName;
      
      // Set rel="noopener" to prevent window manipulation
      anchor.setAttribute('rel', 'noopener');
      
      // Append to body (required in some browsers)
      html.document.body?.appendChild(anchor);
      
      debugPrint('[FILE_WEB_STUB] Triggering download click for: $fileName');
      
      // Trigger the download
      anchor.click();
      
      // Clean up
      html.document.body?.removeChild(anchor);
      
      debugPrint('[FILE_WEB_STUB] Download initiated for: $fileName');
    } finally {
      // Release blob URL after a short delay (allow time for download to start)
      Future.delayed(const Duration(milliseconds: 100), () {
        html.Url.revokeObjectUrl(blobUrl);
        debugPrint('[FILE_WEB_STUB] Blob URL revoked');
      });
    }
  } catch (e) {
    debugPrint('[FILE_WEB_STUB_ERROR] saveFileDirectFromUrl failed: $e');
    rethrow;
  }
}

Future<void> openFile(String filePath) async {
  throw UnsupportedError('openFile is not supported on web platform');
}
