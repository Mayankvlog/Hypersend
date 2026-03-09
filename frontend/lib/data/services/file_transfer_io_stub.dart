// Stub implementation for web platform
// This file provides web-compatible stubs for dart:io functionality

@pragma('dart:web')
import 'package:web/web.dart' as html;
import 'dart:typed_data';
import 'dart:js_interop';

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
}

class HttpClientRequest {
  HttpHeaders headers = HttpHeaders();
  
  set contentType(String type) {
    headers.set('content-type', type);
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
  anchor.click();
  html.URL.revokeObjectURL(url);
}

Future<void> openFile(String filePath) async {
  throw UnsupportedError('openFile is not supported on web platform');
}
