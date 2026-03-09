// Stub implementation for web platform
// This file provides web-compatible stubs for dart:io functionality

@pragma('dart:html')
import 'dart:html' as html;
import 'dart:typed_data';
import 'dart:async';

// Re-export path for compatibility
import 'package:path/path.dart' as path;

// Stub Directory class
class Directory {
  final String _path;
  Directory(this._path);
  
  String get path => _path;
  Directory get parent => Directory(path.substring(0, path.lastIndexOf('/')));
  
  Future<bool> exists() async => false;
  Future<void> create({bool recursive = false}) async {}
  String get name => path.split('/').last;
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

class HttpClientRequest {
  Map<String, String> headers = {};
  
  void set contentType(String type) {
    headers['content-type'] = type;
  }
  
  Future<HttpClientResponse> addStream(Stream<List<int>> stream) async => HttpClientResponse();
  Future<HttpClientResponse> close() async => HttpClientResponse();
}

class HttpClientResponse {
  Stream<List<int>> get stream => Stream.empty();
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
  // Create a blob and download it
  final blob = html.Blob([bytes]);
  final url = html.Url.createObjectUrlFromBlob(blob);
  final anchor = html.AnchorElement(href: url)
    ..setAttribute('download', fileName)
    ..click();
  html.Url.revokeObjectUrl(url);
}

Future<void> openFile(String filePath) async {
  throw UnsupportedError('openFile is not supported on web platform');
}
