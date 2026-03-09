// Stub implementation for web platform
// This file provides web-compatible stubs for dart:io functionality

import 'dart:html' as html;
import 'dart:typed_data';

// Stub Directory class
class StubDirectory {
  final String path;
  StubDirectory(this.path);
  
  static StubDirectory(String path) => StubDirectory(path);
}

// Stub File class
class StubFile {
  final String path;
  StubFile(this.path);
  
  static StubFile(String path) => StubFile(path);
  
  StubDirectory get parent => StubDirectory(path.substring(0, path.lastIndexOf('/')));
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
StubDirectory getApplicationDocumentsDirectory() {
  throw UnsupportedError('getApplicationDocumentsDirectory is not supported on web platform');
}

StubDirectory getDownloadsDirectory() {
  throw UnsupportedError('getDownloadsDirectory is not supported on web platform');
}

StubDirectory getExternalStorageDirectory() {
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
