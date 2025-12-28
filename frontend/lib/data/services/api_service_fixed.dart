import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart' show kIsWeb, debugPrint, kDebugMode;
import 'dart:async';
import 'dart:io' as io;

class ApiService {
  late final Dio _dio;
  
  // Debug flag - set to false in production
  static const bool _debug = kDebugMode;
  
  void _log(String message) {
    if (_debug) {
      debugPrint(message);
    }
  }

  ApiService() {
    _dio = Dio(BaseOptions(
      baseUrl: _getBaseUrl(),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
    ));

    // Add interceptors for debugging and error handling
    _dio.interceptors.add(LogInterceptor(
      requestBody: _debug,
      responseBody: _debug,
      logPrint: (obj) => _log(obj.toString()),
    ));

    _dio.interceptors.add(InterceptorsWrapper(
      onError: (error, handler) {
        _log('API Error: ${error.message}');
        handler.next(error);
      },
    ));
  }

  String _getBaseUrl() {
    if (kIsWeb) {
      return 'http://localhost:8000';
    } else if (!kIsWeb && io.Platform.isAndroid) {
      return 'https://10.0.2.2:8000';
    } else if (!kIsWeb && io.Platform.isIOS) {
      return 'https://127.0.0.1:8000';
    } else if (!kIsWeb && io.Platform.isWindows) {
      return 'http://localhost:8000';
    } else if (!kIsWeb && io.Platform.isMacOS) {
      return 'http://localhost:8000';
    } else if (!kIsWeb && io.Platform.isLinux) {
      return 'http://localhost:8000';
    } else {
      return 'http://localhost:8000';
    }
  }



  // Future methods that use File and Directory should be wrapped in !kIsWeb checks
  Future<List<String>> getLocalFiles(String localStoragePath) async {
    if (kIsWeb) {
      _log('[LOCAL_STORAGE] Local file listing not available on web');
      return [];
    }

    try {
      _log('[LOCAL_STORAGE] Listing files in: $localStoragePath');
      
      if (!kIsWeb) {
        // Mobile platform
        final directory = io.Directory(localStoragePath);
        
        if (!await directory.exists()) {
          _log('[LOCAL_STORAGE] Directory does not exist: $localStoragePath');
          return [];
        }
        
        final files = await directory.list().toList();
        final fileNames = files
            .whereType<io.File>()
            .map((file) => file.path.split('/').last)
            .toList();
        
        _log('[LOCAL_STORAGE] Found ${fileNames.length} files');
        return fileNames;
      } else {
        return [];
      }
    } catch (e) {
      _log('[LOCAL_STORAGE] Error listing files: $e');
      return [];
    }
  }
}