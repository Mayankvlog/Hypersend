import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart' show kIsWeb, debugPrint, kDebugMode;
import 'package:file_picker/file_picker.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:async';
import 'dart:math';

// Conditional import: dart:io only available on mobile/desktop platforms
import '../../core/constants/api_constants.dart';
import 'service_provider.dart';

// Platform-specific imports (dart:io is only used when not running on web)
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

  Map<String, dynamic> _mergeAuthHeaders(Map<String, dynamic> headers) {
    final merged = <String, dynamic>{};
    final auth = _dio.options.headers['Authorization'];
    if (auth != null) {
      merged['Authorization'] = auth;
    }
    merged.addAll(headers);
    return merged;
  }

  // Token refresh will be handled by error interceptor

  // Intelligent base URL selection with fallback logic
  String _getOptimalBaseUrl() {
    final urls = [
      'https://zaply.in.net/api/v1',
      'https://www.zaply.in.net/api/v1',
    ];

    // For now, return the primary URL
    // In a real implementation, you could test connectivity first
    return urls.first;
  }

  // Check server connectivity before making requests
  Future<bool> checkServerConnectivity() async {
    final urls = [
      'https://zaply.in.net/health',
      'https://www.zaply.in.net/health',
    ];
    
    for (String url in urls) {
      try {
        _log('[CONNECTIVITY_CHECK] Testing: $url');
        final response = await Dio().get(
          url,
          options: Options(
            sendTimeout: const Duration(seconds: 10),
            receiveTimeout: const Duration(seconds: 10),
            validateStatus: (status) => status == 200,
          ),
        );
        if (response.statusCode == 200) {
          _log('[CONNECTIVITY_CHECK] ✅ Server reachable at: $url');
          return true;
        }
      } catch (e) {
        _log('[CONNECTIVITY_CHECK] ❌ Failed: $url - $e');
        continue;
      }
    }
    
    _log('[CONNECTIVITY_CHECK] ❌ All server endpoints unreachable');
    return false;
  }

  ApiService() {
    try {
      String url = _getOptimalBaseUrl();
      if (!url.endsWith('/')) {
        url += '/';
      }
      
      _log('[API_INIT] Base URL: $url');
      _log('[API_INIT] Server Base URL: ${ApiConstants.serverBaseUrl}');
      _log('[API_INIT] Auth endpoint: ${ApiConstants.authEndpoint}');
      _log('[API_INIT] Users endpoint: ${ApiConstants.usersEndpoint}');
      _log('[API_INIT] Full avatar URL: $url${ApiConstants.usersEndpoint}/avatar');
      _log('[API_INIT] SSL validation: ${ApiConstants.validateCertificates}');

      _dio = Dio(
      BaseOptions(
        baseUrl: url,
        // CRITICAL FIX: Adaptive timeouts for large file operations
        connectTimeout: const Duration(minutes: 10),  // Increased for 40GB files
        receiveTimeout: const Duration(hours: 2),    // Decreased for faster networks
        sendTimeout: const Duration(minutes: 5),     // Decreased for smaller uploads
          contentType: 'application/json',
          validateStatus: (status) => status != null && (status >= 200 && status < 300),
        headers: {
          'User-Agent': 'zaply-Flutter-Web/1.0',
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
      ),
    );

    // SSL validation - platform-specific handling
    // SECURITY: SSL validation enabled by default to prevent MITM attacks
    // Only disabled for self-signed development certificates
    
    // LOGIC: Check both kDebugMode AND !validateCertificates 
    // to prevent accidental insecure production deployments
    if (kDebugMode && !ApiConstants.validateCertificates) {
      // Development mode: allow self-signed certs on mobile only
      if (!kIsWeb) {
        // Mobile development: allow self-signed certificates (development only)
        (_dio.httpClientAdapter as dynamic).onHttpClientCreate = (client) {
          client.badCertificateCallback = (cert, host, port) => true;
          return client;
        };
        _log('[API_SECURITY] ⚠️  SSL validation disabled - DEBUG MODE (mobile development only)');
        _log('[API_SECURITY] ⚠️  WARNING: This should NEVER be enabled in production!');
      } else if (kIsWeb) {
        // Web platform: SSL validation CANNOT be disabled - browser enforces it
        // This is intentional security boundary - Flutter Web always validates SSL
        _log('[API_SECURITY] 🔒 SSL validation ENFORCED (Flutter Web - browser controls)');
        _log('[API_SECURITY] 🔒 Browsers enforce certificate validation - cannot be disabled');
        _log('[API_SECURITY] 💡 Use valid SSL certificates for zaply.in.net development');
      }
    } else {
      // Production or release mode: SSL validation ALWAYS enabled
      _log('[API_SECURITY] 🔒 SSL validation ENABLED - SECURE');
      _log('[API_SECURITY] ✓ Protected against man-in-the-middle (MITM) attacks');
      if (!kDebugMode) {
        _log('[API_SECURITY] ✓ Running in PRODUCTION mode - maximum security');
      }
    }

    // Add interceptor for logging (disabled print to avoid leaking secrets)
    _dio.interceptors.add(LogInterceptor(
      requestBody: false,
      responseBody: false,
      logPrint: (obj) {},
    ));
    
    // Add request interceptor to ensure auth tokens are sent
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          // Ensure Content-Type is set for all requests if not already set
          if (!options.headers.containsKey('Content-Type')) {
            options.headers['Content-Type'] = 'application/json';
          }
          // Log auth header for debugging
          final authHeader = options.headers['Authorization'];
          if (authHeader != null) {
            _log('[API_REQ] ${options.method} ${options.uri.path} - Auth: present');
          } else {
            _log('[API_REQ_WARN] ${options.method} ${options.uri.path} - Auth: MISSING!');
          }
          return handler.next(options);
        },
        onError: (error, handler) async {
          // PERMANENT FIX: Implement automatic retry with exponential backoff for connection errors
          // This ensures transient errors (server starting up, temporary network issues) don't cause permanent failures
          
          final isConnectionError = error.type == DioExceptionType.connectionError ||
                                   error.type == DioExceptionType.connectionTimeout ||
                                   error.type == DioExceptionType.receiveTimeout;
          
          final isRetryable = isConnectionError ||
                             (error.response?.statusCode != null && 
                              [502, 503, 504].contains(error.response?.statusCode));
          
          // Log network errors with detailed info
          if (error.response?.statusCode == null) {
            _log('[API_ERROR] Network/Connection error: ${error.message}');
            _log('[API_ERROR] URL: ${error.requestOptions.uri}');
            _log('[API_ERROR] Method: ${error.requestOptions.method}');
            _log('[API_ERROR] Type: ${error.type}');
            _log('[API_ERROR] Backend unreachable - ensure server is running');
            
            // PERMANENT FIX: Retry with exponential backoff (max 3 attempts with 2s, 4s, 8s delays)
            if (isRetryable) {
              int retryCount = (error.requestOptions.extra['retryCount'] as int?) ?? 0;
              const maxRetries = 3;
              
              if (retryCount < maxRetries) {
                retryCount++;
                final delaySeconds = pow(2, retryCount).toInt(); // 2s, 4s, 8s
                
                _log('[API_RETRY] Attempt $retryCount/$maxRetries - Retrying in ${delaySeconds}s...');
                await Future.delayed(Duration(seconds: delaySeconds));
                
                // Update retry count and retry
                error.requestOptions.extra['retryCount'] = retryCount;
                try {
                  final response = await _dio.request<dynamic>(
                    error.requestOptions.path,
                    cancelToken: error.requestOptions.cancelToken,
                    data: error.requestOptions.data,
                    onReceiveProgress: error.requestOptions.onReceiveProgress,
                    onSendProgress: error.requestOptions.onSendProgress,
                    queryParameters: error.requestOptions.queryParameters,
                    options: Options(
                      method: error.requestOptions.method,
                      sendTimeout: error.requestOptions.sendTimeout,
                      receiveTimeout: error.requestOptions.receiveTimeout,
                      extra: error.requestOptions.extra,
                      headers: error.requestOptions.headers,
                      responseType: error.requestOptions.responseType,
                      contentType: error.requestOptions.contentType,
                      validateStatus: error.requestOptions.validateStatus,
                      receiveDataWhenStatusError: error.requestOptions.receiveDataWhenStatusError,
                      followRedirects: error.requestOptions.followRedirects,
                      maxRedirects: error.requestOptions.maxRedirects,
                      persistentConnection: error.requestOptions.persistentConnection,
                    ),
                  );
                  return handler.resolve(response);
                } catch (e) {
                  _log('[API_RETRY] Retry failed: $e');
                  return handler.next(error);
                }
              } else {
                _log('[API_RETRY] Max retries ($maxRetries) reached - giving up');
              }
            }
          } else {
            _log('[API_ERROR] HTTP ${error.response?.statusCode}: ${error.message}');
            
            // PERMANENT FIX: Retry 502/503/504 server errors with backoff
            if (isRetryable && error.response?.statusCode != null) {
              int retryCount = (error.requestOptions.extra['retryCount'] as int?) ?? 0;
              const maxRetries = 3;
              
              if (retryCount < maxRetries) {
                retryCount++;
                final delaySeconds = pow(2, retryCount).toInt();
                
                _log('[API_RETRY] Server error ${error.response?.statusCode} - Attempt $retryCount/$maxRetries - Retrying in ${delaySeconds}s...');
                await Future.delayed(Duration(seconds: delaySeconds));
                
                error.requestOptions.extra['retryCount'] = retryCount;
                try {
                  final response = await _dio.request<dynamic>(
                    error.requestOptions.path,
                    cancelToken: error.requestOptions.cancelToken,
                    data: error.requestOptions.data,
                    onReceiveProgress: error.requestOptions.onReceiveProgress,
                    onSendProgress: error.requestOptions.onSendProgress,
                    queryParameters: error.requestOptions.queryParameters,
                    options: Options(
                      method: error.requestOptions.method,
                      sendTimeout: error.requestOptions.sendTimeout,
                      receiveTimeout: error.requestOptions.receiveTimeout,
                      extra: error.requestOptions.extra,
                      headers: error.requestOptions.headers,
                      responseType: error.requestOptions.responseType,
                      contentType: error.requestOptions.contentType,
                      validateStatus: error.requestOptions.validateStatus,
                      receiveDataWhenStatusError: error.requestOptions.receiveDataWhenStatusError,
                      followRedirects: error.requestOptions.followRedirects,
                      maxRedirects: error.requestOptions.maxRedirects,
                      persistentConnection: error.requestOptions.persistentConnection,
                    ),
                  );
                  return handler.resolve(response);
                } catch (e) {
                  _log('[API_RETRY] Retry failed: $e');
                  return handler.next(error);
                }
              }
            }
            
            // Special handling for 405 Method Not Allowed to prevent infinite loops
            if (error.response?.statusCode == 405) {
              _log('[API_ERROR] 405 Method Not Allowed on ${error.requestOptions.uri}');
              _log('[API_ERROR] Used method: ${error.requestOptions.method}');
              _log('[API_ERROR] Expected method: POST (for avatar upload)');
              _log('[API_ERROR] This error indicates GET request to POST endpoint!');
              _log('[API_ERROR] ERROR: 405 errors should NOT be retried under any circumstances!');
            }
            
            // Log 401 specifically with headers info for debugging
            if (error.response?.statusCode == 401) {
              _log('[API_ERROR] 401 Unauthorized on ${error.requestOptions.uri}');
              _log('[API_ERROR] Auth header present: ${error.requestOptions.headers.containsKey("Authorization")}');
              _log('[API_ERROR] Attempting token refresh for expired session');
              // Token refresh would be handled by interceptor in interceptors list
            }
            
            // Log 400 Bad Request with detailed debugging
            if (error.response?.statusCode == 400) {
              _log('[API_ERROR] 400 Bad Request on ${error.requestOptions.uri}');
              _log('[API_ERROR] Method: ${error.requestOptions.method}');
              _log('[API_ERROR] Request URL: ${error.requestOptions.uri}');
              _log('[API_ERROR] Request data: ${(error.requestOptions.data as dynamic)?.length ?? 0} bytes');
              _log('[API_ERROR] Response data: ${error.response?.data}');
            }
          }
          return handler.next(error);
        },
      ),
    );
    } catch (e) {
      // Fallback: create basic Dio instance if initialization fails
      _log('[API_ERROR] ApiService initialization failed: $e');
      String fallbackUrl = ApiConstants.baseUrl;
      if (!fallbackUrl.endsWith('/')) {
        fallbackUrl += '/';
      }
      _dio = Dio(
        BaseOptions(
          baseUrl: fallbackUrl,
          connectTimeout: const Duration(minutes: 5),
          receiveTimeout: const Duration(hours: 2),
        ),
      );
      _log('[API_WARN] Using fallback API configuration: $fallbackUrl');
    }
  }

  // Helper method to get user-friendly error message
  static String getErrorMessage(DioException error) {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
        return 'Connection timeout. Please check if the server is running at ${ApiConstants.serverBaseUrl}';
      case DioExceptionType.receiveTimeout:
        return 'Server took too long to respond. Server at ${ApiConstants.serverBaseUrl} may be overloaded. Please try again.';
      case DioExceptionType.badResponse:
        return _handleHttpStatusCodes(error);
      case DioExceptionType.connectionError:
        return _handleConnectionErrors(error);
      case DioExceptionType.unknown:
        return _handleUnknownErrors(error);
      default:
        return 'An error occurred: ${error.message}';
    }
  }

  // Handle HTTP status codes 300-600
  static String _handleHttpStatusCodes(DioException error) {
    final statusCode = error.response?.statusCode;
    final responseData = error.response?.data;
    
    // Extract custom error message from response if available
    String? customMessage;
    if (responseData is Map) {
      customMessage = responseData['detail'] as String? ?? 
                     responseData['error'] as String? ??
                     responseData['message'] as String?;
    }
    
  // Handle specific HTTP status codes - BACKEND CONSISTENT FIX
  switch (statusCode) {
    // 3xx Redirection
    case 300:
      return customMessage ?? 'Multiple choices available. Please select a specific option.';
      case 301:
        return customMessage ?? 'Resource permanently moved. Please update your bookmarks.';
      case 302:
        return customMessage ?? 'Resource temporarily moved. Redirecting...';
      case 303:
        return customMessage ?? 'See other resource. Please follow the provided link.';
      case 304:
        return customMessage ?? 'Resource not modified. Using cached version.';
      case 305:
        return customMessage ?? 'Use proxy. Please configure your proxy settings.';
      case 306:
        return customMessage ?? 'Reserved for future use.';
      case 307:
        return customMessage ?? 'Temporary redirect. Preserving request method.';
      case 308:
        return customMessage ?? 'Permanent redirect. Preserving request method.';
      
      // 4xx Client Errors
      case 400:
        return customMessage ?? 'Bad request. Please check your input data and try again.';
      case 401:
        return customMessage ?? 'Unauthorized. Authentication required or credentials invalid.';
      case 402:
        return customMessage ?? 'Payment required. Please check your subscription.';
      case 403:
        return customMessage ?? 'Access forbidden. You don\'t have permission to perform this action.';
      case 404:
        return customMessage ?? 'Resource not found. Please check the URL or contact support.';
      case 405:
        return customMessage ?? 'Method not allowed. Please use the correct HTTP method.';
      case 406:
        return customMessage ?? 'Not acceptable. Server cannot fulfill your request format.';
      case 407:
        return customMessage ?? 'Proxy authentication required. Please check proxy credentials.';
      case 408:
        return customMessage ?? 'Request timeout. Please try again with a faster connection.';
      case 409:
        return customMessage ?? 'Conflict. Resource already exists or is being modified.';
      case 410:
        return customMessage ?? 'Resource gone. This resource is no longer available.';
      case 411:
        return customMessage ?? 'Length required. Please specify content length.';
      case 412:
        return customMessage ?? 'Precondition failed. Request conditions not met.';
      case 413:
        return customMessage ?? 'Payload too large. Please reduce file size or data.';
      case 414:
        return customMessage ?? 'URI too long. Please use shorter URLs.';
      case 415:
        return customMessage ?? 'Unsupported media type. Please use supported file formats.';
      case 416:
        return customMessage ?? 'Range not satisfiable. Requested range not available.';
      case 417:
        return customMessage ?? 'Expectation failed. Server cannot meet requirements.';
      case 418:
        return customMessage ?? 'I\'m a teapot! (RFC 2324 Easter egg)';
      case 421:
        return customMessage ?? 'Misdirected request. Please try again.';
      case 422:
        return customMessage ?? 'Unprocessable entity. Please validate your input data.';
      case 423:
        return customMessage ?? 'Locked. Resource is currently locked.';
      case 424:
        return customMessage ?? 'Failed dependency. Required action failed.';
      case 425:
        return customMessage ?? 'Too early. Server is not ready to process this request.';
      case 426:
        return customMessage ?? 'Upgrade required. Please upgrade your client.';
      case 428:
        return customMessage ?? 'Precondition required. Please provide required conditions.';
      case 429:
        return customMessage ?? 'Too many requests. Please wait before trying again.';
      case 431:
        return customMessage ?? 'Request header fields too large.';
      case 451:
        return customMessage ?? 'Unavailable for legal reasons.';
      
      // 5xx Server Errors
      case 500:
        return customMessage ?? 'Internal server error. Please try again later.';
      case 501:
        return customMessage ?? 'Not implemented. This feature is not available yet.';
      case 502:
        return customMessage ?? 'Bad gateway. Server received invalid response.';
      case 503:
        return customMessage ?? 'Service unavailable. Server is temporarily down.';
      case 504:
        return customMessage ?? 'Gateway timeout. Server took too long to respond.';
      case 505:
        return customMessage ?? 'HTTP version not supported. Please use HTTP/1.1 or HTTP/2.';
      case 506:
        return customMessage ?? 'Variant also negotiates. Content negotiation failed.';
      case 507:
        return customMessage ?? 'Insufficient storage. Server storage full.';
      case 508:
        return customMessage ?? 'Loop detected. Request redirection loop.';
      case 510:
        return customMessage ?? 'Not extended. Required extensions not available.';
      case 511:
        return customMessage ?? 'Network authentication required. Please check network credentials.';
      
      default:
        if (statusCode != null && statusCode >= 300 && statusCode < 600) {
          return customMessage ?? 'HTTP $statusCode: ${_getHttpStatusCategory(statusCode)}';
        }
        return 'Server error: ${statusCode ?? 'Unknown'}';
    }
  }

  // Get category of HTTP status code
  static String _getHttpStatusCategory(int statusCode) {
    if (statusCode >= 300 && statusCode < 400) return 'Redirection error';
    if (statusCode >= 400 && statusCode < 500) return 'Client error';
    if (statusCode >= 500 && statusCode < 600) return 'Server error';
    return 'HTTP error';
  }

  // Handle connection errors with enhanced debugging
  static String _handleConnectionErrors(DioException error) {
    final message = error.message ?? '';

    if (message.contains('SocketException')) {
      return '🌐 Network error. Please check internet connection and server accessibility.';
    } else if (message.contains('Connection refused')) {
      return '🚫 Server connection refused. The backend may be down or restarting.';
    } else if (message.contains('Connection timeout')) {
      return '⏰ Connection timeout. Server is not responding. Please try again.';
    } else if (message.contains('HandshakeException')) {
      return '🔒 SSL/TLS certificate error. Server security certificate may be invalid.';
    } else if (message.contains('No Internet connection')) {
      return '📶 No internet connection. Please check your network settings.';
    } else if (message.contains('Host is down')) {
      return '💥 Server is down. Please try again later.';
    } else if (message.contains('Network is unreachable')) {
      return '📡 Network unreachable. Please check your internet connection.';
    } else if (message.contains('DNS resolution failed')) {
      return '🔍 DNS resolution failed. Server domain may be incorrect.';
    }

    return '❌ Cannot connect to server. Please check:\n'
        '1. 📶 Internet connection is active\n'
        '2. 🖥️  Server is running and accessible\n'
        '3. 🔗 API endpoint is reachable\n'
        '4. 🔒 SSL certificates are valid\n'
        '5. 🛡️  Firewall is not blocking connections\n\n'
        'Debug info: $message\n\n'
        'If the problem persists:\n'
        '• Contact support if this is a production environment\n'
        '• Check server status and logs\n'
        '• Verify domain configuration';
  }

  // Handle unknown errors with enhanced debugging
  static String _handleUnknownErrors(DioException error) {
    final message = error.message ?? '';
    
    if (message.contains('SocketException')) {
      return '🌐 Network error. Please check internet connection and server accessibility.';
    } else if (message.contains('Connection refused')) {
      return '🚫 Server connection refused. The backend may be down or restarting.';
    } else if (message.contains('Connection timeout')) {
      return '⏰ Connection timeout. Server is not responding. Please try again.';
    } else if (message.contains('HandshakeException')) {
      return '🔒 SSL/TLS certificate error. Server security certificate may be invalid.';
    } else if (message.contains('FormatException')) {
      return '📝 Invalid data format. Please check your input and try again.';
    } else if (message.contains('JsonException')) {
      return '📄 Invalid JSON response from server. Please try again.';
    } else if (message.contains('TimeoutException')) {
      return '⏱️ Request timed out. Please try again with better connection.';
    }
    
    return '🔗 Connection error. Please check if server is accessible and try again.';
  }

// Auth endpoints
  Future<Map<String, dynamic>> register({
    required String email,
    required String password,
    required String name,
  }) async {
    try {
      // CRITICAL: Do not attach Authorization header for register endpoint
      final response = await _dio.post('${ApiConstants.authEndpoint}/register', 
        data: {
          'email': email,
          'password': password,
          'name': name,
        },
        options: Options(
          headers: {
            // Remove Authorization header explicitly for register
            'Authorization': null,
          },
        ),
      );
      
      // Handle all HTTP status codes for registration
      return _handleRegisterResponse(response);
    } catch (e) {
      _log('[API_REGISTER] Registration error: $e');
      rethrow;
    }
  }

  // Handle registration response for all HTTP status codes
  Map<String, dynamic> _handleRegisterResponse(Response response) {
    final statusCode = response.statusCode;
    final responseData = response.data;
    
    _log('[API_REGISTER] Response status: $statusCode');
    
    // Success: 2xx status codes
    if (statusCode != null && statusCode >= 200 && statusCode < 300) {
      if (responseData is Map<String, dynamic>) {
        return responseData;
      } else if (responseData is Map) {
        return Map<String, dynamic>.from(responseData);
      } else if (responseData != null) {
        _log('[API_REGISTER] Unexpected response format: $responseData');
        throw Exception('Invalid server response format');
      } else {
        _log('[API_REGISTER] Empty response received');
        throw Exception('Empty server response');
      }
    }
    
    // Handle 3xx-6xx status codes
    String errorMessage = _getRegisterErrorMessage(statusCode!, responseData);
    _log('[API_REGISTER] Registration failed: $statusCode - $errorMessage');
    throw Exception(errorMessage);
  }

  // Get specific registration error messages - BACKEND CONSISTENCY FIX
  String _getRegisterErrorMessage(int statusCode, dynamic responseData) {
    // CRITICAL FIX: Prioritize backend error messages over hardcoded ones
    String? customMessage;
    if (responseData is Map) {
      // Extract custom message with fallback hierarchy
      customMessage = responseData['detail'] as String? ??
                     responseData['error'] as String? ??
                     responseData['message'] as String? ??
                     responseData['reason'] as String?;  // Additional fallback
    }
    
    // Return custom message if available, otherwise use defaults
    switch (statusCode) {
      // 3xx Redirection
      case 300: return customMessage ?? 'Multiple registration options available. Please contact support.';
      case 301: return customMessage ?? 'Registration endpoint permanently moved. Please update app.';
      case 302: return customMessage ?? 'Registration redirected. Please try again.';
      case 307: return customMessage ?? 'Temporary registration redirect. Please try again.';
      case 308: return customMessage ?? 'Permanent registration redirect. Please update app.';
      
      // 4xx Client Errors  
      case 400: return customMessage ?? 'Invalid registration request. Please check your input data.';
      case 401: return customMessage ?? 'Registration requires authentication. Please login first.';
      case 402: return customMessage ?? 'Payment required for registration. Please check subscription.';
      case 403: return customMessage ?? 'Registration forbidden. You may not be allowed to register.';
      case 404: return customMessage ?? 'Registration endpoint not found. Please update app.';
      case 405: return customMessage ?? 'Registration method not allowed. Please update app.';
      case 406: return customMessage ?? 'Registration format not acceptable. Please update app.';
      case 407: return customMessage ?? 'Proxy authentication required. Please check network settings.';
      case 408: return customMessage ?? 'Registration request timed out. Please try again.';
      case 409: return customMessage ?? 'Email already registered. Please use a different email or login.';
      case 410: return customMessage ?? 'Registration service gone. Please contact support.';
      case 412: return customMessage ?? 'Registration precondition failed. Please clear app cache.';
      case 413: return customMessage ?? 'Registration request too large. Please reduce data size.';
      case 415: return customMessage ?? 'Registration format unsupported. Please update app.';
      case 416: return customMessage ?? 'Registration range not satisfiable. Please try again.';
      case 417: return customMessage ?? 'Registration expectation failed. Please try again.';
      case 421: return customMessage ?? 'Misdirected registration request. Please try again.';
      case 422: return customMessage ?? 'Invalid registration data. Please check your name, email, and password format.';
      case 423: return customMessage ?? 'Registration locked due to security reasons. Please contact support.';
      case 424: return customMessage ?? 'Registration dependency failed. Please try again.';
      case 425: return customMessage ?? 'Registration request too early. Please wait and try again.';
      case 426: return customMessage ?? 'Registration upgrade required. Please update app.';
      case 428: return customMessage ?? 'Registration precondition required. Please include required headers.';
      case 429: return customMessage ?? 'Too many registration attempts. Please wait before trying again.';
      case 431: return customMessage ?? 'Registration headers too large. Please try again.';
      case 451: return customMessage ?? 'Registration unavailable for legal reasons. Please contact support.';
      
      // 5xx Server Errors
      case 500: return customMessage ?? 'Server registration error. Please try again later.';
      case 501: return customMessage ?? 'Registration method not implemented. Please update app.';
      case 502: return customMessage ?? 'Registration gateway error. Please try again later.';
      case 503: return customMessage ?? 'Service temporarily unavailable. Retrying... Please wait.';
      case 504: return customMessage ?? 'Registration gateway timeout. Server is too busy.';
      case 505: return customMessage ?? 'Registration HTTP version not supported. Please update app.';
      case 506: return customMessage ?? 'Registration content negotiation failed. Please try again.';
      case 507: return customMessage ?? 'Registration service storage full. Please contact support.';
      case 508: return customMessage ?? 'Registration redirection loop detected. Please contact support.';
      case 510: return customMessage ?? 'Registration extension not available. Please update app.';
      case 511: return customMessage ?? 'Network registration authentication required. Please check network.';
      
      default:
        if (statusCode >= 300 && statusCode < 400) {
          return customMessage ?? 'Registration redirection required. Please try again.';
        } else if (statusCode >= 400 && statusCode < 500) {
          return customMessage ?? 'Registration request failed (Error $statusCode). Please try again.';
        } else if (statusCode >= 500 && statusCode < 600) {
          return customMessage ?? 'Registration server error (Error $statusCode). Please try again later.';
        }
        return customMessage ?? 'Registration failed with error $statusCode. Please try again.';
    }
  }

  Future<Map<String, dynamic>> login({
    required String email,
    required String password,
  }) async {
    try {
      final loginUrl = '${ApiConstants.authEndpoint}/login';
      _log('[API_LOGIN] Full URL: ${_dio.options.baseUrl}$loginUrl');
      
      final response = await _dio.post(loginUrl, data: {
        'email': email,
        'password': password,
      });
      
      // Handle all HTTP status codes properly
      return _handleLoginResponse(response);
    } catch (e) {
      _log('[API_LOGIN] Login error: $e');
      rethrow;
    }
  }

  // Handle login response for all HTTP status codes
  Map<String, dynamic> _handleLoginResponse(Response response) {
    final statusCode = response.statusCode;
    final responseData = response.data;
    
    _log('[API_LOGIN] Response status: $statusCode');
    _log('[API_LOGIN] Response data type: ${responseData.runtimeType}');
    
    // Success: 2xx status codes
    if (statusCode != null && statusCode >= 200 && statusCode < 300) {
      if (responseData is Map<String, dynamic>) {
        return responseData;
      } else if (responseData is Map) {
        return Map<String, dynamic>.from(responseData);
      } else if (responseData != null) {
        _log('[API_LOGIN] Unexpected response format: $responseData');
        throw Exception('Invalid server response format');
      } else {
        _log('[API_LOGIN] Empty response received');
        throw Exception('Empty server response');
      }
    }
    
    // Handle 3xx-6xx status codes
    String errorMessage = _getLoginErrorMessage(statusCode!, responseData);
    _log('[API_LOGIN] Login failed: $statusCode - $errorMessage');
    throw Exception(errorMessage);
  }

  // Get specific login error messages
  String _getLoginErrorMessage(int statusCode, dynamic responseData) {
    // Extract custom message from response if available
    String? customMessage;
    if (responseData is Map) {
      customMessage = responseData['detail'] as String? ?? 
                     responseData['error'] as String? ??
                     responseData['message'] as String?;
    }
    
    // Return custom message if available, otherwise use defaults
    switch (statusCode) {
      // 3xx Redirection
      case 300: return customMessage ?? 'Multiple login options available. Please contact support.';
      case 301: return customMessage ?? 'Login endpoint permanently moved. Please update app.';
      case 302: return customMessage ?? 'Login redirected. Please try again.';
      case 307: return customMessage ?? 'Temporary login redirect. Please try again.';
      case 308: return customMessage ?? 'Permanent login redirect. Please update app.';
      
      // 4xx Client Errors  
      case 400: return customMessage ?? 'Invalid login request. Please check your credentials.';
      case 401: return customMessage ?? 'Authentication failed. Please login again or check your credentials.';
      case 402: return customMessage ?? 'Payment required. Please check your subscription.';
      case 403: return customMessage ?? 'Access forbidden. Your account may be locked or suspended.';
      case 404: return customMessage ?? 'Login endpoint not found. Please update app.';
      case 405: return customMessage ?? 'Login method not allowed. Please update app.';
      case 406: return customMessage ?? 'Login format not acceptable. Please update app.';
      case 407: return customMessage ?? 'Proxy authentication required. Please check network settings.';
      case 408: return customMessage ?? 'Login request timed out. Please try again.';
      case 409: return customMessage ?? 'Login conflict. User may be already logged in elsewhere.';
      case 410: return customMessage ?? 'Login service gone. Please contact support.';
      case 412: return customMessage ?? 'Login precondition failed. Please clear app cache.';
      case 413: return customMessage ?? 'Login request too large. Please try again.';
      case 415: return customMessage ?? 'Login format unsupported. Please update app.';
      case 416: return customMessage ?? 'Login range not satisfiable. Please try again.';
      case 417: return customMessage ?? 'Login expectation failed. Please try again.';
      case 421: return customMessage ?? 'Misdirected login request. Please try again.';
      case 422: return customMessage ?? 'Invalid login data. Please check your email and password format.';
      case 423: return customMessage ?? 'Account locked due to security reasons. Please contact support.';
      case 424: return customMessage ?? 'Login dependency failed. Please try again.';
      case 425: return customMessage ?? 'Login request too early. Please wait and try again.';
      case 426: return customMessage ?? 'Login upgrade required. Please update app.';
      case 428: return customMessage ?? 'Login precondition required. Please include required headers.';
      case 429: return customMessage ?? 'Too many login attempts. Please wait before trying again.';
      case 431: return customMessage ?? 'Login headers too large. Please try again.';
      case 451: return customMessage ?? 'Login unavailable for legal reasons. Please contact support.';
      
      // 5xx Server Errors
      case 500: return customMessage ?? 'Server login error. Please try again later.';
      case 501: return customMessage ?? 'Login method not implemented. Please update app.';
      case 502: return customMessage ?? 'Login gateway error. Please try again later.';
      case 503: return customMessage ?? 'Login service temporarily unavailable. Retrying... Please wait.';
      case 504: return customMessage ?? 'Login gateway timeout. Server is too busy.';
      case 505: return customMessage ?? 'Login HTTP version not supported. Please update app.';
      case 506: return customMessage ?? 'Login content negotiation failed. Please try again.';
      case 507: return customMessage ?? 'Login service storage full. Please contact support.';
      case 508: return customMessage ?? 'Login redirection loop detected. Please contact support.';
      case 510: return customMessage ?? 'Login extension not available. Please update app.';
      case 511: return customMessage ?? 'Network login authentication required. Please check network.';
      
      default:
        if (statusCode >= 300 && statusCode < 400) {
          return customMessage ?? 'Login redirection required. Please try again.';
        } else if (statusCode >= 400 && statusCode < 500) {
          return customMessage ?? 'Login request failed (Error $statusCode). Please try again.';
        } else if (statusCode >= 500 && statusCode < 600) {
          return customMessage ?? 'Login server error (Error $statusCode). Please try again later.';
        }
        return customMessage ?? 'Login failed with error $statusCode. Please try again.';
    }
  }

  Future<Map<String, dynamic>> logout({required String refreshToken}) async {
    try {
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/logout',
        data: {'refresh_token': refreshToken},
      );
      
      // Handle all HTTP status codes for logout
      return _handleLogoutResponse(response);
    } catch (e) {
      _log('[API_LOGOUT] Logout error: $e');
      rethrow;
    }
  }

  // Token refresh is handled via interceptor when 401 is encountered
  // This method should not be called directly
  @Deprecated('Token refresh should be handled by AuthService')
  Future<bool> refreshAccessToken() async {
    try {
      debugPrint('[API_REFRESH] Token refresh should be handled by interceptor');
      // Deprecated: use AuthService directly instead
      return false;
    } catch (e) {
      debugPrint('[AVATAR_UPLOAD] Error: \$e');
      throw Exception('Failed to upload chat avatar: \$e');
    }
  }

  // Token management methods used by AuthService
  void setAuthToken(String token) {
    _dio.options.headers['Authorization'] = 'Bearer $token';
    _log('[API_AUTH] Token set (Bearer token), length: ${token.length}');
  }

  void clearAuthToken() {
    _dio.options.headers.remove('Authorization');
    _log('[API_AUTH] Token cleared from headers');
  }

  Future<Map<String, dynamic>> refreshToken({required String refreshToken}) async {
    try {
      _log('[API_REFRESH_TOKEN] Attempting token refresh');
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/refresh',
        data: {'refresh_token': refreshToken},
      );
      return response.data ?? {};
    } on DioException catch (e) {
      _log('[API_REFRESH_TOKEN_ERROR] Dio error: ${e.message}');
      rethrow;
    } catch (e) {
      _log('[API_REFRESH_TOKEN_ERROR] Failed: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> requestPasswordReset(String email) async {
    try {
      _log('[API_REQUEST_PASSWORD_RESET] Requesting password reset for: $email');
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/forgot-password',
        data: {'email': email},
      );
      return response.data ?? {};
    } on DioException catch (e) {
      _log('[API_REQUEST_PASSWORD_RESET_ERROR] Dio error: ${e.message}');
      rethrow;
    } catch (e) {
      _log('[API_REQUEST_PASSWORD_RESET_ERROR] Failed: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> resetPasswordWithToken({
    required String token,
    required String newPassword,
  }) async {
    try {
      _log('[API_RESET_PASSWORD_WITH_TOKEN] Sending password reset with token');
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/reset-password',
        data: {'token': token, 'new_password': newPassword},
      );
      return response.data ?? {};
    } on DioException catch (e) {
      _log('[API_RESET_PASSWORD_WITH_TOKEN_ERROR] Dio error: ${e.message}');
      rethrow;
    } catch (e) {
      _log('[API_RESET_PASSWORD_WITH_TOKEN_ERROR] Failed: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    try {
      _log('[API_CHANGE_PASSWORD] Sending password change request');
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/change-password',
        data: {'current_password': currentPassword, 'new_password': newPassword},
      );
      return response.data ?? {};
    } on DioException catch (e) {
      _log('[API_CHANGE_PASSWORD_ERROR] Dio error: ${e.message}');
      rethrow;
    } catch (e) {
      _log('[API_CHANGE_PASSWORD_ERROR] Failed: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> changeEmail({required String newEmail}) async {
    try {
      _log('[API_CHANGE_EMAIL] Sending change email request for: $newEmail');
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/change-email',
        data: {'new_email': newEmail},
      );
      return response.data ?? {};
    } on DioException catch (e) {
      _log('[API_CHANGE_EMAIL_ERROR] Dio error: ${e.message}');
      rethrow;
    } catch (e) {
      _log('[API_CHANGE_EMAIL_ERROR] Failed: $e');
      rethrow;
    }
  }

  // Handle logout response for all HTTP status codes
  Map<String, dynamic> _handleLogoutResponse(Response response) {
    final statusCode = response.statusCode;
    final responseData = response.data;
    
    _log('[API_LOGOUT] Response status: $statusCode');
    
    // Success: 2xx status codes
    if (statusCode != null && statusCode >= 200 && statusCode < 300) {
      if (responseData is Map<String, dynamic>) {
        return responseData;
      } else if (responseData is Map) {
        return Map<String, dynamic>.from(responseData);
      } else {
        return {'message': 'Logged out successfully'};
      }
    }
    
    // Handle 3xx-6xx status codes
    String errorMessage = _getLogoutErrorMessage(statusCode!, responseData);
    _log('[API_LOGOUT] Logout failed: $statusCode - $errorMessage');
    throw Exception(errorMessage);
  }

  // Get specific logout error messages
  String _getLogoutErrorMessage(int statusCode, dynamic responseData) {
    // Extract custom message from response if available
    String? customMessage;
    if (responseData is Map) {
      customMessage = responseData['detail'] as String? ?? 
                     responseData['error'] as String? ??
                     responseData['message'] as String?;
    }
    
    // Return custom message if available, otherwise use defaults
    switch (statusCode) {
      case 400: return customMessage ?? 'Invalid logout request. Please try again.';
      case 401: return customMessage ?? 'Already logged out or session expired.';
      case 403: return customMessage ?? 'Logout forbidden. Please contact support.';
      case 404: return customMessage ?? 'Logout endpoint not found.';
      case 429: return customMessage ?? 'Too many logout requests. Please wait.';
      case 500: return customMessage ?? 'Server logout error. Session may be cleared.';
      case 503: return customMessage ?? 'Logout service temporarily unavailable.';
      default:
        return customMessage ?? 'Logout failed (Error $statusCode). Please try again.';
    }
  }

// User endpoints
  Future<Map<String, dynamic>> getMe() async {
    try {
      _log('[API_ME] Fetching current user profile');
      final response = await _dio.get('${ApiConstants.usersEndpoint}/me');
      _log('[API_ME] Success: ${response.data}');
      
      // Handle all HTTP status codes for getMe
      return _handleGetMeResponse(response);
    } catch (e) {
      _log('[API_ME_ERROR] Failed: $e');
      rethrow;
    }
  }

  // Handle getMe response for all HTTP status codes
  Map<String, dynamic> _handleGetMeResponse(Response response) {
    final statusCode = response.statusCode;
    final responseData = response.data;
    
    _log('[API_ME] Response status: $statusCode');
    
    // Success: 2xx status codes
    if (statusCode != null && statusCode >= 200 && statusCode < 300) {
      if (responseData is Map<String, dynamic>) {
        return responseData;
      } else if (responseData is Map) {
        return Map<String, dynamic>.from(responseData);
      } else if (responseData != null) {
        // Try to convert any response to Map
        try {
          return Map<String, dynamic>.from(responseData);
        } catch (e) {
          _log('[API_ME] Could not convert response to Map: $responseData');
          // Return empty map instead of throwing
          return {};
        }
      } else {
        _log('[API_ME] Empty user response received, returning empty map');
        return {};  // Return empty map instead of throwing
      }
    }
    
    // Handle 3xx-6xx status codes
    String errorMessage = _getGetMeErrorMessage(statusCode!, responseData);
    _log('[API_ME] Get user failed: $statusCode - $errorMessage');
    throw Exception(errorMessage);
  }

  // Get specific getMe error messages
  String _getGetMeErrorMessage(int statusCode, dynamic responseData) {
    // Extract custom message from response if available
    String? customMessage;
    if (responseData is Map) {
      customMessage = responseData['detail'] as String? ?? 
                     responseData['error'] as String? ??
                     responseData['message'] as String?;
    }
    
    // Return custom message if available, otherwise use defaults
    switch (statusCode) {
      case 301: return customMessage ?? 'User endpoint permanently moved. Please update app.';
      case 400: return customMessage ?? 'Invalid user request. Please try again.';
      case 401: return customMessage ?? 'Authentication required. Please login again.';
      case 403: return customMessage ?? 'Access to user profile forbidden.';
      case 404: return customMessage ?? 'User profile not found. Please login again.';
      case 429: return customMessage ?? 'Too many profile requests. Please wait.';
      case 500: return customMessage ?? 'Server error fetching user profile. Please try again.';
      case 503: return customMessage ?? 'User service temporarily unavailable.';
      default:
        return customMessage ?? 'Failed to fetch user profile (Error $statusCode). Please try again.';
    }
  }

  Future<Map<String, dynamic>> updateProfile(Map<String, dynamic> data) async {
    try {
      _log('[API_PROFILE] Updating profile with fields: ${data.keys.toList()}');
      _log('[API_PROFILE] Payload: $data');
      _log('[API_PROFILE] Endpoint: ${ApiConstants.usersEndpoint}/profile');
      final response = await _dio.put('${ApiConstants.usersEndpoint}/profile', data: data);
      _log('[API_PROFILE] Response status: ${response.statusCode}');
      _log('[API_PROFILE] Response data: ${response.data}');
      return response.data ?? {};
    } on DioException catch (e) {
      _log('[API_PROFILE_ERROR] Dio error: ${e.message}');
      _log('[API_PROFILE_ERROR] Status code: ${e.response?.statusCode}');
      _log('[API_PROFILE_ERROR] Response data: ${e.response?.data}');
      rethrow;
    } catch (e) {
      _log('[API_PROFILE_ERROR] Failed to update profile: $e');
      rethrow;
    }
  }

Future<Map<String, dynamic>> uploadAvatar(Uint8List bytes, String filename) async {
    try {
      debugPrint('[API_SERVICE] Uploading avatar: $filename (${bytes.length} bytes)');
      
      final formData = FormData.fromMap({
        'file': MultipartFile.fromBytes(bytes, filename: filename),
      });
      
      final uploadUrl = '${ApiConstants.usersEndpoint}/avatar';
      debugPrint('[API_SERVICE] Avatar upload URL: ${_dio.options.baseUrl}$uploadUrl');
      
      // Remove Content-Type header to let Dio set it automatically with correct boundary
      final response = await _dio.post(
        uploadUrl, 
        data: formData,
        options: Options(
          method: 'POST',
          sendTimeout: const Duration(seconds: 30),
          receiveTimeout: const Duration(seconds: 30),
          headers: {
            'Accept': 'application/json',
            // Remove Content-Type to let Dio handle multipart/form-data with proper boundary
          },
          // Explicitly disable redirects to prevent 301/302 -> GET conversion
          followRedirects: false,
          // Ensure we only allow 2xx responses as success
          validateStatus: (status) => status != null && status >= 200 && status < 300,
        ),
      );
      
      debugPrint('[API_SERVICE] Avatar upload status: ${response.statusCode}');
      debugPrint('[API_SERVICE] Avatar upload response: ${response.data}');
      
      // Handle all HTTP status codes for avatar upload
      return _handleAvatarUploadResponse(response, filename);
    } on DioException catch (e) {
      debugPrint('[API_SERVICE] DioException during avatar upload: ${e.type} - ${e.message}');
      debugPrint('[API_SERVICE] Response status: ${e.response?.statusCode}');
      debugPrint('[API_SERVICE] Response data: ${e.response?.data}');
      
      // Special handling for 405 Method Not Allowed - prevent any retry attempts
      if (e.response?.statusCode == 405) {
        final errorMessage = 'Method Not Allowed: Avatar upload only supports POST requests. Please check your app configuration.';
        debugPrint('[API_SERVICE] 405 ERROR: $errorMessage');
        throw Exception(errorMessage);
      }
      
      String errorMessage = _getAvatarUploadErrorMessage(e.response?.statusCode, e.response?.data);
      throw Exception(errorMessage);
    } catch (e) {
      debugPrint('[API_SERVICE] Error during avatar upload: $e');
      rethrow;
    }
  }

  // Handle avatar upload response for all HTTP status codes
  Map<String, dynamic> _handleAvatarUploadResponse(Response response, String filename) {
    final statusCode = response.statusCode;
    final responseData = response.data;
    
    debugPrint('[API_SERVICE] Response status: $statusCode');
    debugPrint('[API_SERVICE] Response data type: ${responseData.runtimeType}');
    
    // Success: 2xx status codes
    if (statusCode != null && statusCode >= 200 && statusCode < 300) {
      // Try to parse different response formats
      if (responseData is Map<String, dynamic>) {
        return responseData;
      } else if (responseData is Map) {
        return Map<String, dynamic>.from(responseData);
      } else if (responseData is String) {
        try {
          final parsed = jsonDecode(responseData);
          if (parsed is Map) {
            return Map<String, dynamic>.from(parsed);
          }
          // If JSON decoded to non-Map type, throw exception
          throw Exception(
            'Avatar upload: JSON parse returned non-Map type (${parsed.runtimeType}). '
            'Status: $statusCode'
          );
        } catch (e) {
          debugPrint('[API_SERVICE] Failed to parse JSON string: $e');
          throw Exception(
            'Avatar upload: Failed to parse JSON response. Status: $statusCode, Error: $e'
          );
        }
      } else if (responseData != null) {
        debugPrint('[API_SERVICE] Unexpected response format: $responseData');
        // Try to convert any response to Map
        try {
          return Map<String, dynamic>.from(responseData);
        } catch (e) {
          throw Exception(
            'Avatar upload: Cannot convert response to Map. '
            'Status: $statusCode, Response type: ${responseData.runtimeType}, Error: $e'
          );
        }
      } else {
        // Null response body in successful response
        throw Exception(
          'Avatar upload: Empty response body received. Status: $statusCode, but expected data'
        );
      }
    }
    
    // Handle 3xx-6xx status codes
    String errorMessage = _getAvatarUploadErrorMessage(statusCode!, responseData);
    debugPrint('[API_SERVICE] Avatar upload failed: $statusCode - $errorMessage');
    throw Exception(errorMessage);
  }

  // Get specific avatar upload error messages
  String _getAvatarUploadErrorMessage(int? statusCode, dynamic responseData) {
    // Extract custom message from response if available
    String? customMessage;
    if (responseData is Map) {
      customMessage = responseData['detail'] as String? ?? 
                     responseData['error'] as String? ??
                     responseData['message'] as String?;
    }
    
    // Return custom message if available, otherwise use defaults
    switch (statusCode) {
      case 301: return customMessage ?? 'Avatar upload endpoint permanently moved. Please update app.';
      case 400: return customMessage ?? 'Invalid avatar upload request. Please check file format.';
      case 401: return customMessage ?? 'Authentication required for avatar upload. Please login.';
      case 403: return customMessage ?? 'Avatar upload forbidden. You may not have permission.';
      case 404: return customMessage ?? 'Avatar upload endpoint not found. Please update app.';
      case 405: return customMessage ?? 'Method Not Allowed: Avatar upload only supports POST requests. This error cannot be retried.';
      case 408: return customMessage ?? 'Avatar upload timeout. Please check connection and try again.';
      case 413: return customMessage ?? 'Avatar file too large. Please use a smaller image.';
      case 415: return customMessage ?? 'Unsupported image format. Please use JPG, PNG, or GIF.';
      case 422: return customMessage ?? 'Invalid avatar file. Please check file format and size.';
      case 429: return customMessage ?? 'Too many avatar uploads. Please wait before trying again.';
      case 500: return customMessage ?? 'Server error uploading avatar. Please try again later.';
      case 503: return customMessage ?? 'Avatar upload service temporarily unavailable.';
      case 507: return customMessage ?? 'Storage full. Cannot upload avatar at this time.';
      default:
        if (statusCode != null) {
          return customMessage ?? 'Avatar upload failed (Error $statusCode). Please try again.';
        }
        return 'Failed to upload avatar. Please check your connection and try again.';
    }
  }

  Future<Map<String, dynamic>> getFileInfo(String fileId) async {
    try {
      debugPrint('[API_SERVICE] Getting file info for: $fileId');
      final response = await _dio.get('${ApiConstants.filesEndpoint}/$fileId/info');
      debugPrint('[API_SERVICE] File info response: ${response.data}');
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error getting file info: $e');
      rethrow;
    }
  }



  Future<Map<String, dynamic>> getSavedChat() async {
    try {
      final response = await _dio.get('${ApiConstants.chatsEndpoint}/saved');
      return response.data ?? {};
    } catch (e) {
      rethrow;
    }
  }

  // Chat endpoints
  Future<List<Map<String, dynamic>>> getChats() async {
    try {
      _log('[API_CHATS] Fetching chats from ${ApiConstants.chatsEndpoint}');
      final response = await _dio.get(ApiConstants.chatsEndpoint);
      _log('[API_CHATS] Success: received ${response.data?['chats']?.length ?? 0} chats');
      return List<Map<String, dynamic>>.from(response.data?['chats'] ?? const []);
    } catch (e) {
      _log('[API_CHATS_ERROR] Failed to fetch chats: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> getChatMessages(String chatId) async {
    try {
      final response = await _dio.get('${ApiConstants.chatsEndpoint}/$chatId/messages');
      return response.data ?? {};
    } catch (e) {
      rethrow;
    }
  }

  Future<List<Map<String, dynamic>>> searchMessages(String query, {String? chatId}) async {
    final response = await _dio.get(
      '${ApiConstants.messagesEndpoint}/search', 
      queryParameters: {
        'q': query,
        if (chatId != null) 'chat_id': chatId,
      },
    );
    return List<Map<String, dynamic>>.from(response.data?['messages'] ?? []);
  }

Future<List<Map<String, dynamic>>> searchUsers(String query) async {
    final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/search',
        queryParameters: {'q': query},
    );
    return List<Map<String, dynamic>>.from(response.data?['users'] ?? []);
  }

  Future<List<Map<String, dynamic>>> getContacts({int limit = 50, int offset = 0}) async {
    final response = await _dio.get(
      '${ApiConstants.usersEndpoint}/contacts',
      queryParameters: {'limit': limit, 'offset': offset},
    );
    return List<Map<String, dynamic>>.from(response.data?['contacts'] ?? []);
  }

  /// Simple user list for group creation when contacts are empty
  Future<List<Map<String, dynamic>>> getSimpleUsers({int limit = 50, int offset = 0}) async {
    final response = await _dio.get(
      '${ApiConstants.usersEndpoint}/simple',
      queryParameters: {
        'limit': limit,
        'offset': offset,
      },
    );
    return List<Map<String, dynamic>>.from(response.data?['users'] ?? []);
  }

  Future<List<Map<String, dynamic>>> searchUsersByEmail(String email) async {
    final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/search',
        queryParameters: {'q': email, 'search_type': 'email'},
    );
    return List<Map<String, dynamic>>.from(response.data?['users'] ?? []);
  }

  Future<List<Map<String, dynamic>>> searchUsersByUsername(String username) async {
    // Remove @ if user included it
    final cleanUsername = username.startsWith('@') ? username.substring(1) : username;
    final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/search',
        queryParameters: {'q': cleanUsername, 'search_type': 'username'},
    );
    return List<Map<String, dynamic>>.from(response.data?['users'] ?? []);
  }

  Future<Map<String, dynamic>> sendMessage({
    required String chatId,
    String? content,
    String? fileId,
  }) async {
    try {
      final response = await _dio.post('${ApiConstants.chatsEndpoint}/$chatId/messages', data: {
        'text': content,
        'file_id': fileId,
      });
      return response.data ?? {};
    } catch (e) {
      rethrow;
    }
  }

  // Message actions
  Future<Map<String, dynamic>> editMessage(String messageId, String text) async {
    final response = await _dio.put(
      '${ApiConstants.messagesEndpoint}/$messageId',
      data: {'text': text},
    );
    return response.data;
  }

  Future<Map<String, dynamic>> deleteMessage(String messageId, {bool hardDelete = false}) async {
    final response = await _dio.delete(
      '${ApiConstants.messagesEndpoint}/$messageId',
      queryParameters: {'hard_delete': hardDelete},
    );
    return response.data;
  }

  Future<Map<String, dynamic>> toggleReaction(String messageId, String emoji) async {
    final response = await _dio.post(
      '${ApiConstants.messagesEndpoint}/$messageId/reactions',
      data: {'emoji': emoji},
    );
    return response.data;
  }

  Future<Map<String, dynamic>> pinMessage(String messageId) async {
    final response = await _dio.post('${ApiConstants.messagesEndpoint}/$messageId/pin');
    return response.data;
  }

  Future<Map<String, dynamic>> unpinMessage(String messageId) async {
    final response = await _dio.post('${ApiConstants.messagesEndpoint}/$messageId/unpin');
    return response.data;
  }

  Future<Map<String, dynamic>> markRead(String messageId) async {
    final response = await _dio.post('${ApiConstants.messagesEndpoint}/$messageId/read');
    return response.data;
  }

  Future<void> pinChat(String chatId) async {
    await _dio.post('${ApiConstants.chatsEndpoint}/$chatId/pin_chat');
  }

  Future<void> unpinChat(String chatId) async {
    await _dio.post('${ApiConstants.chatsEndpoint}/$chatId/unpin_chat');
  }



  Future<Map<String, dynamic>> getChannel(String channelId) async {
    final response = await _dio.get('channels/$channelId');
    return response.data;
  }

  Future<void> subscribeChannel(String channelId) async {
    await _dio.post('channels/$channelId/subscribe');
  }

Future<void> postToChannel(String channelId, String text) async {
    await _dio.post(
      'channels/$channelId/posts',
      data: {
        'text': text 
        // Note: Backend might expect MessageCreate format, keeping it simple for now
      },
    );
  }

  Future<void> removeChannel(String channelId) async {
    await _dio.post('channels/$channelId/remove');
  }

  Future<Map<String, dynamic>> createChat({
    required String targetUserId,
    String type = 'private',
  }) async {
    final response = await _dio.post(
      ApiConstants.chatsEndpoint,
      data: {
        'type': type,
        'member_ids': [targetUserId],
      },
    );
    return response.data;
  }

  Future<Map<String, dynamic>> createGroup({
    required String name,
    String description = '',
    String? avatarUrl,
    required List<String> memberIds,
  }) async {
    final response = await _dio.post(
      'groups',
      data: {
        'name': name,
        'description': description,
        'avatar_url': avatarUrl,
        'member_ids': memberIds,
      },
    );
    return response.data;
  }

  Future<Map<String, dynamic>> getGroup(String groupId) async {
    final response = await _dio.get('groups/$groupId');
    return response.data;
  }

  Future<Map<String, dynamic>> updateGroup(String groupId, Map<String, dynamic> data) async {
    final response = await _dio.put('groups/$groupId', data: data);
    return response.data;
  }

  Future<Map<String, dynamic>> uploadGroupAvatar({
    required String groupId,
    required Uint8List bytes,
    required String filename,
  }) async {
    try {
      debugPrint('[API_SERVICE] Uploading group avatar: $filename (${bytes.length} bytes)');

      final formData = FormData.fromMap({
        'file': MultipartFile.fromBytes(bytes, filename: filename),
      });

      final uploadUrl = 'groups/$groupId/avatar';
      debugPrint('[API_SERVICE] Group avatar upload URL: ${_dio.options.baseUrl}$uploadUrl');

      final response = await _dio.post(
        uploadUrl,
        data: formData,
        options: Options(
          method: 'POST',
          sendTimeout: const Duration(seconds: 30),
          receiveTimeout: const Duration(seconds: 30),
          headers: {
            'Accept': 'application/json',
          },
          followRedirects: false,
          validateStatus: (status) => status != null && status >= 200 && status < 300,
        ),
      );

      final data = response.data;
      if (data is Map<String, dynamic>) return data;
      if (data is Map) return Map<String, dynamic>.from(data);
      if (data is String) {
        final parsed = jsonDecode(data);
        if (parsed is Map) return Map<String, dynamic>.from(parsed);
      }
      return {};
    } on DioException catch (e) {
      debugPrint('[API_SERVICE] DioException during group avatar upload: ${e.type} - ${e.message}');
      debugPrint('[API_SERVICE] Response status: ${e.response?.statusCode}');
      debugPrint('[API_SERVICE] Response data: ${e.response?.data}');
      rethrow;
    } catch (e) {
      debugPrint('[API_SERVICE] Error during group avatar upload: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> addGroupMembers(String groupId, List<String> userIds) async {
    final response = await _dio.post('groups/$groupId/members', data: {'user_ids': userIds.map((id) => id.toString()).toList()});
    return response.data;
  }

  Future<Map<String, dynamic>> removeGroupMember(String groupId, String memberId) async {
    final response = await _dio.delete('groups/$groupId/members/$memberId');
    return response.data;
  }

  Future<Map<String, dynamic>> updateGroupMemberRole(String groupId, String memberId, String role) async {
    final response = await _dio.put('groups/$groupId/members/$memberId/role', data: {'role': role});
    return response.data;
  }

  Future<Map<String, dynamic>> leaveGroup(String groupId) async {
    final response = await _dio.post('groups/$groupId/leave');
    return response.data;
  }

  Future<Map<String, dynamic>> deleteGroup(String groupId) async {
    final response = await _dio.delete('groups/$groupId');
    return response.data;
  }

  Future<Map<String, dynamic>> muteGroup(String groupId, {required bool mute}) async {
    final response = await _dio.post('groups/$groupId/mute', queryParameters: {'mute': mute});
    return response.data;
  }

  Future<Map<String, dynamic>> getGroupActivity(String groupId, {int limit = 50}) async {
    final response = await _dio.get('groups/$groupId/activity', queryParameters: {'limit': limit});
    return response.data;
  }

  Future<Map<String, dynamic>> getPinnedMessages(String groupId, {int limit = 20}) async {
    final response = await _dio.get('groups/$groupId/pinned', queryParameters: {'limit': limit});
    return response.data;
  }

  // Files (resumable upload)
  Future<Map<String, dynamic>> initUpload({
    required String filename,
    required int size,
    required String mime,  // Parameter name stays 'mime' for compatibility
    required String chatId,
    String? checksum,
  }) async {
    try {
      final response = await _dio.post(
        '${ApiConstants.filesEndpoint}/init',
        data: {
          'filename': filename,
          'size': size,
          'mime_type': mime,
          'chat_id': chatId,
          if (checksum != null) 'checksum': checksum,
        },
      );
      return response.data ?? {};
    } on DioException catch (e) {
      _log('[API_INIT_ERROR] Failed to initialize upload: ${e.toString()}');
      
      // CRITICAL FIX: Enhanced error handling with retry logic and proper status code mapping
      if (e.type == DioExceptionType.connectionTimeout ||
          e.type == DioExceptionType.receiveTimeout ||
          e.type == DioExceptionType.sendTimeout) {
        // Retry for timeout errors (504 Gateway Timeout)
        _log('[API_INIT_RETRY] Timeout error detected, attempting retry...');
        return await _retryUpload(filename, size, mime, chatId, checksum);
      }
      
      // Enhanced status code checking
      final statusCode = e.response?.statusCode;
      if (statusCode != null) {
        if (statusCode >= 500 && statusCode < 600) {
          // Server errors - should be retried
          _log('[API_INIT_RETRY] Server error $statusCode detected, attempting retry...');
          return await _retryUpload(filename, size, mime, chatId, checksum);
        } else if (statusCode == 408 || statusCode == 429) {
          // Request timeout and rate limit - should be retried
          _log('[API_INIT_RETRY] Retryable error $statusCode detected, attempting retry...');
          return await _retryUpload(filename, size, mime, chatId, checksum);
        }
        // 4xx client errors (except 408, 429) - should NOT be retried
      }
      
      // CRITICAL FIX: Throw exception instead of returning error object
      // This prevents KeyError in calling code when trying to access response['upload_id']
      final errorMessage = _getInitUploadErrorMessage(e);
      _log('[API_INIT_ERROR] Throwing error: $errorMessage');
      throw Exception(errorMessage);
    }
  }

  Future<Map<String, dynamic>> _retryUpload(
    String filename,
    int size, 
    String mime,
    String chatId,
    String? checksum,
  ) async {
    int retryCount = 0;
    const maxRetries = 3;
    
    while (retryCount < maxRetries) {
      try {
        final response = await _dio.post(
          '${ApiConstants.filesEndpoint}/init',
          data: {
            'filename': filename,
            'size': size,
            'mime_type': mime,
            'chat_id': chatId,
            if (checksum != null) 'checksum': checksum,
          },
        );
        return response.data ?? {};
      } on DioException catch (e) {
        retryCount++;
        if (retryCount >= maxRetries) rethrow;
        
        _log('[API_INIT_RETRY] Attempt $retryCount failed: ${e.toString()}');
        await Future.delayed(Duration(seconds: 2 * retryCount)); // Exponential backoff
      }
    }
    
    throw Exception('Upload initialization failed after $maxRetries retries');
  }

  String _getInitUploadErrorMessage(DioException e) {
    switch (e.response?.statusCode) {
      case 400:
        return 'Invalid file data. Please check file size, type, and format.';
      case 401:
        return 'Authentication required. Please login again.';
      case 403:
        return 'Access denied. You do not have permission to upload files.';
      case 413:
        return 'File too large. Maximum file size is 40GB.';
      case 429:
        return 'Too many upload attempts. Please wait before trying again.';
      case 500:
        return 'Server error. Please try again later.';
      case 503:
        return 'Service temporarily unavailable. Please try again later.';
      default:
        return e.message ?? 'Unknown error occurred during upload initialization.';
    }
  }

  Future<void> uploadChunk({
    required String uploadId,
    required int chunkIndex,
    required Uint8List bytes,
    String? chunkChecksum,
  }) async {
    debugPrint('[API_SERVICE] Uploading chunk $chunkIndex for upload $uploadId (${bytes.length} bytes)');
    
    final url = '${ApiConstants.filesEndpoint}/$uploadId/chunk?chunk_index=$chunkIndex';
    debugPrint('[API_SERVICE] Chunk upload URL: $url');
    
    // Enhanced error handling with comprehensive retry logic
    int retryCount = 0;
    const maxRetries = 3;
    
    while (retryCount < maxRetries) {
      try {
        final response = await _dio.put(
          url,
          data: bytes,
          options: Options(
            contentType: 'application/octet-stream',
            sendTimeout: const Duration(minutes: 30),
            receiveTimeout: const Duration(minutes: 30),
            headers: {
              if (chunkChecksum != null) 'x-chunk-checksum': chunkChecksum,
              'Content-Length': bytes.length.toString(),
            },
            followRedirects: false,
            validateStatus: (status) => status != null && status < 500,
          ),
        );
        
        if (response.statusCode == 200) {
          debugPrint('[API_SERVICE] Chunk $chunkIndex uploaded successfully');
          return; // Success - exit retry loop
        } else if (response.statusCode == null || response.statusCode! >= 500) {
          // Server error - should retry
          throw DioException(
            requestOptions: response.requestOptions,
            response: response,
            type: DioExceptionType.badResponse,
            message: 'Server error: ${response.statusCode}',
          );
        } else {
          // Client error (4xx) - should NOT retry, just throw
          String errorMessage = _getChunkUploadErrorMessage(response.statusCode, response.data);
          debugPrint('[API_SERVICE] Chunk $chunkIndex failed with client error: $errorMessage');
          throw Exception(errorMessage);
        }
      } on DioException catch (e) {
        debugPrint('[API_SERVICE] Chunk upload attempt ${retryCount + 1} failed: $e');
        debugPrint('[API_SERVICE] Status: ${e.response?.statusCode}');
        debugPrint('[API_SERVICE] Response data: ${e.response?.data}');
        debugPrint('[API_SERVICE] Request URL: ${e.requestOptions.uri}');
        debugPrint('[API_SERVICE] Request method: ${e.requestOptions.method}');
        
        // Check if this is a retryable error
        if (!_isRetryableChunkError(e)) {
          // Non-retryable error - rethrow immediately
          String errorMessage = _getChunkUploadErrorMessage(e.response?.statusCode, e.response?.data);
          throw Exception(errorMessage);
        }
        
        retryCount++;
        if (retryCount >= maxRetries) {
          // Max retries reached
          String errorMessage = _getChunkUploadErrorMessage(e.response?.statusCode, e.response?.data);
          errorMessage += ' (failed after $maxRetries retries)';
          throw Exception(errorMessage);
        }
        
        // Wait before retry with exponential backoff
        final delay = Duration(seconds: 2 * retryCount);
        debugPrint('[API_SERVICE] Retrying chunk $chunkIndex in ${delay.inSeconds} seconds...');
        await Future.delayed(delay);
      } catch (e) {
        // Non-DioException - rethrow immediately
        debugPrint('[API_SERVICE] Unexpected error uploading chunk $chunkIndex: $e');
        rethrow;
      }
    }
  }
  
  // Check if chunk upload error is retryable
  bool _isRetryableChunkError(DioException e) {
    final statusCode = e.response?.statusCode;
    
    // Retry on network errors and 5xx server errors
    if (e.type == DioExceptionType.connectionError ||
        e.type == DioExceptionType.connectionTimeout ||
        e.type == DioExceptionType.receiveTimeout ||
        e.type == DioExceptionType.sendTimeout) {
      return true;
    }
    
    // Retry on 5xx server errors
    if (statusCode != null && statusCode >= 500 && statusCode < 600) {
      return true;
    }
    
    // Don't retry on 4xx client errors (except 408 Request Timeout)
    if (statusCode != null && statusCode >= 400 && statusCode < 500 && statusCode != 408) {
      return false;
    }
    
    return true;
  }
  
  // Get specific chunk upload error messages
  String _getChunkUploadErrorMessage(int? statusCode, dynamic responseData) {
    // Extract custom message from response if available
    String? customMessage;
    if (responseData is Map) {
      customMessage = responseData['detail'] as String? ?? 
                     responseData['error'] as String? ??
                     responseData['message'] as String?;
    }
    
    // Return custom message if available, otherwise use defaults
    switch (statusCode) {
      // 4xx Client Errors
      case 400:
        return customMessage ?? 'Invalid chunk data. Please check chunk size and format.';
      case 401:
        return customMessage ?? 'Authentication required for chunk upload. Please login again.';
      case 403:
        return customMessage ?? 'Access denied for chunk upload. You may not have permission.';
      case 404:
        return customMessage ?? 'Upload session not found. Please restart file upload.';
      case 408:
        return customMessage ?? 'Chunk upload timeout. Please check connection and try again.';
      case 413:
        return customMessage ?? 'Chunk too large. Maximum chunk size exceeded.';
      case 422:
        return customMessage ?? 'Invalid chunk data. Please check checksum and try again.';
      case 429:
        return customMessage ?? 'Too many chunk uploads. Please wait before trying again.';
        
      // 5xx Server Errors  
      case 500:
        return customMessage ?? 'Server error uploading chunk. Please retry.';
      case 502:
        return customMessage ?? 'Gateway error during chunk upload. Please retry.';
      case 503:
        return customMessage ?? 'Chunk upload service temporarily unavailable. Please retry.';
      case 504:
        return customMessage ?? 'Chunk upload timeout. Server took too long to respond.';
      case 507:
        return customMessage ?? 'Server storage full. Cannot upload chunk at this time.';
        
      default:
        if (statusCode != null) {
          return customMessage ?? 'Chunk upload failed (Error $statusCode). Please retry.';
        }
        return 'Failed to upload chunk. Please check your connection and retry.';
    }
  }

  Future<Map<String, dynamic>> completeUpload({required String uploadId}) async {
    final response = await _dio.post('${ApiConstants.filesEndpoint}/$uploadId/complete');
    return response.data;
  }

  Future<void> downloadFileToPath({
    required String fileId,
    required String savePath,
    void Function(int, int)? onReceiveProgress,
  }) async {
    try {
      // Get current access token for query parameter authentication
      final accessToken = serviceProvider.authService.accessToken;
      
      String url = '${ApiConstants.filesEndpoint}/$fileId/download';
      if (accessToken != null) {
        url += '?dl=1&token=$accessToken';
      }
      
      await _dio.download(
        url,
        savePath,
        onReceiveProgress: onReceiveProgress,
        options: Options(
          headers: _mergeAuthHeaders({
            'Accept': 'application/octet-stream',
            'Cache-Control': 'no-cache',
          }),
          receiveTimeout: Duration(minutes: 30),
          sendTimeout: Duration(minutes: 30),
        ),
      );
    } on DioException catch (e) {
      debugPrint('[DOWNLOAD] Error downloading file: ${e.type} - ${e.message}');
      
      // Enhanced error handling
      if (e.type == DioExceptionType.connectionTimeout ||
          e.type == DioExceptionType.receiveTimeout) {
        throw Exception('Download timeout - Please check your connection and try again');
      } else if (e.type == DioExceptionType.badResponse) {
        final statusCode = e.response?.statusCode;
        if (statusCode == 404) {
          throw Exception('File not found - The file may have been deleted');
        } else if (statusCode == 403) {
          throw Exception('Access denied - You do not have permission to download this file');
        } else if (statusCode == 416) {
          throw Exception('Invalid range request - Please try downloading again');
        } else if (statusCode != null && statusCode >= 500) {
          throw Exception('Server error - Please try again later');
        } else {
          throw Exception('Download failed: ${e.response?.data ?? 'Unknown error'}');
        }
      } else if (e.type == DioExceptionType.connectionError) {
        throw Exception('Network error - Please check your internet connection');
      } else {
        throw Exception('Download failed: ${e.message}');
      }
    }
  }

  // Convenience method that accepts double progress callback
  Future<void> downloadFileToPathWithProgress({
    required String fileId,
    required String savePath,
    required Function(double) onProgress,
  }) async {
    // CRITICAL FIX: Ensure parent directory exists
    final file = io.File(savePath);
    final parentDir = file.parent;
    if (!await parentDir.exists()) {
      _log('[DOWNLOAD] Creating parent directory: ${parentDir.path}');
      await parentDir.create(recursive: true);
    }
    
    try {
      _log('[DOWNLOAD] Starting download: $fileId -> $savePath');
      
      await _dio.download(
        '${ApiConstants.filesEndpoint}/$fileId/download',
        savePath,
        onReceiveProgress: (received, total) {
          if (total > 0) {
            onProgress(received / total);
          }
        },
        options: Options(
          headers: _mergeAuthHeaders({
            'Accept': 'application/octet-stream',
            'Cache-Control': 'no-cache',
          }),
          receiveTimeout: Duration(minutes: 30),
          sendTimeout: Duration(minutes: 30),
        ),
      );
      
      // CRITICAL FIX: Verify file was downloaded
      if (await file.exists()) {
        final actualSize = await file.length();
        _log('[DOWNLOAD] Download completed: $savePath (Size: $actualSize bytes)');
      } else {
        throw Exception('File was not created after download: $savePath');
      }
    } catch (e) {
      _log('[DOWNLOAD] Failed: $e');
      
      // Cleanup on error
      try {
        if (await file.exists()) {
          await file.delete();
        }
      } catch (_) {} // Ignore cleanup errors
      
      rethrow;
    }
  }

  Future<Response<Uint8List>> downloadFileBytes(String fileId) async {
    // Get current access token for query parameter authentication
    final accessToken = serviceProvider.authService.accessToken;
    
    String url = '${ApiConstants.filesEndpoint}/$fileId/download';
    if (accessToken != null) {
      url += '?dl=1&token=$accessToken';
    }
    
    return await _dio.get<Uint8List>(
      url,
      options: Options(
        responseType: ResponseType.bytes,
        followRedirects: false,
        headers: _mergeAuthHeaders({'Range': 'bytes=0-'}),
      ),
    );
  }

  // NEW: Chunked download for large files with range requests
  Future<void> downloadLargeFileToPath({
    required String fileId,
    required String savePath,
    int chunkSize = 4 * 1024 * 1024, // 4MB chunks like upload
    void Function(int, int)? onReceiveProgress,
  }) async {
    try {
      _log('[DOWNLOAD_LARGE] Starting chunked download for file: $fileId');
      
      // Get file info first
      final fileInfo = await getFileInfo(fileId);
      final totalSize = fileInfo['size'] as int? ?? 0;
      final fileName = fileInfo['filename']?.toString() ?? 'unknown';
      
      // Validate file size
      if (totalSize <= 0) {
        throw Exception('Invalid file size: $totalSize bytes');
      }
      
      _log('[DOWNLOAD_LARGE] File info: size=$totalSize, name=$fileName');
      
      // For small files (<100MB), use regular download
      if (totalSize < 100 * 1024 * 1024) {
        _log('[DOWNLOAD_LARGE] Small file detected, using regular download');
        await downloadFileToPath(
          fileId: fileId,
          savePath: savePath,
          onReceiveProgress: onReceiveProgress,
        );
        return;
      }
      
      // For large files, use chunked download with range requests
      int downloadedBytes = 0;
      final file = io.File(savePath);
      
      // CRITICAL FIX: Ensure parent directory exists first
      final parentDir = file.parent;
      if (!await parentDir.exists()) {
        _log('[DOWNLOAD_LARGE] Creating parent directory: ${parentDir.path}');
        await parentDir.create(recursive: true);
      }
      
      // Create/clear file with proper error handling
      try {
        if (file.existsSync()) {
          await file.delete();
        }
        // CRITICAL FIX: Use writeAsBytes for more reliable file writing
        _log('[DOWNLOAD_LARGE] Initializing file: $savePath');
        await file.writeAsBytes([]);
      } catch (e) {
        _log('[DOWNLOAD_LARGE] File initialization failed: $e');
        throw Exception('Failed to initialize download file: $e');
      }
      
      final sink = file.openWrite();
      
      try {
        while (downloadedBytes < totalSize) {
          final endByte = min(downloadedBytes + chunkSize - 1, totalSize - 1);
          
          _log('[DOWNLOAD_LARGE] Downloading chunk: $downloadedBytes-$endByte');
          
          final response = await _dio.get(
            '${ApiConstants.filesEndpoint}/$fileId/download',
            options: Options(
              responseType: ResponseType.bytes,
              headers: _mergeAuthHeaders({'Range': 'bytes=$downloadedBytes-$endByte'}),
              receiveTimeout: Duration(minutes: 10),
              sendTimeout: Duration(minutes: 5),
            ),
          );
          
          // CRITICAL FIX: Proper data type handling and validation
          Uint8List chunkData;
          if (response.data is Uint8List) {
            chunkData = response.data as Uint8List;
          } else if (response.data is List<int>) {
            chunkData = Uint8List.fromList(response.data as List<int>);
          } else {
            throw Exception('Invalid response data type: ${response.data.runtimeType}');
          }
          
          // CRITICAL FIX: Validate response status
          if (response.statusCode != 200 && response.statusCode != 206) {
            throw Exception('HTTP ${response.statusCode}: Failed to download chunk $downloadedBytes-$endByte');
          }
          
          // CRITICAL FIX: Write data with proper flushing
          sink.add(chunkData);
          await sink.flush(); // Ensure data is written to disk
          
          downloadedBytes = endByte + 1;
          
          // Update progress
          onReceiveProgress?.call(downloadedBytes, totalSize);
          
          _log('[DOWNLOAD_LARGE] Chunk written: ${chunkData.length} bytes, Total: $downloadedBytes/$totalSize');
        }
        
        await sink.close();
        
        // CRITICAL FIX: Verify file was written correctly
        if (await file.exists()) {
          final actualSize = await file.length();
          _log('[DOWNLOAD_LARGE] Download completed: $savePath (Size: $actualSize bytes)');
          
          if (actualSize != totalSize) {
            throw Exception('File size mismatch: expected $totalSize, got $actualSize');
          }
        } else {
          throw Exception('File was not created after download: $savePath');
        }
        
      } catch (e) {
        try {
          sink.close();
        } catch (_) {} // Ignore close errors
        
        // Cleanup on error
        try {
          if (await file.exists()) {
            await file.delete();
            _log('[DOWNLOAD_LARGE] Cleaned up failed download: $savePath');
          }
        } catch (_) {} // Ignore cleanup errors
        
        rethrow;
      }
      
    } catch (e) {
      _log('[DOWNLOAD_LARGE_ERROR] Failed: $e');
      rethrow;
    }
  }

  // Settings endpoints
  Future<Map<String, dynamic>> getSettings() async {
    // Not implemented in backend yet (reserved for future)
    return {};
  }

  Future<Map<String, dynamic>> updateSettings(Map<String, dynamic> settings) async {
    // Not implemented in backend yet (reserved for future)
    return {};
  }

  // Comprehensive error handling for all API methods
  // ignore: unused_element
  Future<Map<String, dynamic>> _handleApiResponse(
    Future<Response> apiCall,
    String operationName,
  ) async {
    try {
      final response = await apiCall;
      _log('[$operationName] Response status: ${response.statusCode}');
      
      // Success: 2xx status codes
      if (response.statusCode != null && response.statusCode! >= 200 && response.statusCode! < 300) {
        if (response.data is Map<String, dynamic>) {
          return response.data as Map<String, dynamic>;
        } else if (response.data is Map) {
          return Map<String, dynamic>.from(response.data);
        } else if (response.data != null) {
          _log('[$operationName] Unexpected response format: ${response.data}');
          throw Exception('Invalid server response format for $operationName');
        } else {
          return {'message': '$operationName completed successfully'};
        }
      }
      
      // Handle error status codes
      String errorMessage = _getGenericErrorMessage(response.statusCode!, response.data, operationName);
      _log('[$operationName] Failed: ${response.statusCode} - $errorMessage');
      throw Exception(errorMessage);
    } on DioException catch (e) {
      _log('[$operationName] DioException: ${e.type} - ${e.message}');
      _log('[$operationName] Status: ${e.response?.statusCode}');
      
      String errorMessage = _getGenericErrorMessage(e.response?.statusCode, e.response?.data, operationName);
      throw Exception(errorMessage);
    } catch (e) {
      _log('[$operationName] Unexpected error: $e');
      rethrow;
    }
  }

  // Generic error message handler for all operations
  String _getGenericErrorMessage(int? statusCode, dynamic responseData, String operationName) {
    // Extract custom message from response if available
    String? customMessage;
    if (responseData is Map) {
      customMessage = responseData['detail'] as String? ?? 
                     responseData['error'] as String? ??
                     responseData['message'] as String?;
    }
    
    if (customMessage != null) {
      return customMessage;
    }
    
    // Return operation-specific error messages
    switch (statusCode) {
      case 301: return '$operationName endpoint permanently moved. Please update app.';
      case 400: return 'Invalid $operationName request. Please check your input data.';
      case 401: return 'Authentication required for $operationName. Please login.';
      case 403: return '$operationName forbidden. You may not have permission.';
      case 404: return '$operationName endpoint not found. Please update app.';
      case 408: return '$operationName timeout. Please try again.';
      case 413: return '$operationName request too large. Please reduce data size.';
      case 415: return 'Unsupported format for $operationName. Please use supported formats.';
      case 422: return 'Invalid data for $operationName. Please check your input.';
      case 429: return 'Too many $operationName requests. Please wait before trying again.';
      case 500: return 'Server error during $operationName. Please try again later.';
      case 502: return 'Gateway error during $operationName. Please try again later.';
      case 503: return '$operationName service temporarily unavailable. Please try again later.';
      case 504: return '$operationName gateway timeout. Server is too busy.';
      case 507: return 'Storage full. Cannot complete $operationName at this time.';
      default:
        if (statusCode != null) {
          return '$operationName failed (Error $statusCode). Please try again.';
        }
        return '$operationName failed. Please check your connection and try again.';
    }
  }



  Future<FilePickerResult?> pickFile() async {
    return await FilePicker.platform.pickFiles(
      withData: true,
      allowMultiple: false,
    );
  }

  // Test connectivity to API endpoints
  Future<Map<String, dynamic>> testConnectivity() async {
    try {
      _log('[API_CONNECTIVITY] Testing connection to ${_dio.options.baseUrl}');
      
      // Test health endpoint
      final healthResponse = await _dio.get('/health');
      _log('[API_CONNECTIVITY] Health endpoint: ${healthResponse.statusCode}');
      
      // Test auth endpoint availability
      try {
        await _dio.head('${ApiConstants.authEndpoint}/login');
        _log('[API_CONNECTIVITY] Auth endpoint: Available');
      } catch (e) {
        _log('[API_CONNECTIVITY] Auth endpoint error: $e');
      }
      
      return {
        'connected': true,
        'baseUrl': _dio.options.baseUrl,
        'authEndpoint': '${ApiConstants.authEndpoint}/login',
        'healthStatus': healthResponse.statusCode,
      };
    } catch (e) {
      _log('[API_CONNECTIVITY] Connection failed: $e');
      return {
        'connected': false,
        'error': e.toString(),
        'baseUrl': _dio.options.baseUrl,
        'serverUrl': ApiConstants.serverBaseUrl,
      };
    }
  }

  // Contact Management Methods
  


  // Location and People Nearby endpoints
  Future<Map<String, dynamic>> updateLocation({
    required double latitude,
    required double longitude,
  }) async {
    try {
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/location/update',
        queryParameters: {
          'lat': latitude,
          'lng': longitude,
        },
      );
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error updating location: $e');
      rethrow;
    }
  }

  Future<void> clearLocation() async {
    try {
      await _dio.post('${ApiConstants.usersEndpoint}/location/clear');
    } catch (e) {
      debugPrint('[API_SERVICE] Error clearing location: $e');
      rethrow;
    }
  }

  Future<Map<String, dynamic>> getNearbyUsers({
    required double latitude,
    required double longitude,
    double radiusMeters = 1000,
  }) async {
    try {
      final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/nearby',
        queryParameters: {
          'lat': latitude,
          'lng': longitude,
          'radius': radiusMeters,
        },
      );
      return response.data ?? {};
    } catch (e) {
      debugPrint('[API_SERVICE] Error fetching nearby users: $e');
      rethrow;
    }
  }

  // ============ LOCAL FILE STORAGE FUNCTIONS ============
  
  // Maximum file size: 40GB
  static const int maxFileSizeBytes = 40 * 1024 * 1024 * 1024; // 40GB in bytes
  
  /// Validates if a file can be stored locally based on size
  /// Returns true if file size is within 40GB limit
  bool isFileSizeValid(int fileSizeBytes) {
    if (fileSizeBytes <= 0) {
      _log('[LOCAL_STORAGE] Invalid file size: $fileSizeBytes');
      return false;
    }
    
    if (fileSizeBytes > maxFileSizeBytes) {
      _log('[LOCAL_STORAGE] File size exceeds 40GB limit: ${(fileSizeBytes / (1024 * 1024 * 1024)).toStringAsFixed(2)}GB');
      return false;
    }
    
    _log('[LOCAL_STORAGE] File size valid: ${(fileSizeBytes / (1024 * 1024)).toStringAsFixed(2)}MB');
    return true;
  }
  
  /// Saves file data to local storage with validation
  /// Returns the file path where saved
  Future<String?> saveFileLocally({
    required String fileName,
    required Uint8List fileData,
    required String localStoragePath,
  }) async {
    if (kIsWeb) {
      // Web platform - return empty string instead of null for consistency
      _log('[LOCAL_STORAGE] Web platform: File storage not supported');
      return ''; // Return empty string, not null
    }
    
    try {
      _log('[LOCAL_STORAGE] Saving file: $fileName');
      
      // Validate file size
      if (!isFileSizeValid(fileData.length)) {
        throw Exception('File size exceeds 40GB limit');
      }
      
// Ensure directory exists (web: uses IndexedDB/LocalStorage, mobile: uses file system)
      // Mobile platform - use actual file system
      // Use complete file path for native platforms
      final directory = io.Directory(localStoragePath);
      if (!await directory.exists()) {
        await directory.create(recursive: true);
      }
      final filePath = io.Platform.isWindows ? '${directory.path}\\$fileName' : '${directory.path}/$fileName';
      final file = io.File(filePath);
      
      // Create directory if needed
      await file.parent.create(recursive: true);
      
      // Write file
      await file.writeAsBytes(fileData);
      
      _log('[LOCAL_STORAGE] File saved successfully at: ${file.path}');
      _log('[LOCAL_STORAGE] File size: ${(fileData.length / (1024 * 1024)).toStringAsFixed(2)}MB');
      
      return file.path;
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to save file: $e');
      rethrow;
    }
  }
  
/// Retrieves file data from local storage
  /// Returns the file data as Uint8List
  Future<Uint8List> getFileLocally({
    required String fileName,
    required String localStoragePath,
  }) async {
    try {
      _log('[LOCAL_STORAGE] Retrieving file: $fileName');
      
      if (!kIsWeb) {
        // Mobile platform
        final directory = io.Directory(localStoragePath);
        
        if (!await directory.exists()) {
          _log('[LOCAL_STORAGE] Directory does not exist: $localStoragePath');
          return Uint8List(0);
        }
        
        // Fix: Use path string instead of Directory object
        final filePath = io.Platform.isWindows ? '$localStoragePath\\$fileName' : '$localStoragePath/$fileName';
        final file = io.File(filePath);
        if (!await file.exists()) {
          _log('[LOCAL_STORAGE] File does not exist: $fileName');
          return Uint8List(0);
        }
        
        final fileData = await file.readAsBytes();
        _log('[LOCAL_STORAGE] File retrieved successfully: $fileName');
        return fileData;
      } else {
        // Web platform - not supported for direct file access
        _log('[LOCAL_STORAGE] Web platform: Direct file access not supported');
        return Uint8List(0);
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to get file: $e');
      return Uint8List(0);
    }
  }
  
  /// Gets total size of all files in local storage
  /// Returns size in bytes
  Future<int> getTotalLocalStorageSize(String localStoragePath) async {
    try {
      _log('[LOCAL_STORAGE] Calculating total storage size');
      
if (!kIsWeb) {
        // Mobile platform
        final directory = io.Directory(localStoragePath);
        
        if (!await directory.exists()) {
          return 0;
        }
        
        int totalSize = 0;
        final files = await directory.list(recursive: true).toList();
        
        for (var file in files) {
          if (file is io.File) {
            totalSize += await file.length();
          }
        }
        
        _log('[LOCAL_STORAGE] Total size: ${(totalSize / (1024 * 1024 * 1024)).toStringAsFixed(2)}GB / 40GB');
        return totalSize;
      } else {
        return 0;
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to calculate storage size: $e');
      return 0;
    }
  }
  
  /// Checks if there is enough space to store a new file
  /// Returns true if enough space available
  Future<bool> hasEnoughStorageSpace({
    required int requiredBytes,
    required String localStoragePath,
  }) async {
    try {
      final totalUsed = await getTotalLocalStorageSize(localStoragePath);
      final totalAvailable = maxFileSizeBytes;
      
      if (totalUsed + requiredBytes > totalAvailable) {
        _log('[LOCAL_STORAGE] Insufficient storage: ${(totalUsed / (1024 * 1024 * 1024)).toStringAsFixed(2)}GB used + ${(requiredBytes / (1024 * 1024)).toStringAsFixed(2)}MB required > 40GB limit');
        return false;
      }
      
      _log('[LOCAL_STORAGE] Sufficient storage available');
      return true;
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to check storage space: $e');
      return false;
    }
  }
  
  /// Clears all files from local storage directory
  /// Returns number of files deleted
  Future<int> clearLocalStorage(String localStoragePath) async {
    try {
      _log('[LOCAL_STORAGE] Clearing all files from: $localStoragePath');
      
if (!kIsWeb) {
        // Mobile platform
        final directory = io.Directory(localStoragePath);
        
        if (!await directory.exists()) {
          return 0;
        }
        
        int deletedCount = 0;
        final files = await directory.list().toList();
        
        for (var file in files) {
          if (file is io.File) {
            await file.delete();
            deletedCount++;
          }
        }
        
        _log('[LOCAL_STORAGE] Cleared $deletedCount files');
        return deletedCount;
      } else {
        return 0;
      }
    } catch (e) {
      _log('[LOCAL_STORAGE_ERROR] Failed to clear storage: $e');
      rethrow;
    }
  }

  // ============ QR CODE CROSS-PLATFORM LINKING FUNCTIONS ============
  
  /// Generates a QR code for connecting same account across multiple platforms
  /// Works for: Mobile APK, Web Page, Desktop App
  /// Device types: 'mobile', 'web', 'desktop'
  /// Returns session ID, session code, and QR code data
  Future<Map<String, dynamic>> generateQRCodeForSameAccount({
    required String deviceType, // 'mobile', 'web', 'desktop'
    String? deviceName,
  }) async {
    try {
      _log('[QR_CODE_SAME_ACCOUNT] Generating QR code for same account connection');
      _log('[QR_CODE_SAME_ACCOUNT] Device Type: $deviceType');
      
      // Validate device type
      const validDevices = ['mobile', 'web', 'desktop'];
      if (!validDevices.contains(deviceType.toLowerCase())) {
        throw Exception('Invalid device type. Must be one of: ${validDevices.join(", ")}');
      }
      
      // Call backend to generate QR code
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/qrcode/generate',
        data: {
          'device_type': deviceType.toLowerCase(),
          'device_name': deviceName ?? _getDeviceName(),
        },
      );
      
      final result = response.data ?? {};
      
      _log('[QR_CODE_SAME_ACCOUNT] QR code generated successfully');
      _log('[QR_CODE_SAME_ACCOUNT] Session ID: ${result['session_id']}');
      _log('[QR_CODE_SAME_ACCOUNT] Device: $deviceType');
      
      return {
        'session_id': result['session_id'],
        'session_code': result['session_code'],
        'qr_code_data': result['qr_code_data'],
        'device_type': deviceType.toLowerCase(),
        'device_name': deviceName ?? _getDeviceName(),
        'expiry_seconds': result['expires_in_seconds'] ?? 300,
        'verification_url': result['verification_url'],
      };
    } catch (e) {
      _log('[QR_CODE_SAME_ACCOUNT_ERROR] Failed to generate QR code: $e');
      rethrow;
    }
  }
  
  /// Verifies QR code with session code for same account connection
  /// Returns authentication tokens for the new device
  Future<Map<String, dynamic>> verifyQRCodeForSameAccount({
    required String sessionId,
    required String sessionCode,
  }) async {
    try {
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT] Verifying QR code');
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT] Session ID: $sessionId');
      
      // Call backend to verify QR code
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/qrcode/verify',
        data: {
          'session_id': sessionId,
          'session_code': sessionCode,
        },
      );
      
      final result = response.data ?? {};
      
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT] QR code verified successfully');
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT] Access token received');
      
      return {
        'access_token': result['access_token'],
        'refresh_token': result['refresh_token'],
        'token_type': result['token_type'] ?? 'bearer',
        'user_id': result['user_id'],
        'user_name': result['user_name'],
        'device_id': result['device_id'],
        'device_type': result['device_type'],
        'expires_in': result['expires_in'],
      };
    } catch (e) {
      _log('[QR_CODE_VERIFY_SAME_ACCOUNT_ERROR] Failed to verify QR code: $e');
      rethrow;
    }
  }
  
  /// Gets list of all devices connected to same account
  /// Shows device info: name, type, last seen, status
  Future<List<Map<String, dynamic>>> getConnectedDevices() async {
    try {
      _log('[QR_CODE_DEVICES] Fetching connected devices for same account');
      
      final response = await _dio.get('${ApiConstants.usersEndpoint}/devices');
      
      final devices = (response.data as List?)?.cast<Map<String, dynamic>>() ?? [];
      
      _log('[QR_CODE_DEVICES] Found ${devices.length} connected devices');
      
      return devices;
    } catch (e) {
      _log('[QR_CODE_DEVICES_ERROR] Failed to fetch connected devices: $e');
      return [];
    }
  }
  
  /// Disconnects a device from same account
  /// Revokes access tokens for that device
  Future<bool> disconnectDevice(String deviceId) async {
    try {
      _log('[QR_CODE_DISCONNECT] Disconnecting device: $deviceId');
      
      final response = await _dio.delete(
        '${ApiConstants.usersEndpoint}/devices/$deviceId',
      );
      
      _log('[QR_CODE_DISCONNECT] Device disconnected successfully');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_DISCONNECT_ERROR] Failed to disconnect device: $e');
      rethrow;
    }
  }
  
  /// Syncs account data across all connected devices
  /// Ensures messages and settings are consistent
  Future<Map<String, dynamic>> syncAccountDataAcrossDevices({
    required String dataType, // 'chats', 'messages', 'settings'
    Map<String, dynamic>? additionalData,
  }) async {
    try {
      _log('[QR_CODE_SYNC] Syncing $dataType across all connected devices');
      
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/sync',
        data: {
          'data_type': dataType,
          'timestamp': DateTime.now().millisecondsSinceEpoch,
          ...?additionalData,
        },
      );
      
      _log('[QR_CODE_SYNC] Data sync completed for: $dataType');
      
      return response.data ?? {};
    } catch (e) {
      _log('[QR_CODE_SYNC_ERROR] Failed to sync $dataType: $e');
      rethrow;
    }
  }
  
  /// Gets synchronization status for all connected devices
  /// Shows which devices are online/offline and last sync time
  Future<Map<String, dynamic>> getDeviceSyncStatus() async {
    try {
      _log('[QR_CODE_SYNC_STATUS] Fetching device synchronization status');
      
      final response = await _dio.get('${ApiConstants.usersEndpoint}/sync-status');
      
      final data = response.data ?? {};
      
      _log('[QR_CODE_SYNC_STATUS] Sync status retrieved');
      _log('[QR_CODE_SYNC_STATUS] Devices online: ${data['devices_online']}');
      _log('[QR_CODE_SYNC_STATUS] Last sync: ${data['last_sync']}');
      
      return data;
    } catch (e) {
      _log('[QR_CODE_SYNC_STATUS_ERROR] Failed to fetch sync status: $e');
      return {};
    }
  }
  
  /// Enables real-time synchronization across all devices
  /// When enabled, changes on one device instantly reflect on others
  Future<bool> enableCrossDeviceSync() async {
    try {
      _log('[QR_CODE_ENABLE_SYNC] Enabling cross-device synchronization');
      
      final response = await _dio.put(
        '${ApiConstants.usersEndpoint}/settings/sync',
        data: {'enabled': true},
      );
      
      _log('[QR_CODE_ENABLE_SYNC] Cross-device sync enabled');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_ENABLE_SYNC_ERROR] Failed to enable sync: $e');
      rethrow;
    }
  }
  
  /// Disables real-time synchronization across devices
  Future<bool> disableCrossDeviceSync() async {
    try {
      _log('[QR_CODE_DISABLE_SYNC] Disabling cross-device synchronization');
      
      final response = await _dio.put(
        '${ApiConstants.usersEndpoint}/settings/sync',
        data: {'enabled': false},
      );
      
      _log('[QR_CODE_DISABLE_SYNC] Cross-device sync disabled');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_DISABLE_SYNC_ERROR] Failed to disable sync: $e');
      rethrow;
    }
  }
  
  /// Checks if current device is the primary device for the account
  /// Primary device can manage other connected devices
  Future<bool> isPrimaryDevice() async {
    try {
      _log('[QR_CODE_PRIMARY] Checking if current device is primary');
      
      final response = await _dio.get(
        '${ApiConstants.usersEndpoint}/device-status/is-primary',
      );
      
      final isPrimary = response.data?['is_primary'] ?? false;
      
      _log('[QR_CODE_PRIMARY] Primary device: $isPrimary');
      
      return isPrimary;
    } catch (e) {
      _log('[QR_CODE_PRIMARY_ERROR] Failed to check primary device: $e');
      return false;
    }
  }
  
  /// Gets complete account connection info for same account setup
  /// Returns user, all devices, and sync settings
  Future<Map<String, dynamic>> getAccountConnectionInfo() async {
    try {
      _log('[QR_CODE_ACCOUNT_INFO] Fetching account connection information');
      
      // Get user info
      final userInfo = await getMe();
      
      // Get connected devices
      final devices = await getConnectedDevices();
      
      // Get sync status
      final syncStatus = await getDeviceSyncStatus();
      
      _log('[QR_CODE_ACCOUNT_INFO] Account info retrieved successfully');
      
      return {
        'user': userInfo,
        'devices': devices,
        'sync_status': syncStatus,
        'total_devices': devices.length,
        'timestamp': DateTime.now().toIso8601String(),
      };
    } catch (e) {
      _log('[QR_CODE_ACCOUNT_INFO_ERROR] Failed to get account connection info: $e');
      rethrow;
    }
  }
  
  /// Generates a QR code for cross-platform account linking (Legacy - use generateQRCodeForSameAccount)
  /// Works for: Mobile APK, Web Page, Desktop App
  /// Returns QR code data string and pairing token
  Future<Map<String, dynamic>> generateQRCodeForPairing({
    required String userId,
    required String userName,
    String? deviceName,
  }) async {
    try {
      _log('[QR_CODE] Generating QR code for cross-platform pairing');
      
      // Generate unique pairing session token
      final pairingToken = _generatePairingToken();
      final sessionId = _generateSessionId();
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      
      // Create pairing data object
      final pairingData = {
        'type': 'account_linking',
        'session_id': sessionId,
        'pairing_token': pairingToken,
        'user_id': userId,
        'user_name': userName,
        'device_name': deviceName ?? _getDeviceName(),
        'timestamp': timestamp,
        'expiry': timestamp + (15 * 60 * 1000), // Expires in 15 minutes
        'server_url': ApiConstants.baseUrl,
      };
      
      // Encode as JSON string
      final qrCodeData = jsonEncode(pairingData);
      
      _log('[QR_CODE] QR code generated successfully');
      _log('[QR_CODE] Session ID: $sessionId');
      _log('[QR_CODE] Expiry: 15 minutes');
      
      return {
        'qr_data': qrCodeData,
        'session_id': sessionId,
        'pairing_token': pairingToken,
        'expiry_seconds': 900,
        'device_name': pairingData['device_name'],
      };
    } catch (e) {
      _log('[QR_CODE_ERROR] Failed to generate QR code: $e');
      rethrow;
    }
  }
  
  /// Validates and processes scanned QR code for account linking
  /// Returns paired account information (Legacy - decodes local QR data)
  Future<Map<String, dynamic>> validateQRCodeScan(String qrCodeData) async {
    try {
      _log('[QR_CODE_VALIDATE] Validating scanned QR code');
      
      // Decode QR data
      final pairingData = jsonDecode(qrCodeData) as Map<String, dynamic>;
      
      // Validate required fields
      _validateQRCodeFields(pairingData);
      
      // Check expiry
      final currentTime = DateTime.now().millisecondsSinceEpoch;
      final expiryTime = pairingData['expiry'] as int;
      
      if (currentTime > expiryTime) {
        throw Exception('QR code has expired. Please generate a new one.');
      }
      
      _log('[QR_CODE_VALIDATE] QR code validation successful');
      _log('[QR_CODE_VALIDATE] User: ${pairingData['user_name']}');
      _log('[QR_CODE_VALIDATE] Source Device: ${pairingData['device_name']}');
      
      return pairingData;
    } catch (e) {
      _log('[QR_CODE_VALIDATE_ERROR] Failed to validate QR code: $e');
      rethrow;
    }
  }
  
  /// Links a new device/platform to existing account using pairing token
  /// Returns success status and session information (Legacy function)
  Future<Map<String, dynamic>> linkDeviceWithPairingToken({
    required String pairingToken,
    required String sessionId,
    required String targetDeviceType, // 'mobile', 'web', 'desktop'
    required String targetDeviceName,
  }) async {
    try {
      _log('[QR_CODE_LINK_LEGACY] Linking device: $targetDeviceName ($targetDeviceType)');
      
      // Send pairing request to backend
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/link-device',
        data: {
          'pairing_token': pairingToken,
          'session_id': sessionId,
          'device_type': targetDeviceType,
          'device_name': targetDeviceName,
          'timestamp': DateTime.now().millisecondsSinceEpoch,
        },
      );
      
      final result = response.data ?? {};
      
      _log('[QR_CODE_LINK_LEGACY] Device linked successfully');
      _log('[QR_CODE_LINK_LEGACY] Device ID: ${result['device_id']}');
      
      return result;
    } catch (e) {
      _log('[QR_CODE_LINK_LEGACY_ERROR] Failed to link device: $e');
      rethrow;
    }
  }
  
  /// Gets list of all linked devices for current account
  /// Returns list of device information (Legacy - use getConnectedDevices)
  Future<List<Map<String, dynamic>>> getLinkedDevices() async {
    try {
      _log('[QR_CODE_LEGACY] Fetching linked devices');
      
      final response = await _dio.get('${ApiConstants.usersEndpoint}/devices');
      
      final devices = (response.data as List?)?.cast<Map<String, dynamic>>() ?? [];
      
      _log('[QR_CODE_LEGACY] Found ${devices.length} linked devices');
      
      return devices;
    } catch (e) {
      _log('[QR_CODE_LEGACY_ERROR] Failed to fetch linked devices: $e');
      return [];
    }
  }
  
  /// Unlinks a device from account
  /// Returns success status (Legacy - use disconnectDevice)
  Future<bool> unlinkDevice(String deviceId) async {
    try {
      _log('[QR_CODE_UNLINK_LEGACY] Unlinking device: $deviceId');
      
      final response = await _dio.delete(
        '${ApiConstants.usersEndpoint}/devices/$deviceId',
      );
      
      _log('[QR_CODE_UNLINK_LEGACY] Device unlinked successfully');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_UNLINK_LEGACY_ERROR] Failed to unlink device: $e');
      rethrow;
    }
  }
  
  /// Syncs data across all linked devices (Legacy - use syncAccountDataAcrossDevices)
  /// Used to keep accounts synchronized
  Future<Map<String, dynamic>> syncAcrossDevices({
    required String dataType, // 'chats', 'messages', 'settings'
    Map<String, dynamic>? additionalData,
  }) async {
    try {
      _log('[QR_CODE_SYNC_LEGACY] Syncing $dataType across all devices');
      
      final response = await _dio.post(
        '${ApiConstants.usersEndpoint}/sync',
        data: {
          'data_type': dataType,
          'timestamp': DateTime.now().millisecondsSinceEpoch,
          ...?additionalData,
        },
      );
      
      _log('[QR_CODE_SYNC_LEGACY] Sync completed successfully');
      
      return response.data ?? {};
    } catch (e) {
      _log('[QR_CODE_SYNC_LEGACY_ERROR] Failed to sync data: $e');
      rethrow;
    }
  }
  
  /// Enables or disables cross-device notifications
  /// When enabled, notifications sync across all linked devices (Legacy)
  Future<bool> setCrossDeviceNotifications(bool enabled) async {
    try {
      _log('[QR_CODE_NOTIFICATIONS_LEGACY] Setting cross-device notifications: $enabled');
      
      final response = await _dio.put(
        '${ApiConstants.usersEndpoint}/settings/cross-device-notifications',
        data: {'enabled': enabled},
      );
      
      _log('[QR_CODE_NOTIFICATIONS_LEGACY] Cross-device notifications updated');
      
      return response.statusCode == 200;
    } catch (e) {
      _log('[QR_CODE_NOTIFICATIONS_LEGACY_ERROR] Failed to update notifications: $e');
      rethrow;
    }
  }
  
  /// Verifies a device login from another platform using pairing token
  /// Prevents unauthorized access attempts (Legacy)
  Future<Map<String, dynamic>> verifyDeviceLogin({
    required String pairingToken,
    required String deviceId,
    required String deviceType,
  }) async {
    try {
      _log('[QR_CODE_VERIFY_LOGIN_LEGACY] Verifying device login: $deviceId');
      
      final response = await _dio.post(
        '${ApiConstants.authEndpoint}/verify-device-login',
        data: {
          'pairing_token': pairingToken,
          'device_id': deviceId,
          'device_type': deviceType,
          'verification_time': DateTime.now().millisecondsSinceEpoch,
        },
      );
      
      _log('[QR_CODE_VERIFY_LOGIN_LEGACY] Device login verified');
      
      return response.data ?? {};
    } catch (e) {
      _log('[QR_CODE_VERIFY_LOGIN_LEGACY_ERROR] Failed to verify device login: $e');
      rethrow;
    }
  }
  
  // ============ PRIVATE HELPER FUNCTIONS FOR QR CODE ============
  
  /// Generates a cryptographically secure pairing token
  String _generatePairingToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    final random = Random.secure();
    final token = List<String>.generate(32, (index) => chars[random.nextInt(chars.length)]).join();
    return token;
  }
  
  /// Generates a unique session ID for pairing
  String _generateSessionId() {
    return 'session_${DateTime.now().millisecondsSinceEpoch}_${Random().nextInt(10000)}';
  }
  
/// Gets device name based on platform
  String _getDeviceName() {
    if (kIsWeb) {
      return 'Web Browser';
    } else if (io.Platform.isAndroid) {
      return 'Android Device';
    } else if (io.Platform.isIOS) {
      return 'iOS Device';
    } else if (io.Platform.isWindows) {
      return 'Windows Desktop';
    } else if (io.Platform.isMacOS) {
      return 'macOS Device';
    } else if (io.Platform.isLinux) {
      return 'Linux Device';
    } else {
      return 'Unknown Device';
    }
  }
  
  /// Validates required fields in QR code data
  void _validateQRCodeFields(Map<String, dynamic> data) {
    final requiredFields = [
      'type',
      'session_id',
      'pairing_token',
      'user_id',
      'user_name',
      'device_name',
      'timestamp',
      'expiry',
    ];
    
    for (final field in requiredFields) {
      if (!data.containsKey(field) || data[field] == null) {
        throw Exception('Invalid QR code: Missing required field "$field"');
      }
    }
    
    if (data['type'] != 'account_linking') {
      throw Exception('Invalid QR code: Incorrect type');
    }
  }
}
