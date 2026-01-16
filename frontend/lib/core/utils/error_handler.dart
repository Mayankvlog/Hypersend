import 'package:dio/dio.dart';

/// Comprehensive HTTP status code handler for frontend
class HttpErrorHandler {
  /// Handle HTTP errors and return user-friendly messages
  static String getErrorMessage(int statusCode, String? detail) {
    switch (statusCode) {
      // 2xx Success Codes
      case 200:
        return 'Request successful';
      case 201:
        return 'Resource created successfully';
      case 202:
        return 'Request accepted for processing';
      case 204:
        return 'Request successful, no content to return';
      
      // 3xx Redirection Codes
      case 300:
        return 'Multiple choices available - please select an option';
      case 301:
        return 'Resource moved permanently - please update your bookmarks';
      case 302:
        return 'Resource temporarily moved - following redirect';
      case 304:
        return 'Content not modified - using cached version';
      case 307:
        return 'Temporary redirect - preserving request method';
      case 308:
        return 'Permanent redirect - preserving request method';
      
      // 4xx Client Errors
      case 400:
        return _get400ErrorMessage(detail);
      case 401:
        return _get401ErrorMessage(detail);
      case 403:
        return _get403ErrorMessage(detail);
      case 404:
        return _get404ErrorMessage(detail);
      case 405:
        return 'Method not allowed - please check API documentation';
      case 408:
        return 'Request timeout - please check your connection and try again';
      case 409:
        return _get409ErrorMessage(detail);
      case 422:
        return _get422ErrorMessage(detail);
      case 429:
        return _get429ErrorMessage(detail);
      
      // 5xx Server Errors
      case 500:
        return 'Internal server error - please try again later';
      case 502:
        return 'Bad gateway - upstream service unavailable';
      case 503:
        return 'Service temporarily unavailable - please try again later';
      case 504:
        return 'Gateway timeout - request took too long';
      case 511:
        return 'Network authentication required';
      
      default:
        return detail ?? 'An error occurred - please try again';
    }
  }

  /// Get specific error message for 400 Bad Request
  static String _get400ErrorMessage(String? detail) {
    if (detail == null) return 'Bad request - please check your input';
    
    final lowerDetail = detail.toLowerCase();
    
    if (lowerDetail.contains('email')) {
      if (lowerDetail.contains('required') || lowerDetail.contains('empty')) {
        return 'Email is required';
      } else if (lowerDetail.contains('valid') || lowerDetail.contains('format')) {
        return 'Please enter a valid email address';
      }
    }
    
    if (lowerDetail.contains('password')) {
      if (lowerDetail.contains('required') || lowerDetail.contains('empty')) {
        return 'Password is required';
      } else if (lowerDetail.contains('at least')) {
        return 'Password must be at least 8 characters long';
      }
    }
    
    if (lowerDetail.contains('username') || lowerDetail.contains('name')) {
      if (lowerDetail.contains('required') || lowerDetail.contains('empty')) {
        return 'Username is required';
      }
    }
    
    return 'Bad request - please check your input and try again';
  }

  /// Get specific error message for 401 Unauthorized
  static String _get401ErrorMessage(String? detail) {
    if (detail == null) return 'Authentication required';
    
    final lowerDetail = detail.toLowerCase();
    
    if (lowerDetail.contains('missing') || lowerDetail.contains('required')) {
      return 'Please log in to access this resource';
    } else if (lowerDetail.contains('invalid') || lowerDetail.contains('incorrect')) {
      return 'Invalid email or password';
    } else if (lowerDetail.contains('expired') || lowerDetail.contains('token')) {
      return 'Your session has expired - please log in again';
    } else if (lowerDetail.contains('credentials')) {
      return 'Invalid authentication credentials';
    }
    
    return 'Authentication required - please log in';
  }

  /// Get specific error message for 403 Forbidden
  static String _get403ErrorMessage(String? detail) {
    if (detail == null) return 'Access denied';
    
    final lowerDetail = detail.toLowerCase();
    
    if (lowerDetail.contains('permission') || lowerDetail.contains('access')) {
      return 'You don\'t have permission to access this resource';
    } else if (lowerDetail.contains('admin') || lowerDetail.contains('administrator')) {
      return 'Administrator access required';
    } else if (lowerDetail.contains('owner')) {
      return 'Only the resource owner can access this';
    }
    
    return 'Access denied - insufficient permissions';
  }

  /// Get specific error message for 404 Not Found
  static String _get404ErrorMessage(String? detail) {
    if (detail == null) return 'Resource not found';
    
    if (detail.contains('user') || detail.contains('account')) {
      return 'User not found';
    } else if (detail.contains('chat') || detail.contains('conversation')) {
      return 'Chat not found';
    } else if (detail.contains('message')) {
      return 'Message not found';
    } else if (detail.contains('file')) {
      return 'File not found';
    } else if (detail.contains('group')) {
      return 'Group not found';
    }
    
    return 'Resource not found - please check the URL';
  }

  /// Get specific error message for 409 Conflict
  static String _get409ErrorMessage(String? detail) {
    if (detail == null) return 'Resource conflict';
    
    if (detail.contains('email') || detail.contains('exists')) {
      return 'An account with this email already exists';
    } else if (detail.contains('username')) {
      return 'This username is already taken';
    } else if (detail.contains('chat') || detail.contains('group')) {
      return 'A chat with this name already exists';
    }
    
    return 'Resource conflict - the resource may have been modified';
  }

  /// Get specific error message for 422 Unprocessable Entity
  static String _get422ErrorMessage(String? detail) {
    if (detail == null) return 'Invalid data provided';
    
    if (detail.contains('validation')) {
      return 'Validation failed - please check your input';
    } else if (detail.contains('email') && detail.contains('valid')) {
      return 'Please enter a valid email address';
    } else if (detail.contains('password') && detail.contains('length')) {
      return 'Password must be at least 8 characters long';
    } else if (detail.contains('required')) {
      return 'Required fields are missing';
    }
    
    return 'Invalid data - please check your input and try again';
  }

  /// Get specific error message for 429 Too Many Requests
  static String _get429ErrorMessage(String? detail) {
    if (detail == null) return 'Too many requests - please try again later';
    
    if (detail.contains('rate') || detail.contains('limit')) {
      return 'Rate limit exceeded - please wait before trying again';
    } else if (detail.contains('login') || detail.contains('auth')) {
      return 'Too many login attempts - please wait before trying again';
    }
    
    return 'Too many requests - please slow down and try again later';
  }

  /// Get user-friendly hints for error codes
  static List<String> getErrorHints(int statusCode) {
    switch (statusCode) {
      case 400:
        return [
          'Check all required fields are filled',
          'Verify email format is correct',
          'Ensure password meets requirements'
        ];
      case 401:
        return [
          'Check your email and password',
          'Try logging in again',
          'Create an account if you don\'t have one'
        ];
      case 403:
        return [
          'Verify you have the right permissions',
          'Contact the resource owner',
          'Check if you\'re logged into the correct account'
        ];
      case 404:
        return [
          'Check the URL is correct',
          'Verify the resource exists',
          'The resource may have been deleted'
        ];
      case 408:
        return [
          'Check your internet connection',
          'Try with a smaller file',
          'Refresh and try again'
        ];
      case 409:
        return [
          'Refresh the page and try again',
          'Use different data if creating new resource',
          'Check if someone else made changes'
        ];
      case 422:
        return [
          'Review form validation errors',
          'Check data format and constraints',
          'Ensure all fields are valid'
        ];
      case 429:
        return [
          'Wait a few minutes before trying again',
          'Reduce how frequently you\'re making requests',
          'Try again later or contact support if the problem continues'
        ];
      case 500:
      case 502:
      case 503:
      case 504:
        return [
          'Try again in a few moments',
          'Check if there\'s ongoing maintenance',
          'Contact support if the problem persists'
        ];
      default:
        return ['Try again', 'Check your internet connection', 'Contact support if needed'];
    }
  }

  /// Determine if error is recoverable (should retry)
  static bool isRecoverableError(int statusCode) {
    return [
      408, // Request Timeout
      429, // Too Many Requests
      500, // Internal Server Error
      502, // Bad Gateway
      503, // Service Unavailable
      504, // Gateway Timeout
    ].contains(statusCode);
  }

  /// Get retry delay in seconds for retryable errors
  static int getRetryDelay(int statusCode) {
    switch (statusCode) {
      case 408:
        return 5; // 5 seconds for timeout
      case 429:
        return 60; // 1 minute for rate limiting
      case 500:
        return 10; // 10 seconds for server error
      case 502:
        return 30; // 30 seconds for bad gateway
      case 503:
        return 60; // 1 minute for service unavailable
      case 504:
        return 30; // 30 seconds for gateway timeout
      default:
        return 5;
    }
  }

  /// Handle Dio exceptions and convert to user-friendly format
  static Map<String, dynamic> handleDioError(DioException error) {
    String message;
    int? statusCode;
    List<String> hints = [];

    if (error.response != null) {
      statusCode = error.response!.statusCode;
      // Safely handle nullable statusCode and detail
      final safeStatusCode = statusCode ?? -1;
      final detailMsg = error.response?.data?['detail']?.toString();
      message = getErrorMessage(safeStatusCode, detailMsg);
      hints = getErrorHints(safeStatusCode);
    } else if (error.type == DioExceptionType.connectionTimeout) {
      message = 'Connection timeout - please check your internet connection';
      statusCode = 408;
      hints = ['Check your internet connection', 'Try again in a moment'];
    } else if (error.type == DioExceptionType.sendTimeout) {
      message = 'Request timeout - please try again';
      statusCode = 408;
      hints = ['Check your internet connection', 'Try with smaller data'];
    } else if (error.type == DioExceptionType.receiveTimeout) {
      message = 'Server response timeout - please try again';
      statusCode = 504;
      hints = ['Try again in a moment', 'Check server status'];
    } else if (error.type == DioExceptionType.connectionError) {
      message = 'No internet connection - please check your network';
      statusCode = null;
      hints = ['Check your internet connection', 'Verify WiFi/mobile data'];
    } else if (error.type == DioExceptionType.badResponse) {
      message = 'Invalid server response';
      statusCode = error.response?.statusCode;
      hints = ['Try again', 'Contact support if problem persists'];
    } else {
      message = 'Network error occurred';
      statusCode = null;
      hints = ['Check your internet connection', 'Try again'];
    }

    return {
      'message': message,
      'statusCode': statusCode,
      'hints': hints,
      'isRecoverable': statusCode != null ? isRecoverableError(statusCode) : false,
      'retryDelay': statusCode != null ? getRetryDelay(statusCode) : 5,
      'errorType': error.type.toString(),
    };
  }
}

/// Custom exception for API errors
class ApiException implements Exception {
  final String message;
  final int? statusCode;
  final List<String> hints;
  final bool isRecoverable;
  final int retryDelay;

  ApiException({
    required this.message,
    this.statusCode,
    this.hints = const [],
    this.isRecoverable = false,
    this.retryDelay = 5,
  });

  @override
  String toString() {
    return 'ApiException: $message (Status: $statusCode, Recoverable: $isRecoverable)';
  }
}