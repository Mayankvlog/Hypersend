import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart' as path;

class ClientSecurityManager {
  static final _secureStorage = FlutterSecureStorage();
  static const _maxAuthFailures = 5;
  
  int _authFailureCount = 0;
  int? _lastAuthTime;
  List<SecurityEvent> _securityEvents = [];
  Uint8List? _encryptionKey;
  
  // Security configuration
  final SecurityConfig _config;
  
  ClientSecurityManager(this._config);

  /// Initialize client security
  Future<void> initialize() async {
    // Generate or load encryption key
    await _initializeEncryption();
    
    // Check device security
    await _performSecurityCheck();
    
    // Setup security monitoring
    await _setupSecurityMonitoring();
    
    // Clear clipboard on start
    await _secureClipboardClear();
  }

  /// Encrypt message for local storage
  Future<EncryptedLocalMessage> encryptLocalMessage(
    String content,
    String chatId,
    String messageType,
    {String? mediaKey, String? thumbnailKey}
  ) async {
    if (_encryptionKey == null) {
      throw SecurityException('Encryption not initialized');
    }
    
    // Generate random IV
    final iv = _generateIV();
    
    // Encrypt content
    final encrypted = await _aesGcmEncrypt(content, _encryptionKey!, iv);
    
    return EncryptedLocalMessage(
      messageId: _generateMessageId(),
      encryptedContent: encrypted.ciphertext,
      iv: iv,
      authTag: encrypted.authTag,
      chatId: chatId,
      messageType: messageType,
      timestamp: DateTime.now().millisecondsSinceEpoch,
      mediaKey: mediaKey,
      thumbnailKey: thumbnailKey,
    );
  }

  /// Decrypt message from local storage
  Future<String> decryptLocalMessage(EncryptedLocalMessage encryptedMessage) async {
    if (_encryptionKey == null) {
      throw SecurityException('Encryption not initialized');
    }
    
    return await _aesGcmDecrypt(
      encryptedMessage.encryptedContent,
      _encryptionKey!,
      encryptedMessage.iv,
      encryptedMessage.authTag,
    );
  }

  /// Check if device is compromised
  Future<bool> isDeviceCompromised() async {
    final checks = await Future.wait([
      _checkRootJailbreak(),
      _checkDeveloperMode(),
      _checkAdbDebugging(),
      _checkAppIntegrity(),
      _checkSystemIntegrity(),
    ]);
    
    return checks.any((check) => check);
  }

  /// Enable screenshot protection
  Future<bool> enableScreenshotProtection() async {
    if (!_config.enableScreenshotProtection) {
      return false;
    }
    
    try {
      // Use platform channels to prevent screenshots
      const platform = MethodChannel('zaply/security');
      
      await platform.invokeMethod('enableScreenshotProtection');
      
      _recordSecurityEvent(
        SecurityEventType.screenshotProtectionEnabled,
        'Screenshot protection enabled',
        SecuritySeverity.low,
      );
      
      return true;
    } catch (e) {
      _recordSecurityEvent(
        SecurityEventType.screenshotProtectionFailed,
        'Failed to enable screenshot protection: $e',
        SecuritySeverity.medium,
      );
      return false;
    }
  }

  /// Handle authentication failure
  Future<bool> handleAuthFailure() async {
    _authFailureCount++;
    _lastAuthTime = DateTime.now().millisecondsSinceEpoch;
    
    _recordSecurityEvent(
      SecurityEventType.authFailure,
      'Authentication failure #$_authFailureCount',
      _authFailureCount >= _maxAuthFailures ? SecuritySeverity.critical : SecuritySeverity.high,
    );
    
    // Check if auto-wipe should be triggered
    if (_authFailureCount >= _maxAuthFailures && _config.autoWipeOnAuthFailure) {
      await _initiateAutoWipe();
      return true;
    }
    
    return false;
  }

  /// Handle successful authentication
  Future<void> handleAuthSuccess() async {
    _authFailureCount = 0;
    _lastAuthTime = DateTime.now().millisecondsSinceEpoch;
    
    _recordSecurityEvent(
      SecurityEventType.authSuccess,
      'Authentication successful',
      SecuritySeverity.low,
    );
  }

  /// Get security status
  Future<SecurityStatus> getSecurityStatus() async {
    final isCompromised = await isDeviceCompromised();
    final packageInfo = await PackageInfo.fromPlatform();
    final deviceInfoPlugin = DeviceInfoPlugin();
    Map<String, dynamic> deviceInfo = {};
    
    if (Platform.isAndroid) {
      final androidInfo = await deviceInfoPlugin.androidInfo;
      deviceInfo = androidInfo.data;
    } else if (Platform.isIOS) {
      final iosInfo = await deviceInfoPlugin.iosInfo;
      deviceInfo = iosInfo.data;
    }
    
    return SecurityStatus(
      isCompromised: isCompromised,
      authFailureCount: _authFailureCount,
      lastAuthTime: _lastAuthTime,
      appVersion: packageInfo.version,
      buildNumber: packageInfo.buildNumber,
      deviceInfo: deviceInfo,
      recentSecurityEvents: _securityEvents.take(10).toList(),
      encryptionInitialized: _encryptionKey != null,
      config: _config,
    );
  }

  /// Initialize encryption key
  Future<void> _initializeEncryption() async {
    try {
      // Try to load existing key
      final storedKey = await _secureStorage.read(key: 'encryption_key');
      
      if (storedKey != null) {
        _encryptionKey = base64.decode(storedKey);
      } else {
        // Generate new key
        _encryptionKey = _generateEncryptionKey();
        await _secureStorage.write(
          key: 'encryption_key',
          value: base64.encode(_encryptionKey!),
        );
      }
      
      _recordSecurityEvent(
        SecurityEventType.encryptionInitialized,
        'Encryption initialized',
        SecuritySeverity.low,
      );
      
    } catch (e) {
      _recordSecurityEvent(
        SecurityEventType.encryptionFailed,
        'Failed to initialize encryption: $e',
        SecuritySeverity.critical,
      );
      throw SecurityException('Failed to initialize encryption');
    }
  }

  /// Generate encryption key
  Uint8List _generateEncryptionKey() {
    final random = Random.secure();
    final bytes = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      bytes[i] = random.nextInt(256);
    }
    return bytes;
  }

  /// Generate IV
  Uint8List _generateIV() {
    final random = Random.secure();
    final bytes = Uint8List(12);
    for (int i = 0; i < 12; i++) {
      bytes[i] = random.nextInt(256);
    }
    return bytes;
  }

  /// Generate message ID
  String _generateMessageId() {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final random = Random.secure().nextInt(1 << 16);
    return '$timestamp-$random';
  }

  /// AES-256-GCM encryption
  Future<AESEncryptedData> _aesGcmEncrypt(String plaintext, Uint8List key, Uint8List iv) async {
    // Use platform-specific encryption
    const platform = MethodChannel('zaply/crypto');
    
    final result = await platform.invokeMethod('aesGcmEncrypt', {
      'plaintext': plaintext,
      'key': base64.encode(key),
      'iv': base64.encode(iv),
    });
    
    return AESEncryptedData(
      ciphertext: base64.decode(result['ciphertext']),
      authTag: base64.decode(result['authTag']),
    );
  }

  /// AES-256-GCM decryption
  Future<String> _aesGcmDecrypt(
    Uint8List ciphertext,
    Uint8List key,
    Uint8List iv,
    Uint8List authTag,
  ) async {
    // Use platform-specific decryption
    const platform = MethodChannel('zaply/crypto');
    
    final result = await platform.invokeMethod('aesGcmDecrypt', {
      'ciphertext': base64.encode(ciphertext),
      'key': base64.encode(key),
      'iv': base64.encode(iv),
      'authTag': base64.encode(authTag),
    });
    
    return result['plaintext'];
  }

  /// Check for root/jailbreak
  Future<bool> _checkRootJailbreak() async {
    if (!_config.enableRootDetection) {
      return false;
    }
    
    try {
      const platform = MethodChannel('zaply/security');
      
      final isRooted = await platform.invokeMethod('checkRootJailbreak');
      
      if (isRooted) {
        _recordSecurityEvent(
          SecurityEventType.rootDetected,
          'Root/jailbreak detected',
          SecuritySeverity.critical,
        );
        return true;
      }
      
      return false;
    } catch (e) {
      _recordSecurityEvent(
        SecurityEventType.rootCheckFailed,
        'Failed to check root/jailbreak: $e',
        SecuritySeverity.medium,
      );
      return false;
    }
  }

  /// Check developer mode
  Future<bool> _checkDeveloperMode() async {
    try {
      const platform = MethodChannel('zaply/security');
      
      final devModeEnabled = await platform.invokeMethod('checkDeveloperMode');
      
      if (devModeEnabled) {
        _recordSecurityEvent(
          SecurityEventType.developerModeDetected,
          'Developer mode detected',
          SecuritySeverity.medium,
        );
        return true;
      }
      
      return false;
    } catch (e) {
      return false;
    }
  }

  /// Check ADB debugging
  Future<bool> _checkAdbDebugging() async {
    try {
      const platform = MethodChannel('zaply/security');
      
      final adbEnabled = await platform.invokeMethod('checkAdbDebugging');
      
      if (adbEnabled) {
        _recordSecurityEvent(
          SecurityEventType.adbDebuggingDetected,
          'ADB debugging detected',
          SecuritySeverity.medium,
        );
        return true;
      }
      
      return false;
    } catch (e) {
      return false;
    }
  }

  /// Check app integrity
  Future<bool> _checkAppIntegrity() async {
    try {
      final expectedSignature = _config.expectedAppSignature;
      
      if (expectedSignature != null) {
        const platform = MethodChannel('zaply/security');
        
        final appSignature = await platform.invokeMethod('getAppSignature');
        
        if (appSignature != expectedSignature) {
          _recordSecurityEvent(
            SecurityEventType.appSignatureMismatch,
            'App signature mismatch',
            SecuritySeverity.critical,
          );
          return true;
        }
      }
      
      return false;
    } catch (e) {
      _recordSecurityEvent(
        SecurityEventType.appIntegrityCheckFailed,
        'Failed to check app integrity: $e',
        SecuritySeverity.medium,
      );
      return false;
    }
  }

  /// Check system integrity
  Future<bool> _checkSystemIntegrity() async {
    try {
      const platform = MethodChannel('zaply/security');
      
      final systemIntegrity = await platform.invokeMethod('checkSystemIntegrity');
      
      if (!systemIntegrity) {
        _recordSecurityEvent(
          SecurityEventType.systemIntegrityCompromised,
          'System integrity compromised',
          SecuritySeverity.high,
        );
        return true;
      }
      
      return false;
    } catch (e) {
      return false;
    }
  }

  /// Perform initial security check
  Future<void> _performSecurityCheck() async {
    final isCompromised = await isDeviceCompromised();
    
    if (isCompromised) {
      await _initiateAutoWipe();
    }
  }

  /// Setup security monitoring
  Future<void> _setupSecurityMonitoring() async {
    // Monitor app lifecycle
    // Monitor network changes
    // Monitor battery optimization
    // Monitor app overlay attempts
  }

  /// Secure clipboard clear
  Future<void> _secureClipboardClear() async {
    try {
      await Clipboard.setData(const ClipboardData(text: ''));
      
      _recordSecurityEvent(
        SecurityEventType.clipboardCleared,
        'Clipboard cleared',
        SecuritySeverity.low,
      );
    } catch (e) {
      _recordSecurityEvent(
        SecurityEventType.clipboardClearFailed,
        'Failed to clear clipboard: $e',
        SecuritySeverity.low,
      );
    }
  }

  /// Initiate auto-wipe
  Future<void> _initiateAutoWipe() async {
    _recordSecurityEvent(
      SecurityEventType.autoWipeInitiated,
      'Auto-wipe initiated due to security compromise',
      SecuritySeverity.critical,
    );
    
    try {
      // Clear all local data
      await _wipeLocalData();
      
      // Clear secure storage
      await _secureStorage.deleteAll();
      
      // Clear encryption key
      _encryptionKey = null;
      
      // Reset auth failures
      _authFailureCount = 0;
      _lastAuthTime = null;
      
      // Notify user
      await _notifySecurityCompromise();
      
    } catch (e) {
      _recordSecurityEvent(
        SecurityEventType.autoWipeFailed,
        'Auto-wipe failed: $e',
        SecuritySeverity.critical,
      );
    }
  }

  /// Wipe local data
  Future<void> _wipeLocalData() async {
    try {
      final appDir = await getApplicationDocumentsDirectory();
      final dbPath = await getDatabasesPath();
      
      // Delete database
      final database = await openDatabase(
        path.join(dbPath, 'zaply.db'),
      );
      await database.close();
      
      await deleteDatabase(path.join(dbPath, 'zaply.db'));
      
      // Delete local files
      if (await appDir.exists()) {
        await appDir.delete(recursive: true);
      }
      
      _recordSecurityEvent(
        SecurityEventType.localDataWiped,
        'Local data wiped',
        SecuritySeverity.high,
      );
      
    } catch (e) {
      _recordSecurityEvent(
        SecurityEventType.localDataWipeFailed,
        'Failed to wipe local data: $e',
        SecuritySeverity.high,
      );
    }
  }

  /// Notify security compromise
  Future<void> _notifySecurityCompromise() async {
    // Show security alert to user
    // Log to server for monitoring
    // Optionally send security notification
  }

  /// Record security event
  void _recordSecurityEvent(
    SecurityEventType type,
    String message,
    SecuritySeverity severity,
  ) {
    final event = SecurityEvent(
      type: type,
      message: message,
      severity: severity,
      timestamp: DateTime.now().millisecondsSinceEpoch,
    );
    
    _securityEvents.insert(0, event);
    
    // Keep only last 100 events
    if (_securityEvents.length > 100) {
      _securityEvents = _securityEvents.take(100).toList();
    }
    
    // Log critical events
    if (severity == SecuritySeverity.critical) {
      debugPrint('CRITICAL SECURITY EVENT: $message');
    }
  }
}

// Data classes
class SecurityConfig {
  final bool enableScreenshotProtection;
  final bool enableRootDetection;
  final bool autoWipeOnAuthFailure;
  final String? expectedAppSignature;
  
  const SecurityConfig({
    this.enableScreenshotProtection = true,
    this.enableRootDetection = true,
    this.autoWipeOnAuthFailure = true,
    this.expectedAppSignature,
  });
}

class EncryptedLocalMessage {
  final String messageId;
  final Uint8List encryptedContent;
  final Uint8List iv;
  final Uint8List authTag;
  final String chatId;
  final String messageType;
  final int timestamp;
  final String? mediaKey;
  final String? thumbnailKey;
  
  EncryptedLocalMessage({
    required this.messageId,
    required this.encryptedContent,
    required this.iv,
    required this.authTag,
    required this.chatId,
    required this.messageType,
    required this.timestamp,
    this.mediaKey,
    this.thumbnailKey,
  });
}

class SecurityEvent {
  final SecurityEventType type;
  final String message;
  final SecuritySeverity severity;
  final int timestamp;
  
  SecurityEvent({
    required this.type,
    required this.message,
    required this.severity,
    required this.timestamp,
  });
}

class SecurityStatus {
  final bool isCompromised;
  final int authFailureCount;
  final int? lastAuthTime;
  final String appVersion;
  final String buildNumber;
  final Map<String, dynamic> deviceInfo;
  final List<SecurityEvent> recentSecurityEvents;
  final bool encryptionInitialized;
  final SecurityConfig config;
  
  SecurityStatus({
    required this.isCompromised,
    required this.authFailureCount,
    required this.lastAuthTime,
    required this.appVersion,
    required this.buildNumber,
    required this.deviceInfo,
    required this.recentSecurityEvents,
    required this.encryptionInitialized,
    required this.config,
  });
}

class AESEncryptedData {
  final Uint8List ciphertext;
  final Uint8List authTag;
  
  AESEncryptedData({
    required this.ciphertext,
    required this.authTag,
  });
}

enum SecurityEventType {
  authFailure,
  authSuccess,
  rootDetected,
  rootCheckFailed,
  developerModeDetected,
  adbDebuggingDetected,
  appSignatureMismatch,
  appIntegrityCheckFailed,
  systemIntegrityCompromised,
  screenshotProtectionEnabled,
  screenshotProtectionFailed,
  clipboardCleared,
  clipboardClearFailed,
  encryptionInitialized,
  encryptionFailed,
  autoWipeInitiated,
  autoWipeFailed,
  localDataWiped,
  localDataWipeFailed,
}

enum SecuritySeverity {
  low,
  medium,
  high,
  critical,
}

class SecurityException implements Exception {
  final String message;
  SecurityException(this.message);
  
  @override
  String toString() => 'SecurityException: $message';
}
