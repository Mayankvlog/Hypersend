import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import '../services/service_provider.dart';

/// WebSocket service for real-time chat messaging
/// Connects to production domain with JWT token authentication
class WebSocketService {
  WebSocketChannel? _channel;
  StreamSubscription? _subscription;
  bool _isConnected = false;
  String? _currentChatId;
  
  /// Get connection status
  bool get isConnected => _isConnected;
  
  /// Get current chat ID
  String? get currentChatId => _currentChatId;

  /// Connect to WebSocket for a specific chat
  /// 
  /// [chatId] - The chat ID to connect to
  /// Throws Exception if token is missing or connection fails
  Future<void> connect(String chatId) async {
    try {
      debugPrint('[WS_SERVICE] Starting WebSocket connection for chat: $chatId');
      
      // Disconnect from existing chat if any
      if (_isConnected) {
        await disconnect();
      }
      
      // Get JWT access token from auth service
      final token = await serviceProvider.authService.getAccessToken();
      
      if (token == null || token.isEmpty) {
        debugPrint('[WS_SERVICE] ❌ No access token available for WebSocket connection');
        throw Exception("Token missing - please login first");
      }
      
      // Encode token for URL (industry standard approach)
      final encodedToken = Uri.encodeComponent(token);
      
      // Use production domain as specified - NEVER localhost
      final url = "wss://zaply.in.net/api/v1/ws/chat/$chatId?token=$encodedToken";
      
      debugPrint('[WS_SERVICE] ✅ WS CONNECTING: $url');
      
      // Create WebSocket connection
      _channel = WebSocketChannel.connect(Uri.parse(url));
      _currentChatId = chatId;
      
      // Start listening to messages
      _startListening();
      
      debugPrint('[WS_SERVICE] ✅ WebSocket connection initiated for chat: $chatId');
      
    } catch (e) {
      debugPrint('[WS_SERVICE] ❌ WebSocket connection failed: $e');
      _isConnected = false;
      _currentChatId = null;
      rethrow;
    }
  }

  /// Start listening to WebSocket messages
  void _startListening() {
    if (_channel == null) return;
    
    _subscription = _channel!.stream.listen(
      (message) {
        debugPrint('[WS_SERVICE] 📩 WS MESSAGE: $message');
        _handleIncomingMessage(message);
      },
      onError: (error) {
        debugPrint('[WS_SERVICE] ❌ WS ERROR: $error');
        _isConnected = false;
        _handleConnectionError(error);
      },
      onDone: () {
        debugPrint('[WS_SERVICE] 🔌 WS CLOSED');
        _isConnected = false;
        _currentChatId = null;
        _handleConnectionClosed();
      },
    );
    
    _isConnected = true;
    debugPrint('[WS_SERVICE] ✅ WebSocket listening started');
  }

  /// Send a message through WebSocket
  /// 
  /// [message] - The message to send (will be JSON encoded)
  void send(String message) {
    if (_channel == null || !_isConnected) {
      debugPrint('[WS_SERVICE] ❌ Cannot send message - WebSocket not connected');
      return;
    }
    
    try {
      _channel!.sink.add(message);
      debugPrint('[WS_SERVICE] 📤 Message sent: $message');
    } catch (e) {
      debugPrint('[WS_SERVICE] ❌ Failed to send message: $e');
    }
  }

  /// Send a JSON message
  /// 
  /// [data] - The data to send as JSON
  void sendJson(Map<String, dynamic> data) {
    try {
      final jsonMessage = jsonEncode(data);
      send(jsonMessage);
    } catch (e) {
      debugPrint('[WS_SERVICE] ❌ Failed to encode JSON message: $e');
    }
  }

  /// Disconnect from WebSocket
  Future<void> disconnect() async {
    try {
      debugPrint('[WS_SERVICE] 🔌 Disconnecting WebSocket...');
      
      _subscription?.cancel();
      _subscription = null;
      
      if (_channel != null) {
        await _channel!.sink.close();
        _channel = null;
      }
      
      _isConnected = false;
      _currentChatId = null;
      
      debugPrint('[WS_SERVICE] ✅ WebSocket disconnected');
    } catch (e) {
      debugPrint('[WS_SERVICE] ❌ Error during disconnect: $e');
    }
  }

  /// Handle incoming WebSocket messages
  void _handleIncomingMessage(dynamic message) {
    try {
      // Parse JSON message if it's a string
      Map<String, dynamic>? messageData;
      if (message is String) {
        try {
          messageData = jsonDecode(message) as Map<String, dynamic>;
        } catch (e) {
          debugPrint('[WS_SERVICE] ⚠️ Message is not valid JSON: $message');
          return;
        }
      } else if (message is Map<String, dynamic>) {
        messageData = message;
      } else {
        debugPrint('[WS_SERVICE] ⚠️ Unsupported message format: $message');
        return;
      }
      
      // Handle different message types
      final messageType = messageData['type'] as String?;
      final content = messageData['content'];
      
      debugPrint('[WS_SERVICE] 📩 Received message type: $messageType');
      
      switch (messageType) {
        case 'message':
          _handleChatMessage(content);
          break;
        case 'typing':
          _handleTypingIndicator(content);
          break;
        case 'reaction':
          _handleMessageReaction(content);
          break;
        case 'delete':
          _handleMessageDeletion(content);
          break;
        case 'presence':
          _handlePresenceUpdate(content);
          break;
        default:
          debugPrint('[WS_SERVICE] ⚠️ Unknown message type: $messageType');
      }
    } catch (e) {
      debugPrint('[WS_SERVICE] ❌ Error handling incoming message: $e');
    }
  }

  /// Handle chat messages
  void _handleChatMessage(dynamic content) {
    debugPrint('[WS_SERVICE] 💬 Chat message received: $content');
    // TODO: Emit event or callback for chat messages
    // This can be integrated with your existing chat state management
  }

  /// Handle typing indicators
  void _handleTypingIndicator(dynamic content) {
    debugPrint('[WS_SERVICE] ⌨️ Typing indicator: $content');
    // TODO: Handle typing indicators in UI
  }

  /// Handle message reactions
  void _handleMessageReaction(dynamic content) {
    debugPrint('[WS_SERVICE] 😊 Message reaction: $content');
    // TODO: Handle message reactions
  }

  /// Handle message deletion
  void _handleMessageDeletion(dynamic content) {
    debugPrint('[WS_SERVICE] 🗑️ Message deletion: $content');
    // TODO: Handle message deletion
  }

  /// Handle presence updates
  void _handlePresenceUpdate(dynamic content) {
    debugPrint('[WS_SERVICE] 👤 Presence update: $content');
    // TODO: Handle user presence (online/offline)
  }

  /// Handle connection errors
  void _handleConnectionError(dynamic error) {
    debugPrint('[WS_SERVICE] ❌ Connection error: $error');
    // TODO: Implement reconnection logic or notify user
  }

  /// Handle connection closed
  void _handleConnectionClosed() {
    debugPrint('[WS_SERVICE] 🔌 Connection closed');
    // TODO: Handle cleanup and potential reconnection
  }

  /// Dispose the WebSocket service
  Future<void> dispose() async {
    await disconnect();
    debugPrint('[WS_SERVICE] 🗑️ WebSocket service disposed');
  }
}
