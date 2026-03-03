"""
WhatsApp-Grade WebSocket Delivery Handler
========================================

Handles real-time message delivery, connection management,
and delivery receipts via WebSocket connections.

Security Properties:
- Per-device WebSocket connections
- Real-time delivery tracking
- Connection recovery and resumption
- Heartbeat/ping-pong for connection health
- Graceful degradation on connection loss
"""

import asyncio
import json
import time
import logging
import secrets
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import websockets
from websockets.server import WebSocketServerProtocol

# WhatsApp-Grade Cryptographic Imports
try:
    import redis.asyncio as redis
except ImportError:
    print("[WARNING] Redis not available - using fallback cache")
    redis = None

# TYPE_CHECKING for type hints when redis module is not available
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import redis.asyncio as redis_type
else:
    redis_type = Any

# Import our cryptographic modules
from crypto.signal_protocol import SignalProtocol
from crypto.multi_device import MultiDeviceManager
from crypto.delivery_semantics import DeliveryManager, MessageStatus, DeviceState
from crypto.media_encryption import MediaEncryptionService

logger = logging.getLogger(__name__)

@dataclass
class WebSocketConnection:
    """WebSocket connection metadata"""
    websocket: WebSocketServerProtocol
    device_id: str
    user_id: str
    connected_at: float
    last_ping: float
    last_pong: float
    is_authenticated: bool = False
    message_queue: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.message_queue is None:
            self.message_queue = []
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'device_id': self.device_id,
            'user_id': self.user_id,
            'connected_at': self.connected_at,
            'last_ping': self.last_ping,
            'last_pong': self.last_pong,
            'is_authenticated': self.is_authenticated,
            'queue_size': len(self.message_queue)
        }

class WebSocketDeliveryHandler:
    """WhatsApp-grade WebSocket delivery handler"""
    
    def __init__(self, redis_client: Optional[Any]):
        self.redis = redis_client
        self.delivery_manager = DeliveryManager(redis_client)
        self.device_manager = MultiDeviceManager(redis_client)
        self.signal_protocol = SignalProtocol()
        self.media_service = MediaEncryptionService(redis_client)
        
        # Active connections by device_id (memory-safe structure)
        # CRITICAL: One connection per device_id - old connections auto-replaced
        self.connections: Dict[str, WebSocketConnection] = {}
        self.connection_lock = asyncio.Lock()  # Prevent race conditions
        
        # Redis Pub/Sub subscriptions (one per connection handler)
        self.pubsub_subscriptions: Dict[str, Any] = {}
        
        # Configuration
        self.heartbeat_interval = 30  # seconds
        self.pong_timeout = 10  # seconds
        self.max_queue_size = 1000
        self.connection_timeout = 7200  # 2 hours
        self.reconnect_grace_period = 5  # 5 seconds for reconnect dedupe
        
    async def handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle new WebSocket connection with deduplication"""
        device_id = None
        user_id = None
        heartbeat_task = None
        pubsub_task = None
        
        try:
            logger.info(f"New WebSocket connection from {websocket.remote_address}")
            
            # Extract device and user IDs from headers
            device_id = websocket.request_headers.get('X-Device-ID')
            user_id = websocket.request_headers.get('X-User-ID')
            
            if not device_id or not user_id:
                await websocket.close(4001, "Missing device or user ID")
                return
            
            # Authenticate device
            if not await self._authenticate_device(websocket, device_id, user_id):
                await websocket.close(4003, "Authentication failed")
                return
            
            # Create connection object
            new_connection = WebSocketConnection(
                websocket=websocket,
                device_id=device_id,
                user_id=user_id,
                connected_at=time.time(),
                last_ping=time.time(),
                last_pong=time.time(),
                is_authenticated=True
            )
            
            # CRITICAL: Replace old connection if exists (deduplication)
            # This prevents duplicate sockets for same device_id
            async with self.connection_lock:
                old_connection = self.connections.get(device_id)
                if old_connection and old_connection.websocket:
                    try:
                        await old_connection.websocket.close(4001, "Duplicate connection")
                        logger.info(f"Closed duplicate connection for device {device_id}")
                    except Exception as e:
                        logger.debug(f"Failed to close old connection: {e}")
                
                # Store new connection (thread-safe)
                self.connections[device_id] = new_connection
            
            # Update device connection status
            await self.delivery_manager.update_device_connection(
                device_id=device_id,
                user_id=user_id,
                state="online",  # Use string instead of enum
                websocket_id=id(websocket),
                ip_address=websocket.remote_address[0],
                user_agent=websocket.request_headers.get('User-Agent', '')
            )
            
            logger.info(f"Device {device_id} connected (total: {len(self.connections)})")
            
            # Start background tasks
            heartbeat_task = asyncio.create_task(
                self._heartbeat_loop(device_id, new_connection)
            )
            
            # Subscribe to Redis Pub/Sub for broadcasts
            pubsub_task = asyncio.create_task(
                self._redis_pubsub_listener(device_id, user_id, new_connection)
            )
            
            # Process offline messages
            await self._process_offline_messages(new_connection)
            
            # Handle incoming WebSocket messages
            await self._handle_messages(new_connection)
            
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"WebSocket connection closed for device {device_id}")
        except Exception as e:
            logger.error(f"Error handling WebSocket connection: {e}")
        finally:
            # Cleanup
            if device_id:
                await self._cleanup_connection(device_id)
            
            # Cancel all background tasks
            if heartbeat_task:
                heartbeat_task.cancel()
            if pubsub_task:
                pubsub_task.cancel()
            
            try:
                await asyncio.gather(heartbeat_task, pubsub_task, return_exceptions=True)
            except Exception:
                pass
    
    async def _authenticate_device(
        self,
        websocket: WebSocketServerProtocol,
        device_id: str,
        user_id: str
    ) -> bool:
        """Authenticate WebSocket connection"""
        try:
            # Verify device belongs to user
            user_devices = await self.device_manager.get_user_devices(user_id)
            
            if not any(device.device_id == device_id for device in user_devices):
                logger.warning(f"Device {device_id} not found for user {user_id}")
                return False
            
            # Check device session
            device_session = await self.device_manager.get_device_session(user_id, device_id)
            
            if not device_session:
                logger.warning(f"No session found for device {device_id}")
                return False
            
            # Send authentication challenge
            challenge = secrets.token_urlsafe(32)
            await websocket.send(json.dumps({
                'type': 'auth_challenge',
                'challenge': challenge,
                'timestamp': time.time()
            }))
            
            # Wait for response
            response = await asyncio.wait_for(
                websocket.recv(),
                timeout=10.0
            )
            
            auth_data = json.loads(response)
            
            # Verify challenge response
            expected_response = self._calculate_challenge_response(
                challenge,
                device_session.session_key
            )
            
            if auth_data.get('response') != expected_response:
                logger.warning(f"Invalid auth response for device {device_id}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Authentication error for device {device_id}: {e}")
            return False
    
    async def _handle_messages(self, connection: WebSocketConnection):
        """Handle incoming WebSocket messages"""
        try:
            async for message in connection.websocket:
                try:
                    data = json.loads(message)
                    await self._process_message(connection, data)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON from device {connection.device_id}")
                    await connection.websocket.close(4002, "Invalid JSON")
                    break
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            pass
    
    async def _process_message(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Process incoming WebSocket message"""
        message_type = data.get('type')
        
        if message_type == 'pong':
            connection.last_pong = time.time()
            return
        
        elif message_type == 'delivery_receipt':
            await self._handle_delivery_receipt(connection, data)
        
        elif message_type == 'read_receipt':
            await self._handle_read_receipt(connection, data)
        
        elif message_type == 'typing':
            await self._handle_typing_indicator(connection, data)
        
        elif message_type == 'presence':
            await self._handle_presence_update(connection, data)
        
        else:
            logger.warning(f"Unknown message type: {message_type}")
    
    async def _handle_delivery_receipt(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Handle delivery receipt"""
        message_id = data.get('message_id')
        timestamp = data.get('timestamp', time.time())
        
        if not message_id:
            return
        
        # Update delivery status
        success = await self.delivery_manager.mark_message_delivered(
            message_id,
            connection.device_id
        )
        
        if success:
            # Broadcast to other devices
            await self._broadcast_to_user_devices(
                connection.user_id,
                connection.device_id,
                {
                    'type': 'delivery_receipt',
                    'message_id': message_id,
                    'device_id': connection.device_id,
                    'timestamp': timestamp
                }
            )
            
            logger.info(f"Delivery receipt for message {message_id} from device {connection.device_id}")
    
    async def _handle_read_receipt(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Handle read receipt"""
        message_id = data.get('message_id')
        timestamp = data.get('timestamp', time.time())
        
        if not message_id:
            return
        
        # Update read status
        success = await self.delivery_manager.mark_message_read(
            message_id,
            connection.device_id
        )
        
        if success:
            # Broadcast to other devices
            await self._broadcast_to_user_devices(
                connection.user_id,
                connection.device_id,
                {
                    'type': 'read_receipt',
                    'message_id': message_id,
                    'device_id': connection.device_id,
                    'timestamp': timestamp
                }
            )
            
            logger.info(f"Read receipt for message {message_id} from device {connection.device_id}")
    
    async def _handle_typing_indicator(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Handle typing indicator"""
        chat_id = data.get('chat_id')
        is_typing = data.get('is_typing', False)
        
        if not chat_id:
            return
        
        # Broadcast to chat participants
        await self._broadcast_to_chat_participants(
            chat_id,
            connection.user_id,
            {
                'type': 'typing',
                'user_id': connection.user_id,
                'device_id': connection.device_id,
                'chat_id': chat_id,
                'is_typing': is_typing,
                'timestamp': time.time()
            }
        )
    
    async def _handle_presence_update(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Handle presence update"""
        presence = data.get('presence', 'online')
        
        # Update device presence
        state = DeviceState.ONLINE if presence == 'online' else DeviceState.OFFLINE
        await self.delivery_manager.update_device_connection(
            device_id=connection.device_id,
            user_id=connection.user_id,
            state=state
        )
    
    async def _process_offline_messages(self, connection: WebSocketConnection):
        """Process messages that arrived while device was offline"""
        try:
            # Get offline messages queue
            offline_messages = await self.redis.lrange(
                f"device_offline_queue:{connection.device_id}",
                0,
                -1
            )
            
            if offline_messages:
                logger.info(f"Processing {len(offline_messages)} offline messages for device {connection.device_id}")
                
                # Send messages to device
                for message_data in offline_messages:
                    try:
                        await connection.websocket.send(message_data)
                        await asyncio.sleep(0.01)  # Small delay to prevent overwhelming
                    except Exception as e:
                        logger.error(f"Failed to send offline message: {e}")
                
                # Clear offline queue
                await self.redis.delete(f"device_offline_queue:{connection.device_id}")
                
        except Exception as e:
            logger.error(f"Error processing offline messages: {e}")
    
    async def _heartbeat_loop(self, device_id: str, connection: WebSocketConnection):
        """Send periodic heartbeat pings (keep connection persistent)"""
        while True:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                
                # Verify connection still exists and is active
                if device_id not in self.connections:
                    logger.debug(f"Device {device_id} not in active connections")
                    break
                
                # Check if connection is still alive
                if time.time() - connection.last_pong > self.pong_timeout:
                    logger.warning(f"Pong timeout for device {device_id}")
                    await connection.websocket.close(4000, "Pong timeout")
                    break
                
                # Send ping (UTC ISO format)
                ping_data = {
                    'type': 'ping',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'sequence': int(time.time() * 1000)  # Millisecond sequence
                }
                
                await connection.websocket.send(json.dumps(ping_data))
                connection.last_ping = time.time()
                
            except websockets.exceptions.ConnectionClosed:
                logger.debug(f"Heartbeat: Connection closed for device {device_id}")
                break
            except asyncio.CancelledError:
                logger.debug(f"Heartbeat: Cancelled for device {device_id}")
                break
            except Exception as e:
                logger.error(f"Heartbeat error for device {device_id}: {e}")
                break
    
    async def _broadcast_to_user_devices(
        self,
        user_id: str,
        exclude_device_id: str,
        message: Dict[str, Any]
    ):
        """Broadcast message to all user devices except one"""
        user_devices = await self.device_manager.get_active_devices(user_id)
        
        for device in user_devices:
            if device.device_id == exclude_device_id:
                continue
            
            connection = self.connections.get(device.device_id)
            if connection:
                try:
                    await connection.websocket.send(json.dumps(message))
                except Exception as e:
                    logger.error(f"Failed to broadcast to device {device.device_id}: {e}")
    
    async def _broadcast_to_chat_participants(
        self,
        chat_id: str,
        exclude_user_id: str,
        message: Dict[str, Any]
    ):
        """Broadcast message to all chat participants except one"""
        # Get chat participants
        chat_data = await self.redis.hgetall(f"chat:{chat_id}")
        if not chat_data:
            return
        
        members = json.loads(chat_data.get('members', '[]'))
        
        for user_id in members:
            if user_id == exclude_user_id:
                continue
            
            await self._broadcast_to_user_devices(user_id, '', message)
    
    async def _cleanup_connection(self, device_id: str):
        """Clean up closed connection (thread-safe)"""
        async with self.connection_lock:
            if device_id in self.connections:
                connection = self.connections[device_id]
                
                # Update device status to offline
                try:
                    await self.delivery_manager.update_device_connection(
                        device_id=device_id,
                        user_id=connection.user_id,
                        state="offline"
                    )
                except Exception as e:
                    logger.warning(f"Failed to update device status to offline: {e}")
                
                # Close socket if still open
                try:
                    if connection.websocket and not connection.websocket.closed:
                        await connection.websocket.close()
                except Exception as e:
                    logger.debug(f"Socket already closed: {e}")
                
                # Remove from active connections
                del self.connections[device_id]
                
                logger.info(f"Cleaned up connection for device {device_id} (total: {len(self.connections)})")
            
            # Clean up Redis Pub/Sub subscription
            if device_id in self.pubsub_subscriptions:
                try:
                    await self.pubsub_subscriptions[device_id].close()
                except Exception as e:
                    logger.debug(f"Failed to close pubsub: {e}")
                del self.pubsub_subscriptions[device_id]
    
    def _calculate_challenge_response(self, challenge: str, session_key: str) -> str:
        """Calculate authentication challenge response"""
        # Use HMAC with session key
        import hmac
        import hashlib
        
        hmac_obj = hmac.new(
            session_key.encode(),
            challenge.encode(),
            hashlib.sha256
        )
        
        return hmac_obj.hexdigest()
    
    async def send_message_to_device(self, device_id: str, message: Dict[str, Any]) -> bool:
        """Send message to specific device (online or queue for offline)"""
        async with self.connection_lock:
            connection = self.connections.get(device_id)
        
        if connection:
            try:
                await connection.websocket.send(json.dumps(message))
                return True
            except Exception as e:
                logger.warning(f"Failed to send message to device {device_id}: {e}")
                # Fall through to queue for offline
        
        # Device is offline or send failed, queue message in Redis
        try:
            if self.redis:
                await self.redis.lpush(
                    f"device_offline_queue:{device_id}",
                    json.dumps(message)
                )
                # Set TTL on queue (1 hour)
                await self.redis.expire(f"device_offline_queue:{device_id}", 3600)
                logger.debug(f"Queued message for offline device {device_id}")
        except Exception as e:
            logger.error(f"Failed to queue message for device {device_id}: {e}")
        
        return False
    
    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get WebSocket connection statistics"""
        total_connections = len(self.connections)
        authenticated_connections = sum(
            1 for conn in self.connections.values() if conn.is_authenticated
        )
        
        # Calculate connection duration stats
        now = time.time()
        durations = [
            now - conn.connected_at for conn in self.connections.values()
        ]
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        return {
            'total_connections': total_connections,
            'authenticated_connections': authenticated_connections,
            'average_connection_duration': avg_duration,
            'connections': [
                conn.to_dict() for conn in self.connections.values()
            ]
        }

# Add Redis Pub/Sub listener for Redis broadcast (after _cleanup_connection)
    async def _redis_pubsub_listener(self, device_id: str, user_id: str, connection: WebSocketConnection):
        """Listen to Redis Pub/Sub for broadcast messages"""
        if not self.redis:
            return
        
        try:
            pubsub = self.redis.pubsub()
            self.pubsub_subscriptions[device_id] = pubsub
            
            # Subscribe to broadcast channels
            channels = [
                f"broadcast:user:{user_id}",  # Messages to user
                f"broadcast:device:{device_id}",  # Messages to device
            ]
            
            await pubsub.subscribe(*channels)
            logger.info(f"Device {device_id} subscribed to {len(channels)} channels")
            
            # Listen for messages (Redis Pub/Sub)
            async for message in pubsub.listen():
                if message['type'] == 'message':
                    try:
                        # Verify connection still exists
                        if device_id not in self.connections:
                            break
                        
                        # Send message via WebSocket
                        await connection.websocket.send(message['data'])
                        logger.debug(f"Broadcast to device {device_id}")
                        
                    except Exception as e:
                        logger.warning(f"Failed to send broadcast to device {device_id}: {e}")
                        break
                
                elif message['type'] == 'subscribe':
                    logger.debug(f"Subscribed to {message['channel']}")
        
        except Exception as e:
            logger.error(f"Pub/Sub error for device {device_id}: {e}")
        finally:
            try:
                if device_id in self.pubsub_subscriptions:
                    await pubsub.close()
                    del self.pubsub_subscriptions[device_id]
            except Exception:
                pass

# WebSocket server factory
async def create_websocket_server(redis_client: Optional[Any], host: str = "0.0.0.0", port: int = 8001):
    """Create WebSocket server with delivery handler"""
    handler = WebSocketDeliveryHandler(redis_client)
    
    logger.info(f"Starting WebSocket server on {host}:{port}")
    
    return await websockets.serve(
        handler.handle_connection,
        host,
        port,
        ping_interval=None,  # We handle our own heartbeat
        ping_timeout=None,
        close_timeout=10,
        max_size=10 * 1024 * 1024,  # 10MB max message size
        compression=None,  # Disable compression for security
    )
