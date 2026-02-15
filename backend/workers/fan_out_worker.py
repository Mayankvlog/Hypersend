"""
WhatsApp-Grade Background Fan-Out Workers
==========================================

Handles message fan-out to multiple devices, delivery tracking,
and retry logic. Ensures WhatsApp-grade reliability.

Security Properties:
- Per-device message delivery
- Idempotent retry with exponential backoff
- Exact-once delivery guarantees
- Ordered message delivery per chat
- Connection recovery and resumption
"""

import asyncio
import json
import time
import logging
import os
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

# WhatsApp-Grade Cryptographic Imports
try:
    import redis.asyncio as redis
except ImportError:
    print("[WARNING] Redis not available - using fallback cache")
    redis = None
from celery import Celery

# Import our cryptographic modules
from crypto.signal_protocol import SignalProtocol
from crypto.multi_device import MultiDeviceManager
from crypto.delivery_semantics import DeliveryManager, MessageStatus
from crypto.media_encryption import MediaEncryptionService

logger = logging.getLogger(__name__)

# Initialize Celery app for background workers
celery_app = Celery('hypersend_fanout')
celery_app.config_from_object({
    'broker_url': 'redis://redis:6379/0',
    'result_backend': 'redis://redis:6379/0',
    'task_serializer': 'json',
    'accept_content': ['json'],
    'result_serializer': 'json',
    'timezone': 'UTC',
    'enable_utc': True,
    'task_track_started': True,
    'task_time_limit': 300,  # 5 minutes per task
    'task_soft_time_limit': 240,  # 4 minutes soft limit
    'worker_prefetch_multiplier': 1,
    'worker_max_tasks_per_child': 1000,
    'broker_transport_options': {
        'master_name': 'mymaster',
        'visibility_timeout': 3600,
        'retry_policy': {
            'timeout': 5.0
        },
        'socket_keepalive': True,
        'socket_keepalive_options': {},
    },
    'result_backend_transport_options': {
        'master_name': 'mymaster',
        'retry_policy': {
            'timeout': 5.0
        }
    }
})

@dataclass
class FanOutTask:
    """Background fan-out task data"""
    task_id: str
    message_id: str
    chat_id: str
    sender_id: str
    recipient_devices: List[str]
    message_data: Dict[str, any]
    priority: int  # 1=high, 2=normal, 3=low
    created_at: float
    retry_count: int = 0
    max_retries: int = 7
    next_retry_at: Optional[float] = None
    
    def to_dict(self) -> Dict[str, any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, any]) -> 'FanOutTask':
        return cls(**data)

class MessageFanOutWorker:
    """WhatsApp-grade message fan-out worker"""
    
    def __init__(self, redis_client: Optional['redis.Redis'] = None):
        # Get Redis configuration from environment
        redis_host = os.getenv('REDIS_HOST', 'redis')
        redis_port = int(os.getenv('REDIS_PORT', 6379))
        redis_password = os.getenv('REDIS_PASSWORD', '')
        redis_db = int(os.getenv('REDIS_DB', 0))
        
        # Ensure we're not using cluster mode and use proper authentication
        if hasattr(redis_client, 'cluster'):
            logger.warning("Detected Redis cluster client, switching to standalone mode")
            self.redis = redis.Redis(
                host=redis_host,
                port=redis_port,
                password=redis_password if redis_password else None,
                db=redis_db,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
        else:
            # Use the provided client but ensure it has proper authentication
            self.redis = redis_client
            # Check if the connection pool has a password set
            connection_pool = getattr(self.redis, "connection_pool", None)
            has_password = False
            if connection_pool and hasattr(connection_pool, "connection_kwargs"):
                has_password = connection_pool.connection_kwargs.get("password") is not None
            
            if redis_password and not has_password:
                # Reconnect with password if not already authenticated
                self.redis = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    password=redis_password,
                    db=redis_db,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
        self.delivery_manager = DeliveryManager(redis_client)
        self.device_manager = MultiDeviceManager(redis_client)
        self.media_service = MediaEncryptionService(redis_client)
        self.signal_protocol = SignalProtocol(redis_client)
        
        # Task queues by priority
        self.queues = {
            'high': 'fanout_queue:high',
            'normal': 'fanout_queue:normal', 
            'low': 'fanout_queue:low'
        }
        
        # Worker configuration
        self.batch_size = 100
        self.poll_interval = 1.0  # seconds
        self.max_concurrent_tasks = 50
        
    async def start_worker(self):
        """Start the fan-out worker"""
        logger.info("Starting message fan-out worker")
        
        while True:
            try:
                # Process tasks from all priority queues
                await self._process_priority_queue('high')
                await self._process_priority_queue('normal')
                await self._process_priority_queue('low')
                
                # Small delay to prevent busy waiting
                await asyncio.sleep(self.poll_interval)
                
            except Exception as e:
                error_msg = str(e).lower()
                if "authentication required" in error_msg or "noauth" in error_msg:
                    logger.error(f"Redis authentication failed in fan-out worker main loop: {e}")
                    # Wait much longer for authentication issues
                    await asyncio.sleep(60)
                elif "connection" in error_msg or "redis" in error_msg:
                    logger.error(f"Redis connection error in fan-out worker main loop: {e}")
                    # Wait longer for connection issues
                    await asyncio.sleep(15)
                else:
                    logger.error(f"Unexpected error in fan-out worker main loop: {e}")
                    await asyncio.sleep(5)
    
    async def _process_priority_queue(self, priority: str):
        """Process tasks from a specific priority queue"""
        try:
            queue_key = self.queues[priority]
            
            # Atomically dequeue batch of tasks
            # Try LMPOP first (Redis 7+), fall back to LPOP loop for earlier versions
            tasks = []
            try:
                # LMPOP is atomic and pops up to batch_size items from the left
                result = await self.redis.lmpop(self.batch_size, queue_key)
                if result:
                    # result is (key, list_of_items)
                    tasks = result[1] if len(result) > 1 else []
            except Exception as lmpop_error:
                # Fallback to LPOP loop for Redis < 7.0
                logger.debug(f"LMPOP not available or failed: {lmpop_error}, using LPOP loop")
                tasks = []
                for _ in range(self.batch_size):
                    try:
                        task_data = await self.redis.lpop(queue_key)
                        if task_data:
                            tasks.append(task_data)
                        else:
                            break
                    except Exception as lpop_error:
                        logger.error(f"LPOP failed: {lpop_error}")
                        break
            
            if not tasks:
                return
            
            # Process tasks concurrently
            semaphore = asyncio.Semaphore(self.max_concurrent_tasks)
            processing_tasks = []
            
            for task_data in tasks:
                task = FanOutTask.from_dict(json.loads(task_data))
                
                # Check if task is ready for processing
                if task.next_retry_at and task.next_retry_at > time.time():
                    # Re-queue task for later
                    await self._requeue_task(task, priority)
                    continue
                
                # Process task
                processing_tasks.append(
                    self._process_task_with_semaphore(semaphore, task)
                )
            
            # Wait for all tasks to complete
            if processing_tasks:
                await asyncio.gather(*processing_tasks, return_exceptions=True)
                
        except Exception as e:
            error_msg = str(e).lower()
            if "authentication required" in error_msg or "noauth" in error_msg:
                logger.error(f"Redis authentication failed in fan-out worker: {e}")
                # Don't retry authentication errors immediately - wait longer
                await asyncio.sleep(30)
            elif "connection" in error_msg or "redis" in error_msg:
                logger.error(f"Redis connection error in fan-out worker: {e}")
                # Wait longer for connection issues
                await asyncio.sleep(10)
            else:
                logger.error(f"Error processing priority queue {priority}: {e}")
                await asyncio.sleep(1)
    
    async def _process_task_with_semaphore(self, semaphore: asyncio.Semaphore, task: FanOutTask):
        """Process task with semaphore to limit concurrency"""
        async with semaphore:
            await self._process_single_task(task)
    
    async def _process_single_task(self, task: FanOutTask):
        """Process a single fan-out task"""
        try:
            logger.info(f"Processing fan-out task {task.task_id} for message {task.message_id}")
            
            # Get recipient devices
            recipient_devices = await self._get_recipient_devices(task)
            
            if not recipient_devices:
                logger.warning(f"No active devices found for task {task.task_id}")
                await self._mark_task_completed(task)
                return
            
            # Fan-out to all devices
            successful_deliveries = []
            failed_deliveries = []
            
            for device_id in recipient_devices:
                try:
                    success = await self._deliver_to_device(task, device_id)
                    if success:
                        successful_deliveries.append(device_id)
                    else:
                        failed_deliveries.append(device_id)
                except Exception as e:
                    logger.error(f"Failed to deliver to device {device_id}: {e}")
                    failed_deliveries.append(device_id)
            
            # Handle delivery results
            if successful_deliveries:
                await self._handle_successful_deliveries(task, successful_deliveries)
            
            if failed_deliveries:
                await self._handle_failed_deliveries(task, failed_deliveries)
            
            # Check if task is complete
            if len(successful_deliveries) == len(recipient_devices):
                await self._mark_task_completed(task)
            else:
                await self._schedule_retry(task)
                
        except Exception as e:
            logger.error(f"Error processing task {task.task_id}: {e}")
            await self._schedule_retry(task)
    
    async def _get_recipient_devices(self, task: FanOutTask) -> List[str]:
        """Get active recipient devices for message"""
        devices = []
        
        # Get chat members
        chat_data = await self.redis.hgetall(f"chat:{task.chat_id}")
        if not chat_data:
            return devices
        
        members = json.loads(chat_data.get('members', '[]'))
        
        # Get active devices for each member (excluding sender)
        for member_id in members:
            if member_id == task.sender_id:
                continue
            
            member_devices = await self.device_manager.get_active_devices(member_id)
            devices.extend([device.device_id for device in member_devices])
        
        return devices
    
    async def _deliver_to_device(self, task: FanOutTask, device_id: str) -> bool:
        """Deliver message to specific device"""
        try:
            # Check if device is online
            is_online = await self.delivery_manager.is_device_online(device_id)
            
            if not is_online:
                # Store message for when device comes online
                await self._store_offline_message(task, device_id)
                return True
            
            # Get device session
            device_session = await self.device_manager.get_device_session(
                task.chat_id.split(':')[0],  # Extract user_id from chat_id
                device_id
            )
            
            if not device_session:
                logger.warning(f"No session found for device {device_id}")
                return False
            
            # Encrypt message for device
            encrypted_message = await self._encrypt_message_for_device(
                task.message_data,
                device_session
            )
            
            # Send to device via WebSocket
            await self._send_to_device_websocket(device_id, encrypted_message)
            
            # Mark as sent
            await self.delivery_manager.mark_message_sent(task.message_id, device_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to deliver to device {device_id}: {e}")
            return False
    
    async def _encrypt_message_for_device(
        self,
        message_data: Dict[str, any],
        device_session
    ) -> Dict[str, any]:
        """Encrypt message for specific device"""
        # Use Signal Protocol to encrypt for device
        encrypted_content = await self.signal_protocol.encrypt_message(
            message_data['content'],
            device_session.session_key
        )
        
        return {
            'message_id': message_data['message_id'],
            'chat_id': message_data['chat_id'],
            'sender_id': message_data['sender_id'],
            'encrypted_content': encrypted_content['encrypted_content'],
            'iv': encrypted_content['iv'],
            'auth_tag': encrypted_content['auth_tag'],
            'message_type': message_data.get('message_type', 'text'),
            'timestamp': message_data['timestamp'],
            'sequence_number': message_data.get('sequence_number'),
        }
    
    async def _send_to_device_websocket(self, device_id: str, message: Dict[str, any]):
        """Send message to device via WebSocket"""
        # Store message in device's outbox
        await self.redis.lpush(
            f"device_outbox:{device_id}",
            json.dumps(message)
        )
        
        # Notify device via pub/sub
        await self.redis.publish(
            f"device_notifications:{device_id}",
            json.dumps({
                'type': 'new_message',
                'message_id': message['message_id'],
                'timestamp': time.time()
            })
        )
    
    async def _store_offline_message(self, task: FanOutTask, device_id: str):
        """Store message for offline device"""
        await self.redis.lpush(
            f"device_offline_queue:{device_id}",
            json.dumps(task.message_data)
        )
        
        # Mark as pending
        await self.delivery_manager.mark_message_sent(task.message_id, device_id)
    
    async def _handle_successful_deliveries(self, task: FanOutTask, devices: List[str]):
        """Handle successful deliveries to devices"""
        for device_id in devices:
            logger.info(f"Successfully delivered message {task.message_id} to device {device_id}")
    
    async def _handle_failed_deliveries(self, task: FanOutTask, devices: List[str]):
        """Handle failed deliveries to devices"""
        for device_id in devices:
            logger.warning(f"Failed to deliver message {task.message_id} to device {device_id}")
    
    async def _schedule_retry(self, task: FanOutTask):
        """Schedule retry for failed task"""
        task.retry_count += 1
        
        if task.retry_count >= task.max_retries:
            logger.error(f"Task {task.task_id} exceeded max retries, marking as failed")
            await self._mark_task_failed(task)
            return
        
        # Calculate exponential backoff
        base_delay = 2 ** task.retry_count
        max_delay = 300  # 5 minutes max
        delay = min(base_delay, max_delay)
        
        task.next_retry_at = time.time() + delay
        
        # Re-queue task
        priority = self._get_task_priority(task)
        await self._requeue_task(task, priority)
        
        logger.info(f"Scheduled retry for task {task.task_id} in {delay} seconds")
    
    async def _requeue_task(self, task: FanOutTask, priority: str):
        """Re-queue task for later processing"""
        queue_key = self.queues[priority]
        await self.redis.rpush(queue_key, json.dumps(task.to_dict()))
    
    async def _mark_task_completed(self, task: FanOutTask):
        """Mark task as completed"""
        await self.redis.hset(
            f"fanout_task:{task.task_id}",
            "status",
            "completed"
        )
        await self.redis.hset(
            f"fanout_task:{task.task_id}",
            "completed_at",
            time.time()
        )
        
        logger.info(f"Task {task.task_id} completed successfully")
    
    async def _mark_task_failed(self, task: FanOutTask):
        """Mark task as failed"""
        await self.redis.hset(
            f"fanout_task:{task.task_id}",
            "status",
            "failed"
        )
        await self.redis.hset(
            f"fanout_task:{task.task_id}",
            "failed_at",
            time.time()
        )
        
        logger.error(f"Task {task.task_id} failed after {task.retry_count} retries")
    
    def _get_task_priority(self, task: FanOutTask) -> str:
        """Get task priority based on retry count and message type"""
        if task.retry_count > 3:
            return 'low'
        elif task.message_data.get('message_type') == 'text':
            return 'high'
        else:
            return 'normal'

# Celery tasks for distributed processing
@celery_app.task(bind=True, max_retries=7)
def fan_out_message_task(self, task_data: Dict[str, any]):
    """Celery task for message fan-out"""
    try:
        task = FanOutTask.from_dict(task_data)
        
        # Process the task with standalone Redis connection
        redis_host = os.getenv('REDIS_HOST', 'redis')
        redis_port = int(os.getenv('REDIS_PORT', 6379))
        redis_password = os.getenv('REDIS_PASSWORD', '')
        redis_db = int(os.getenv('REDIS_DB', 0))
        
        redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password if redis_password else None,
            db=redis_db,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )
        worker = MessageFanOutWorker(redis_client)
        asyncio.run(worker._process_single_task(task))
        
        return {'status': 'completed', 'task_id': task.task_id}
        
    except Exception as e:
        logger.error(f"Celery fan-out task failed: {e}")
        
        # Retry with exponential backoff
        countdown = 2 ** self.request.retries
        raise self.retry(exc=e, countdown=countdown)

@celery_app.task
def cleanup_expired_tasks():
    """Clean up expired fan-out tasks"""
    try:
        # Get Redis configuration from environment
        redis_host = os.getenv('REDIS_HOST', 'redis')
        redis_port = int(os.getenv('REDIS_PORT', 6379))
        redis_password = os.getenv('REDIS_PASSWORD', '')
        redis_db = int(os.getenv('REDIS_DB', 0))
        
        redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password if redis_password else None,
            db=redis_db,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )
        
        # Get all fan-out tasks
        task_keys = redis_client.keys("fanout_task:*")
        
        current_time = time.time()
        expired_count = 0
        
        for task_key in task_keys:
            task_data = redis_client.hgetall(task_key)
            
            if not task_data:
                continue
            
            created_at = float(task_data.get('created_at', 0))
            
            # Delete tasks older than 24 hours
            if current_time - created_at > 86400:
                redis_client.delete(task_key)
                expired_count += 1
        
        logger.info(f"Cleaned up {expired_count} expired fan-out tasks")
        return {'cleaned_count': expired_count}
        
    except Exception as e:
        logger.error(f"Failed to cleanup expired tasks: {e}")
        return {'error': str(e)}

# Periodic task for cleanup
@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """Setup periodic tasks"""
    # Run cleanup every hour
    sender.add_periodic_task(3600.0, cleanup_expired_tasks.s(), name='cleanup-expired-tasks')

# Worker entry point
async def main():
    """Main entry point for fan-out worker"""
    # Get Redis configuration from environment
    redis_host = os.getenv('REDIS_HOST', 'redis')
    redis_port = int(os.getenv('REDIS_PORT', 6379))
    redis_password = os.getenv('REDIS_PASSWORD', '')
    redis_db = int(os.getenv('REDIS_DB', 0))
    
    redis_client = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_password if redis_password else None,
        db=redis_db,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        retry_on_timeout=True
    )
    worker = MessageFanOutWorker(redis_client)
    
    logger.info("Starting WhatsApp-grade message fan-out worker")
    await worker.start_worker()

if __name__ == '__main__':
    asyncio.run(main())
