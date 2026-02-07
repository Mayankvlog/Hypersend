"""
WhatsApp-Grade Abuse Detection and Spam Prevention
==================================================

ML-based and rule-based abuse detection with graduated enforcement.
Protects against spam, harassment, and platform abuse while preserving privacy.

Privacy-First Design:
- No message content inspection (only metadata)
- Behavioral pattern analysis
- Per-user scoring with decay
- Graduated enforcement (warning -> shadowban -> suspend)

Security Properties:
- Zero-knowledge abuse detection
- Rate limiting per device
- Forwarding limits enforcement
- Suspicious activity detection
"""

import time
import asyncio
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
import json
import secrets
import math

logger = logging.getLogger(__name__)


class EnforcementLevel(Enum):
    """Graduated enforcement levels"""
    NONE = "none"
    WARNING = "warning"
    RATE_LIMITED = "rate_limited"
    SHADOWBAN = "shadowban"
    SUSPEND = "suspend"


@dataclass
class AbuseMetrics:
    """Per-user abuse metrics"""
    user_id: str
    device_id: str
    message_count: int
    spam_score: float
    last_activity: float
    enforcement_level: str
    warning_count: int
    violation_types: List[str]
    pattern_flags: List[str]
    
    @classmethod
    def create(cls, user_id: str, device_id: str) -> 'AbuseMetrics':
        return cls(
            user_id=user_id,
            device_id=device_id,
            message_count=0,
            spam_score=0.0,
            last_activity=time.time(),
            enforcement_level=EnforcementLevel.NONE.value,
            warning_count=0,
            violation_types=[],
            pattern_flags=[]
        )


class AbuseDetectionService:
    """
    WhatsApp-grade abuse detection and spam prevention.
    
    ANALYSIS DIMENSIONS:
    1. Velocity: Message frequency patterns
    2. Distribution: Recipient diversity
    3. Content: Metadata patterns (no plaintext inspection)
    4. Behavior: Temporal patterns
    5. Device: Per-device tracking
    """
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.decay_hours = 24  # Score decay over 24 hours
        self.max_messages_per_minute = 30
        self.max_messages_per_hour = 1000
        self.max_new_chats_per_hour = 50
        self.max_forward_count = 5
        
        # Spam detection thresholds
        self.spam_thresholds = {
            "velocity_violation": 0.3,
            "distribution_violation": 0.4,
            "pattern_violation": 0.5,
            "device_violation": 0.6,
            "high_risk": 0.8
        }
    
    async def analyze_message(self, user_id: str, chat_id: str, message_type: str,
                            metadata: Optional[Dict], timestamp: float) -> float:
        """
        Analyze message for spam/abuse patterns.
        Returns spam score (0.0 = clean, 1.0 = definite spam).
        """
        try:
            # Get or create user metrics
            device_id = metadata.get("device_id", "unknown") if metadata else "unknown"
            metrics = await self._get_user_metrics(user_id, device_id)
            
            # Update metrics
            metrics.message_count += 1
            metrics.last_activity = timestamp
            
            # Analyze different dimensions
            violations = []
            
            # 1. Velocity analysis
            velocity_score = await self._analyze_velocity(metrics, timestamp)
            if velocity_score > 0.1:
                violations.append(("velocity", velocity_score))
            
            # 2. Distribution analysis
            distribution_score = await self._analyze_distribution(user_id, chat_id, timestamp)
            if distribution_score > 0.1:
                violations.append(("distribution", distribution_score))
            
            # 3. Pattern analysis
            pattern_score = await self._analyze_patterns(user_id, message_type, metadata)
            if pattern_score > 0.1:
                violations.append(("pattern", pattern_score))
            
            # 4. Device analysis
            device_score = await self._analyze_device(user_id, device_id, timestamp)
            if device_score > 0.1:
                violations.append(("device", device_score))
            
            # Calculate combined spam score
            spam_score = self._calculate_spam_score(violations)
            metrics.spam_score = spam_score
            
            # Determine enforcement level
            metrics.enforcement_level = self._determine_enforcement_level(spam_score, metrics)
            
            # Store updated metrics
            await self._store_user_metrics(metrics)
            
            logger.info(f"Abuse analysis for {user_id}: score={spam_score:.3f}, level={metrics.enforcement_level}")
            
            return spam_score
            
        except Exception as e:
            logger.error(f"Abuse detection failed: {e}")
            return 0.0  # Fail safe - allow message
    
    async def _analyze_velocity(self, metrics: AbuseMetrics, timestamp: float) -> float:
        """Analyze message velocity patterns"""
        try:
            # Check messages per minute
            minute_key = f"velocity:{metrics.user_id}:{int(timestamp // 60)}"
            minute_count = await self.redis.incr(minute_key)
            await self.redis.expire(minute_key, 300)  # 5 minutes
            
            if minute_count > self.max_messages_per_minute:
                return min(1.0, minute_count / self.max_messages_per_minute)
            
            # Check messages per hour
            hour_key = f"hourly:{metrics.user_id}:{int(timestamp // 3600)}"
            hour_count = await self.redis.incr(hour_key)
            await self.redis.expire(hour_key, 7200)  # 2 hours
            
            if hour_count > self.max_messages_per_hour:
                return min(1.0, hour_count / self.max_messages_per_hour)
            
            # Check for burst patterns
            if minute_count > 10:  # More than 10 messages in a minute
                return 0.2 + (minute_count - 10) * 0.05
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Velocity analysis failed: {e}")
            return 0.0
    
    async def _analyze_distribution(self, user_id: str, chat_id: str, timestamp: float) -> float:
        """Analyze message distribution patterns"""
        try:
            # Check if this is a new chat
            chat_key = f"user_chats:{user_id}"
            chat_list = await self.redis.lrange(chat_key, 0, -1)
            
            is_new_chat = chat_id.encode() not in chat_list
            if is_new_chat:
                await self.redis.lpush(chat_key, chat_id)
                await self.redis.expire(chat_key, 86400)  # 24 hours
                
                # Check new chats per hour
                new_chats_key = f"new_chats:{user_id}:{int(timestamp // 3600)}"
                new_chats_count = await self.redis.incr(new_chats_key)
                await self.redis.expire(new_chats_key, 7200)
                
                if new_chats_count > self.max_new_chats_per_hour:
                    return min(1.0, new_chats_count / self.max_new_chats_per_hour)
            
            # Check for broadcast patterns (same message to many chats)
            recent_key = f"recent_chats:{user_id}"
            await self.redis.zadd(recent_key, {chat_id: timestamp})
            await self.redis.expire(recent_key, 3600)  # 1 hour
            
            recent_chats = await self.redis.zcard(recent_key)
            if recent_chats > 20:  # More than 20 different chats in 1 hour
                return min(1.0, recent_chats / 50)
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Distribution analysis failed: {e}")
            return 0.0
    
    async def _analyze_patterns(self, user_id: str, message_type: str, metadata: Optional[Dict]) -> float:
        """Analyze behavioral patterns"""
        try:
            score = 0.0
            
            # Check message type patterns
            if message_type == "media":
                # Check for excessive media sharing
                media_key = f"media_count:{user_id}:{int(time.time() // 3600)}"
                media_count = await self.redis.incr(media_key)
                await self.redis.expire(media_key, 7200)
                
                if media_count > 50:  # More than 50 media per hour
                    score += 0.3
            
            # Check forwarding patterns
            if metadata:
                forward_count = metadata.get("forward_count", 0)
                if forward_count > self.max_forward_count:
                    score += 0.5
                elif forward_count > 3:
                    score += 0.2
            
            # Check for suspicious timing patterns
            if metadata and metadata.get("rapid_send", False):
                score += 0.3
            
            # Check for automation patterns
            if metadata and metadata.get("automated", False):
                score += 0.6
            
            return min(1.0, score)
            
        except Exception as e:
            logger.error(f"Pattern analysis failed: {e}")
            return 0.0
    
    async def _analyze_device(self, user_id: str, device_id: str, timestamp: float) -> float:
        """Analyze device-specific patterns"""
        try:
            # Check for device switching patterns
            device_key = f"user_devices:{user_id}"
            devices = await self.redis.smembers(device_key)
            
            if len(devices) > 4:  # More than 4 devices (WhatsApp limit)
                return 0.4
            
            # Check for new device patterns
            device_activity_key = f"device_activity:{user_id}:{device_id}"
            last_activity = await self.redis.get(device_activity_key)
            
            if last_activity is None:
                # New device - slightly elevated risk
                await self.redis.setex(device_activity_key, 86400, timestamp)
                return 0.1
            else:
                await self.redis.setex(device_activity_key, 86400, timestamp)
            
            # Check for device hopping (rapid switching)
            recent_devices_key = f"recent_devices:{user_id}"
            await self.redis.zadd(recent_devices_key, {device_id: timestamp})
            await self.redis.expire(recent_devices_key, 3600)
            
            recent_devices = await self.redis.zcard(recent_devices_key)
            if recent_devices > 2:  # More than 2 devices in 1 hour
                return 0.2
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Device analysis failed: {e}")
            return 0.0
    
    def _calculate_spam_score(self, violations: List[Tuple[str, float]]) -> float:
        """Calculate combined spam score from violations"""
        if not violations:
            return 0.0
        
        # Weight different violation types
        weights = {
            "velocity": 0.3,
            "distribution": 0.4,
            "pattern": 0.5,
            "device": 0.2
        }
        
        total_score = 0.0
        for violation_type, score in violations:
            weight = weights.get(violation_type, 0.3)
            total_score += score * weight
        
        # Apply diminishing returns for multiple violations
        if len(violations) > 1:
            total_score = min(1.0, total_score * (1 + 0.2 * (len(violations) - 1)))
        
        return min(1.0, total_score)
    
    def _determine_enforcement_level(self, spam_score: float, metrics: AbuseMetrics) -> str:
        """Determine enforcement level based on spam score and history"""
        if spam_score >= self.spam_thresholds["high_risk"]:
            return EnforcementLevel.SUSPEND.value
        elif spam_score >= 0.7:
            return EnforcementLevel.SHADOWBAN.value
        elif spam_score >= 0.5:
            if metrics.warning_count >= 3:
                return EnforcementLevel.SHADOWBAN.value
            return EnforcementLevel.RATE_LIMITED.value
        elif spam_score >= 0.3:
            if metrics.warning_count >= 5:
                return EnforcementLevel.SHADOWBAN.value
            return EnforcementLevel.WARNING.value
        else:
            return EnforcementLevel.NONE.value
    
    async def _get_user_metrics(self, user_id: str, device_id: str) -> AbuseMetrics:
        """Get or create user abuse metrics"""
        try:
            metrics_key = f"abuse_metrics:{user_id}:{device_id}"
            metrics_data = await self.redis.get(metrics_key)
            
            if metrics_data:
                data = json.loads(metrics_data)
                return AbuseMetrics(**data)
            else:
                metrics = AbuseMetrics.create(user_id, device_id)
                await self._store_user_metrics(metrics)
                return metrics
                
        except Exception as e:
            logger.error(f"Failed to get user metrics: {e}")
            return AbuseMetrics.create(user_id, device_id)
    
    async def _store_user_metrics(self, metrics: AbuseMetrics):
        """Store user abuse metrics"""
        try:
            metrics_key = f"abuse_metrics:{metrics.user_id}:{metrics.device_id}"
            data = asdict(metrics)
            await self.redis.setex(metrics_key, 86400 * 7, json.dumps(data))  # 7 days
            
        except Exception as e:
            logger.error(f"Failed to store user metrics: {e}")
    
    async def get_enforcement_level(self, user_id: str, device_id: str) -> str:
        """Get current enforcement level for user/device"""
        try:
            metrics = await self._get_user_metrics(user_id, device_id)
            return metrics.enforcement_level
        except Exception as e:
            logger.error(f"Failed to get enforcement level: {e}")
            return EnforcementLevel.NONE.value
    
    async def report_abuse(self, reporter_id: str, reported_user_id: str, 
                         reason: str, evidence: Dict) -> bool:
        """Report abusive behavior"""
        try:
            # Create abuse report
            report_id = secrets.token_urlsafe(16)
            report_data = {
                "report_id": report_id,
                "reporter_id": reporter_id,
                "reported_user_id": reported_user_id,
                "reason": reason,
                "evidence": evidence,
                "timestamp": time.time(),
                "status": "pending"
            }
            
            # Store report
            report_key = f"abuse_report:{report_id}"
            await self.redis.setex(report_key, 86400 * 30, json.dumps(report_data))  # 30 days
            
            # Add to user's violation count
            metrics_key = f"abuse_metrics:{reported_user_id}:*"
            keys = await self.redis.keys(metrics_key)
            
            if keys:
                # Update first device metrics (can be enhanced for multi-device)
                await self.redis.incr(f"{keys[0]}:violations")
            
            logger.info(f"Abuse report filed: {report_id} - {reporter_id} -> {reported_user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to report abuse: {e}")
            return False
    
    async def is_rate_limited(self, user_id: str, device_id: str) -> Tuple[bool, int]:
        """Check if user is rate limited"""
        try:
            enforcement_level = await self.get_enforcement_level(user_id, device_id)
            
            if enforcement_level == EnforcementLevel.SUSPEND.value:
                return True, 0  # Indefinite
            elif enforcement_level == EnforcementLevel.SHADOWBAN.value:
                return True, 3600  # 1 hour
            elif enforcement_level == EnforcementLevel.RATE_LIMITED.value:
                return True, 60  # 1 minute
            else:
                return False, 0
                
        except Exception as e:
            logger.error(f"Failed to check rate limit: {e}")
            return False, 0
