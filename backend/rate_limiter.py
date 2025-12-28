from datetime import datetime, timedelta
from typing import Dict, Optional
import time
import threading
from collections import defaultdict

class RateLimiter:
    def __init__(self, max_requests: int = 5, window_seconds: int = 300):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if the identifier is allowed to make a request"""
        now = time.time()
        
        with self.lock:
            # Clean old requests
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if now - req_time < self.window_seconds
            ]
            
            # Check if under limit
            if len(self.requests[identifier]) >= self.max_requests:
                return False
            
            # Add current request
            self.requests[identifier].append(now)
            return True
    
    def get_retry_after(self, identifier: str) -> int:
        """Get seconds until next request is allowed"""
        if not self.requests[identifier]:
            return 0
        
        oldest_request = min(self.requests[identifier])
        retry_after = int(self.window_seconds - (time.time() - oldest_request))
        return max(0, retry_after)

# Global rate limiters for different auth operations
auth_rate_limiter = RateLimiter(max_requests=5, window_seconds=300)  # 5 requests per 5 minutes
password_reset_limiter = RateLimiter(max_requests=3, window_seconds=900)  # 3 requests per 15 minutes
qr_code_limiter = RateLimiter(max_requests=10, window_seconds=60)  # 10 requests per minute