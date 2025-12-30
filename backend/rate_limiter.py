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
"""Check if the identifier is allowed to make a request with thread safety"""
    try:
        now = time.time()
        
        with self.lock:
            # Atomic: Get current requests list
            current_requests = self.requests.get(identifier, [])
            
            # Atomic: Clean old requests
            valid_requests = [
                req_time for req_time in current_requests
                if now - req_time < self.window_seconds
            ]
            
            # Atomic: Check limit
            if len(valid_requests) >= self.max_requests:
                # Store cleaned list back
                self.requests[identifier] = valid_requests
                return False
            
            # Atomic: Add current request and store
            valid_requests.append(now)
            self.requests[identifier] = valid_requests
            return True
    
    def get_retry_after(self, identifier: str) -> int:
        """Get seconds until next request is allowed"""
        with self.lock:
            current_requests = self.requests.get(identifier, [])
            
            # Sort requests by time (newest first)
            sorted_requests = sorted(current_requests, reverse=True)
            
            # Find when rate limit will be reset
            if len(sorted_requests) >= self.max_requests:
                # After reaching limit, calculate reset time
                oldest_request = sorted_requests[-1]
                reset_time = oldest_request + self.window_seconds
                return int(reset_time - now)
            
            return 0
    
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