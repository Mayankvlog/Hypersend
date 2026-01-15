from typing import Dict
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
        """Check if identifier is allowed to make a request with enhanced thread safety"""
        try:
            now = time.time()
            
            with self.lock:
                # ENHANCED: Atomic operations with proper cleanup
                current_requests = self.requests.get(identifier, [])
                
                # Filter old requests atomically
                cutoff_time = now - self.window_seconds
                valid_requests = [
                    req_time for req_time in current_requests
                    if req_time > cutoff_time
                ]
                
                # Check limit and update atomically
                if len(valid_requests) >= self.max_requests:
                    # Store filtered requests but don't add new one
                    self.requests[identifier] = valid_requests
                    return False
                
                # Add current request atomically
                valid_requests.append(now)
                self.requests[identifier] = valid_requests
                return True
                
        except Exception as e:
            # Enhanced error handling with logging
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Rate limiter error: {e}")
            # Allow request on errors to prevent service disruption
            return True
    
    def get_retry_after(self, identifier: str) -> int:
        """Get seconds until next request is allowed"""
        try:
            now = time.time()
            with self.lock:
                current_requests = self.requests.get(identifier, [])
                
                if not current_requests:
                    return 0
                
                # Clean old requests
                valid_requests = [
                    req_time for req_time in current_requests
                    if now - req_time < self.window_seconds
                ]
                
                # Find when rate limit will be reset
                if len(valid_requests) >= self.max_requests:
                    # After reaching limit, calculate reset time
                    oldest_request = min(valid_requests)
                    reset_time = oldest_request + self.window_seconds
                    return max(0, int(reset_time - now))
                
                return 0
        except Exception as e:
            # Rate limiter errors should not crash the service
            return 0
    
    def reset(self):
        """Reset the rate limiter by clearing all request history"""
        with self.lock:
            self.requests.clear()

# Global rate limiters for different auth operations
auth_rate_limiter = RateLimiter(max_requests=5, window_seconds=300)  # 5 requests per 5 minutes
qr_code_limiter = RateLimiter(max_requests=10, window_seconds=60)  # 10 requests per minute