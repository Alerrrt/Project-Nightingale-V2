from typing import Dict, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_requests: int, time_window: int):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed in the time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: Dict[str, list] = defaultdict(list)
        self.blocked_clients: Dict[str, datetime] = {}

    def check_rate_limit(self, client_id: str) -> bool:
        """
        Check if a client has exceeded their rate limit.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            bool: True if the client is within their rate limit, False otherwise
        """
        # Check if client is blocked
        if client_id in self.blocked_clients:
            if datetime.now() < self.blocked_clients[client_id]:
                return False
            else:
                del self.blocked_clients[client_id]

        # Get current time
        now = datetime.now()
        
        # Remove old requests
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if now - req_time < timedelta(seconds=self.time_window)
        ]
        
        # Check if client has exceeded rate limit
        if len(self.requests[client_id]) >= self.max_requests:
            # Block client for 1 minute
            self.blocked_clients[client_id] = now + timedelta(minutes=1)
            logger.warning(f"Client {client_id} rate limit exceeded")
            return False
        
        # Add new request
        self.requests[client_id].append(now)
        return True

    def get_retry_after(self, client_id: str) -> Optional[int]:
        """
        Get the number of seconds until a client can make another request.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            Optional[int]: Number of seconds until retry is allowed, or None if not blocked
        """
        if client_id in self.blocked_clients:
            retry_after = (self.blocked_clients[client_id] - datetime.now()).total_seconds()
            return max(0, int(retry_after))
        return None

    def reset(self, client_id: str):
        """
        Reset rate limit for a client.
        
        Args:
            client_id: Unique identifier for the client
        """
        if client_id in self.requests:
            del self.requests[client_id]
        if client_id in self.blocked_clients:
            del self.blocked_clients[client_id]

    def get_client_stats(self, client_id: str) -> dict:
        """
        Get rate limit statistics for a client.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            dict: Statistics including request count and time until reset
        """
        now = datetime.now()
        requests = self.requests.get(client_id, [])
        
        # Remove old requests
        valid_requests = [
            req_time for req_time in requests
            if now - req_time < timedelta(seconds=self.time_window)
        ]
        
        return {
            "request_count": len(valid_requests),
            "max_requests": self.max_requests,
            "time_window": self.time_window,
            "is_blocked": client_id in self.blocked_clients,
            "retry_after": self.get_retry_after(client_id),
            "requests_remaining": max(0, self.max_requests - len(valid_requests))
        } 