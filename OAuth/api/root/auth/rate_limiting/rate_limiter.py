"""
Rate limiting functionality.
Provides in-memory rate limiting with decorator support.
"""

import time
from typing import Dict, List, Callable
from functools import wraps

from auth.common.exceptions import RateLimitExceededError


class RateLimiter:
    """In-memory rate limiter (use Redis in production)."""

    def __init__(self):
        self.requests: Dict[str, List[float]] = {}

    def is_allowed(self, key: str, limit: int, window_seconds: int) -> bool:
        """
        Check if request is allowed under rate limit.

        Args:
            key: Rate limit key (e.g., user ID, IP address)
            limit: Maximum requests allowed
            window_seconds: Time window in seconds

        Returns:
            True if request is allowed
        """
        now = time.time()
        window_start = now - window_seconds

        # Clean up old requests
        if key in self.requests:
            self.requests[key] = [
                req_time for req_time in self.requests[key] if req_time > window_start
            ]
        else:
            self.requests[key] = []

        # Check if limit exceeded
        if len(self.requests[key]) >= limit:
            return False

        # Add current request
        self.requests[key].append(now)
        return True

    def limit(self, key_prefix: str, limit: int, window_seconds: int):
        """
        Decorator for rate limiting functions.

        Args:
            key_prefix: Prefix for rate limit key
            limit: Maximum requests allowed
            window_seconds: Time window in seconds
        """

        def decorator(func: Callable):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Generate rate limit key (you might want to customize this)
                key = f"{key_prefix}:global"  # Simple global rate limiting

                if not self.is_allowed(key, limit, window_seconds):
                    raise RateLimitExceededError()

                return func(*args, **kwargs)

            return wrapper

        return decorator

    def get_remaining_requests(self, key: str, limit: int, window_seconds: int) -> int:
        """
        Get remaining requests for a key.

        Args:
            key: Rate limit key
            limit: Maximum requests allowed
            window_seconds: Time window in seconds

        Returns:
            Number of remaining requests
        """
        now = time.time()
        window_start = now - window_seconds

        if key in self.requests:
            recent_requests = [
                req_time for req_time in self.requests[key] if req_time > window_start
            ]
            return max(0, limit - len(recent_requests))

        return limit

    def reset_key(self, key: str):
        """Reset rate limit for a specific key."""
        if key in self.requests:
            del self.requests[key]
