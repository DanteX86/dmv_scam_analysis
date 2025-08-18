"""Rate limiter implementation for API request throttling."""

import asyncio
import time
from collections import defaultdict
from typing import Dict, Optional, Tuple


class RateLimiter:
    """Rate limiter implementation using token bucket algorithm."""

    def __init__(self, max_requests: int = 100, time_window: int = 60):
        """Initialize rate limiter.

        Args:
            max_requests: Maximum number of requests allowed in the time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        # Dict[token, List[timestamp]]
        self._request_history: Dict[str, list] = defaultdict(list)
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def check_rate_limit(self, token: str) -> bool:
        """Check if the request is within rate limits.

        Args:
            token: API token to check

        Returns:
            bool: True if request is allowed, False if rate limit exceeded
        """
        async with self._locks[token]:
            now = time.time()

            # Clean up old requests
            self._request_history[token] = [
                ts
                for ts in self._request_history[token]
                if now - ts <= self.time_window
            ]

            # Check if we're over the limit
            if len(self._request_history[token]) >= self.max_requests:
                return False

            # Add current request
            self._request_history[token].append(now)
            return True

    async def get_remaining_requests(self, token: str) -> Tuple[int, int]:
        """Get remaining requests and reset time.

        Args:
            token: API token to check

        Returns:
            Tuple[int, int]: (remaining requests, seconds until reset)
        """
        async with self._locks[token]:
            now = time.time()

            # Clean up old requests
            self._request_history[token] = [
                ts
                for ts in self._request_history[token]
                if now - ts <= self.time_window
            ]

            # Calculate remaining requests
            used_requests = len(self._request_history[token])
            remaining = max(0, self.max_requests - used_requests)

            # Calculate time until reset
            if used_requests > 0:
                oldest_request = min(self._request_history[token])
                import math

                reset_time = max(
                    0, int(math.ceil(oldest_request + self.time_window - now))
                )
            else:
                reset_time = 0

            return remaining, reset_time

    def reset(self, token: Optional[str] = None) -> None:
        """Reset rate limiter for a token or all tokens.

        Args:
            token: Optional token to reset. If None, resets all tokens.
        """
        if token:
            self._request_history[token] = []
        else:
            self._request_history.clear()

    async def wait_if_needed(self, token: str) -> Tuple[bool, int]:
        """Wait if rate limit is exceeded.

        Args:
            token: API token to check

        Returns:
            Tuple[bool, int]: (True if waited, seconds waited)
        """
        remaining, reset_time = await self.get_remaining_requests(token)

        if remaining > 0:
            return False, 0

        await asyncio.sleep(reset_time)
        return True, reset_time
