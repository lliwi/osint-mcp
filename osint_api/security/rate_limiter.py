"""
In-memory rate limiter for workflow requests and external API calls.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque


class RateLimiter:
    """Token-bucket / sliding-window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = asyncio.Lock()
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    async def is_allowed(self, key: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            window = self._windows[key]
            cutoff = now - self.window_seconds
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) >= self.max_requests:
                return False
            window.append(now)
            return True

    async def check_or_raise(self, key: str) -> None:
        if not await self.is_allowed(key):
            raise RateLimitExceeded(
                f"Rate limit exceeded for '{key}': max {self.max_requests} "
                f"requests per {self.window_seconds}s"
            )


class RateLimitExceeded(Exception):
    pass


# Shared limiters (singleton-like, imported where needed)
workflow_limiter = RateLimiter(max_requests=10, window_seconds=60)
api_limiter = RateLimiter(max_requests=5, window_seconds=60)
