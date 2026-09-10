import asyncio
import time
from collections import deque


class RateLimiter:
    """
    Async rate limiter to allow up to `max_calls` within `period` seconds.
    """

    def __init__(self, max_calls: int, period: float):
        """
        Args:
            max_calls: Max number of allowed calls in the period.
            period: Time window in seconds.
        """

        self.max_calls = max_calls
        self.period = period
        self.calls = deque()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait until the rate limit allows a new call."""
        while True:
            async with self._lock:
                now = time.monotonic()
                while self.calls and now - self.calls[0] > self.period:
                    self.calls.popleft()
                if len(self.calls) < self.max_calls:
                    self.calls.append(now)
                    return
                sleep_time = self.period - (now - self.calls[0])
            await asyncio.sleep(max(0, sleep_time))
