"""
recon_engine.ratelimit
========================
Two mechanisms, both required by the brief:

1. RateLimiter -- a token-bucket limiter driven by --rate (requests/sec),
   so the engine performs "low-rate enumeration" as required by the ROE,
   not a burst scan.

2. RequestBudget -- a hard, non-negotiable cap (240 requests per the
   proof requirements). Once exhausted, no further requests may be sent
   for the remainder of the run, regardless of what stages remain
   incomplete -- the orchestrator must treat budget exhaustion as a stop
   condition, not silently truncate results without recording it.
"""
from __future__ import annotations

import time


class RateLimiter:
    """Simple token bucket. Call wait_for_slot() before each request."""

    def __init__(self, rate_per_second: float, burst: int = 1):
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be > 0")
        self.rate = rate_per_second
        self.capacity = max(burst, 1)
        self._tokens = float(self.capacity)
        self._last = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    def wait_for_slot(self, sleep_fn=time.sleep) -> None:
        self._refill()
        if self._tokens < 1:
            deficit = 1 - self._tokens
            sleep_fn(deficit / self.rate)
            self._refill()
        self._tokens -= 1


class BudgetExceeded(Exception):
    pass


class RequestBudget:
    """Hard cap on total requests for the run. Not a rate -- a lifetime
    count. Matches the proof requirement: 'no more than the 240-request
    budget.'"""

    def __init__(self, max_requests: int = 240):
        self.max_requests = max_requests
        self.used = 0

    def remaining(self) -> int:
        return max(0, self.max_requests - self.used)

    def consume(self, n: int = 1) -> None:
        if self.used + n > self.max_requests:
            raise BudgetExceeded(
                f"request budget exhausted: {self.used}/{self.max_requests} used, "
                f"attempted +{n}"
            )
        self.used += n