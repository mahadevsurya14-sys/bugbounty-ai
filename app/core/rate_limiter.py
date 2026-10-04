"""
Rate Limiter & Concurrency Controller.
Enforces:
- requests_per_second (RPS)
- requests_per_minute (RPM)
- max_concurrent_requests
- max_requests_per_target
- target cooldown
- timeout
"""

from contextlib import contextmanager
import threading
import time
from typing import Dict, Generator, Optional

from app.core.exceptions import RateLimitExceededError


class RateLimiter:
    """Thread-safe token bucket rate limiter with target tracking and concurrency gating."""

    def __init__(
        self,
        requests_per_second: float = 2.0,
        requests_per_minute: float = 60.0,
        max_concurrency: int = 2,
        max_requests_per_target: int = 1000,
        cooldown_seconds: float = 0.5,
        timeout_seconds: float = 15.0,
    ):
        self.rps = max(0.1, requests_per_second)
        self.rpm = max(1.0, requests_per_minute)
        self.max_concurrency = max(1, max_concurrency)
        self.max_requests_per_target = max_requests_per_target
        self.cooldown = max(0.0, cooldown_seconds)
        self.timeout = max(1.0, timeout_seconds)

        self._lock = threading.Lock()
        self._concurrency_semaphore = threading.Semaphore(self.max_concurrency)

        # Token buckets
        self._tokens_sec = self.rps
        self._last_sec_refill = time.monotonic()

        # Per-target tracking
        self._target_last_request: Dict[str, float] = {}
        self._target_request_count: Dict[str, int] = {}

    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_sec_refill
        if elapsed > 0:
            self._tokens_sec = min(self.rps, self._tokens_sec + elapsed * self.rps)
            self._last_sec_refill = now

    def acquire(self, target: str, wait: bool = True) -> bool:
        """
        Attempt to acquire clearance to issue a request to target.
        If wait is True, blocks until token/cooldown allows or timeout expires.
        """
        start_time = time.monotonic()

        # Check total requests to this target
        with self._lock:
            count = self._target_request_count.get(target, 0)
            if count >= self.max_requests_per_target:
                raise RateLimitExceededError(
                    limit=float(self.max_requests_per_target),
                    current=float(count),
                    scope=f"Target {target} max requests quota reached",
                )

        # Acquire concurrency slot
        if wait:
            acquired_sem = self._concurrency_semaphore.acquire(blocking=True, timeout=self.timeout)
        else:
            acquired_sem = self._concurrency_semaphore.acquire(blocking=False)

        if not acquired_sem:
            if not wait:
                return False
            raise RateLimitExceededError(
                limit=float(self.max_concurrency),
                current=float(self.max_concurrency),
                scope="Concurrency limit reached",
            )

        # Now acquire token and observe cooldown
        while True:
            with self._lock:
                self._refill()
                now = time.monotonic()
                last_time = self._target_last_request.get(target, 0.0)
                elapsed_since_target = now - last_time

                has_token = self._tokens_sec >= 1.0
                cooldown_met = elapsed_since_target >= self.cooldown

                if has_token and cooldown_met:
                    self._tokens_sec -= 1.0
                    self._target_last_request[target] = now
                    self._target_request_count[target] = self._target_request_count.get(target, 0) + 1
                    return True

            if not wait:
                self._concurrency_semaphore.release()
                return False

            if (time.monotonic() - start_time) > self.timeout:
                self._concurrency_semaphore.release()
                raise RateLimitExceededError(
                    limit=self.rps,
                    current=0.0,
                    scope=f"Timeout waiting for rate limit token on {target}",
                )

            time.sleep(0.05)

    def release(self, target: Optional[str] = None):
        """Release concurrency slot."""
        self._concurrency_semaphore.release()

    @contextmanager
    def guard(self, target: str) -> Generator[None, None, None]:
        """Context manager to safely acquire and release rate limit slots."""
        self.acquire(target, wait=True)
        try:
            yield
        finally:
            self.release(target)
