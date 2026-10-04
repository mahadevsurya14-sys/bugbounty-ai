"""
Unit tests for RateLimiter.
"""

import time
import pytest
from app.core.exceptions import RateLimitExceededError
from app.core.rate_limiter import RateLimiter


def test_rate_limiter_acquire_and_release():
    limiter = RateLimiter(requests_per_second=10.0, max_concurrency=2, cooldown_seconds=0.01)

    # First acquire succeeds immediately
    assert limiter.acquire("target1", wait=False) is True
    limiter.release("target1")


def test_rate_limiter_concurrency_blocking():
    limiter = RateLimiter(requests_per_second=10.0, max_concurrency=1, timeout_seconds=0.2, cooldown_seconds=0.0)

    # Acquire only slot
    assert limiter.acquire("target1", wait=False) is True

    # Second acquire should fail with wait=False
    assert limiter.acquire("target1", wait=False) is False

    # Release
    limiter.release("target1")

    # Now acquire should succeed
    assert limiter.acquire("target1", wait=False) is True
    limiter.release("target1")


def test_rate_limiter_target_quota():
    limiter = RateLimiter(requests_per_second=100.0, max_requests_per_target=2, cooldown_seconds=0.0)

    limiter.acquire("targetA")
    limiter.release("targetA")

    limiter.acquire("targetA")
    limiter.release("targetA")

    # 3rd request to targetA should exceed quota
    with pytest.raises(RateLimitExceededError):
        limiter.acquire("targetA")
