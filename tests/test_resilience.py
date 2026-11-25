"""Unit tests for Circuit Breaker and Token Bucket Rate Limiter."""

import time
import unittest
from src.ingestion.resilience import CircuitBreaker, TokenBucketRateLimiter


class TestResilience(unittest.TestCase):
    def test_circuit_breaker_tripping_and_reset(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=0.2)
        host = "flaky.feed.com"

        # Initially closed
        self.assertTrue(cb.can_execute(host))

        # 3 failures -> trips to OPEN
        cb.record_failure(host)
        cb.record_failure(host)
        self.assertTrue(cb.can_execute(host))
        cb.record_failure(host)
        self.assertFalse(cb.can_execute(host))

        # After cooldown -> HALF_OPEN (allows probe)
        time.sleep(0.25)
        self.assertTrue(cb.can_execute(host))

        # Successful probe resets to CLOSED
        cb.record_success(host)
        self.assertTrue(cb.can_execute(host))

    def test_rate_limiter_tokens(self):
        rl = TokenBucketRateLimiter(rate=10.0, capacity=2.0)
        host = "api.provider.com"

        # Acquire 2 tokens immediately
        self.assertTrue(rl.acquire(host, 1.0))
        self.assertTrue(rl.acquire(host, 1.0))

        # Third token rejected
        self.assertFalse(rl.acquire(host, 1.0))

        # After short replenishment
        time.sleep(0.15)
        self.assertTrue(rl.acquire(host, 1.0))


if __name__ == "__main__":
    unittest.main()
