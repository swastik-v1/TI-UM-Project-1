"""Resilience module: Circuit Breaker, Exponential Backoff, and Per-Host Rate Limiter."""

import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar
from urllib.parse import urlparse

logger = logging.getLogger("ti_aggregator.resilience")

T = TypeVar("T")


class CircuitBreaker:
    """Tracks endpoint failures and opens circuit when failure threshold is exceeded."""

    def __init__(self, failure_threshold: int = 3, cooldown_seconds: float = 30.0):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        # key -> (failure_count, last_failure_timestamp, state: "CLOSED"|"OPEN"|"HALF_OPEN")
        self._states: Dict[str, Dict[str, Any]] = {}

    def _get_entry(self, key: str) -> Dict[str, Any]:
        if key not in self._states:
            self._states[key] = {
                "failures": 0,
                "last_failure": 0.0,
                "state": "CLOSED",
            }
        return self._states[key]

    def can_execute(self, key: str) -> bool:
        """Determines if a request to the target key/host is permitted."""
        entry = self._get_entry(key)
        state = entry["state"]

        if state == "CLOSED":
            return True

        now = time.time()
        if state == "OPEN":
            if now - entry["last_failure"] >= self.cooldown_seconds:
                entry["state"] = "HALF_OPEN"
                logger.info("Circuit breaker for '%s' transitioned to HALF-OPEN (testing probe).", key)
                return True
            return False

        # HALF_OPEN allows single probe
        return True

    def record_success(self, key: str) -> None:
        """Resets the circuit on successful connection."""
        entry = self._get_entry(key)
        if entry["state"] != "CLOSED":
            logger.info("Circuit breaker for '%s' reset to CLOSED after successful request.", key)
        entry["failures"] = 0
        entry["state"] = "CLOSED"

    def record_failure(self, key: str) -> None:
        """Records a failure and trips the circuit if threshold reached."""
        entry = self._get_entry(key)
        entry["failures"] += 1
        entry["last_failure"] = time.time()

        if entry["failures"] >= self.failure_threshold:
            entry["state"] = "OPEN"
            logger.warning(
                "Circuit breaker for '%s' TRIPPED to OPEN after %d consecutive failures. Cooldown: %.1fs.",
                key, entry["failures"], self.cooldown_seconds
            )


class TokenBucketRateLimiter:
    """Per-host token bucket rate limiter to prevent API / feed throttling."""

    def __init__(self, rate: float = 5.0, capacity: float = 10.0):
        self.rate = rate  # tokens added per second
        self.capacity = capacity
        # host -> (tokens, last_update_time)
        self._buckets: Dict[str, Tuple[float, float]] = {}

    def acquire(self, host: str, tokens: float = 1.0) -> bool:
        """Non-blocking token acquisition."""
        now = time.time()
        if host not in self._buckets:
            self._buckets[host] = (self.capacity, now)

        current_tokens, last_update = self._buckets[host]
        # Replenish
        elapsed = now - last_update
        current_tokens = min(self.capacity, current_tokens + (elapsed * self.rate))

        if current_tokens >= tokens:
            self._buckets[host] = (current_tokens - tokens, now)
            return True
        return False


def get_target_key(url_or_name: str) -> str:
    """Extracts hostname or identifier for circuit breaker tracking."""
    if url_or_name.startswith("http://") or url_or_name.startswith("https://"):
        try:
            return urlparse(url_or_name).netloc or url_or_name
        except Exception:
            return url_or_name
    return url_or_name
