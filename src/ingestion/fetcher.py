"""Feed fetcher supporting local filesystem and high-speed asynchronous HTTP/HTTPS endpoints with resilience (Circuit Breaker, Rate Limiting & Exponential Retries)."""

import asyncio
import logging
from pathlib import Path
import time
from typing import List, Optional, Tuple
import requests

try:
    import httpx
except ImportError:
    httpx = None

from src.models import FeedDefinition
from src.ingestion.resilience import CircuitBreaker, TokenBucketRateLimiter, get_target_key

logger = logging.getLogger("ti_aggregator.fetcher")

USER_AGENT = "ThreatIntelligenceAggregator/1.2 (+https://github.com/threat-intel)"

# Global resilience singletons
global_circuit_breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=30.0)
global_rate_limiter = TokenBucketRateLimiter(rate=5.0, capacity=10.0)


def fetch_feed_content(feed: FeedDefinition, base_dir: Path, max_retries: int = 2) -> Tuple[Optional[str], str]:
    """Synchronous fallback to fetch a single feed with circuit breaking and retries."""
    if feed.source_type == "url" and feed.remote_url:
        target_key = get_target_key(feed.remote_url)

        if not global_circuit_breaker.can_execute(target_key):
            logger.warning("Circuit breaker OPEN for host '%s'. Skipping remote fetch for feed '%s'.", target_key, feed.name)
            if feed.path:
                local_path = base_dir / feed.path
                if local_path.is_file():
                    logger.info("Circuit breaker fallback to local fixture: %s", local_path)
                    with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                        return f.read(), f"local_circuit_fallback:{local_path}"
            return None, f"error:circuit_open:{target_key}"

        # Rate limit
        global_rate_limiter.acquire(target_key)

        headers = {"User-Agent": USER_AGENT}
        for attempt in range(max_retries + 1):
            try:
                logger.info("Fetching remote feed: %s (%s) [Attempt %d/%d]", feed.name, feed.remote_url, attempt + 1, max_retries + 1)
                resp = requests.get(feed.remote_url, headers=headers, timeout=10)
                resp.raise_for_status()
                global_circuit_breaker.record_success(target_key)
                return resp.text, f"remote:{feed.remote_url}"
            except Exception as e:
                logger.warning("Attempt %d failed for '%s': %s", attempt + 1, feed.name, e)
                if attempt < max_retries:
                    time.sleep(0.5 * (2 ** attempt))

        global_circuit_breaker.record_failure(target_key)
        if feed.path:
            local_path = base_dir / feed.path
            if local_path.is_file():
                logger.info("Falling back to local cache fixture: %s", local_path)
                with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read(), f"local_fallback:{local_path}"
        return None, f"error:remote_failed_after_retries"

    if feed.path:
        local_path = base_dir / feed.path
        if local_path.is_file():
            logger.info("Reading local feed: %s (%s)", feed.name, local_path)
            try:
                with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read(), f"local:{local_path}"
            except Exception as e:
                logger.error("Error reading file %s: %s", local_path, e)
                return None, f"error:{e}"
        else:
            logger.error("Configured local feed file does not exist: %s", local_path)
            return None, f"error:file_not_found:{local_path}"

    return None, "error:no_source_configured"


async def fetch_feed_async(
    feed: FeedDefinition,
    base_dir: Path,
    client: httpx.AsyncClient,
    max_retries: int = 2,
) -> Tuple[FeedDefinition, Optional[str], str]:
    """Asynchronously fetches a single threat feed with circuit breaker protection and retries."""
    if feed.source_type == "url" and feed.remote_url:
        target_key = get_target_key(feed.remote_url)

        if not global_circuit_breaker.can_execute(target_key):
            logger.warning("[Async] Circuit breaker OPEN for host '%s'. Skipping remote fetch for '%s'.", target_key, feed.name)
            if feed.path:
                local_path = base_dir / feed.path
                if local_path.is_file():
                    with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                        return feed, f.read(), f"local_circuit_fallback:{local_path}"
            return feed, None, f"error:circuit_open:{target_key}"

        global_rate_limiter.acquire(target_key)
        headers = {"User-Agent": USER_AGENT}

        for attempt in range(max_retries + 1):
            try:
                logger.info("[Async] Fetching remote feed: %s (%s) [Attempt %d/%d]", feed.name, feed.remote_url, attempt + 1, max_retries + 1)
                resp = await client.get(feed.remote_url, headers=headers, timeout=10.0)
                resp.raise_for_status()
                global_circuit_breaker.record_success(target_key)
                return feed, resp.text, f"remote:{feed.remote_url}"
            except Exception as e:
                logger.warning("[Async] Attempt %d failed for '%s': %s", attempt + 1, feed.name, e)
                if attempt < max_retries:
                    await asyncio.sleep(0.5 * (2 ** attempt))

        global_circuit_breaker.record_failure(target_key)
        if feed.path:
            local_path = base_dir / feed.path
            if local_path.is_file():
                logger.info("[Async] Falling back to local fixture: %s", local_path)
                with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                    return feed, f.read(), f"local_fallback:{local_path}"
        return feed, None, f"error:remote_failed_after_retries"

    if feed.path:
        local_path = base_dir / feed.path
        if local_path.is_file():
            try:
                with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                    return feed, f.read(), f"local:{local_path}"
            except Exception as e:
                return feed, None, f"error:{e}"
        return feed, None, f"error:file_not_found:{local_path}"

    return feed, None, "error:no_source_configured"


async def fetch_all_feeds_async(
    feeds: List[FeedDefinition],
    base_dir: Path,
) -> List[Tuple[FeedDefinition, Optional[str], str]]:
    """Concurrently fetches multiple feeds in parallel using asyncio and httpx."""
    if httpx is None:
        logger.warning("httpx is not installed; falling back to sequential feed fetching.")
        results = []
        for feed in feeds:
            content, desc = fetch_feed_content(feed, base_dir)
            results.append((feed, content, desc))
        return results

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        tasks = [fetch_feed_async(feed, base_dir, client) for feed in feeds]
        results = await asyncio.gather(*tasks)
        return list(results)


def fetch_all_feeds(
    feeds: List[FeedDefinition],
    base_dir: Path,
) -> List[Tuple[FeedDefinition, Optional[str], str]]:
    """Synchronous entry point that executes asynchronous concurrent ingestion."""
    return asyncio.run(fetch_all_feeds_async(feeds, base_dir))
