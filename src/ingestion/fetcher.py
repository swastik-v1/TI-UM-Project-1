"""Feed fetcher supporting local filesystem and high-speed asynchronous HTTP/HTTPS endpoints."""

import asyncio
import logging
from pathlib import Path
from typing import List, Optional, Tuple
import httpx
import requests

from src.models import FeedDefinition

logger = logging.getLogger("ti_aggregator.fetcher")

USER_AGENT = "ThreatIntelligenceAggregator/1.1 (+https://github.com/threat-intel)"


def fetch_feed_content(feed: FeedDefinition, base_dir: Path) -> Tuple[Optional[str], str]:
    """Synchronous fallback to fetch a single feed."""
    if feed.source_type == "url" and feed.remote_url:
        try:
            logger.info("Fetching remote feed: %s (%s)", feed.name, feed.remote_url)
            headers = {"User-Agent": USER_AGENT}
            resp = requests.get(feed.remote_url, headers=headers, timeout=10)
            resp.raise_for_status()
            return resp.text, f"remote:{feed.remote_url}"
        except Exception as e:
            logger.warning("Failed to fetch remote feed '%s': %s. Checking fallback...", feed.name, e)
            if feed.path:
                local_path = base_dir / feed.path
                if local_path.is_file():
                    logger.info("Falling back to local cache fixture: %s", local_path)
                    with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                        return f.read(), f"local_fallback:{local_path}"
            return None, f"error:{e}"

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
) -> Tuple[FeedDefinition, Optional[str], str]:
    """Asynchronously fetches a single threat feed."""
    if feed.source_type == "url" and feed.remote_url:
        try:
            logger.info("[Async] Fetching remote feed: %s (%s)", feed.name, feed.remote_url)
            headers = {"User-Agent": USER_AGENT}
            resp = await client.get(feed.remote_url, headers=headers, timeout=10.0)
            resp.raise_for_status()
            return feed, resp.text, f"remote:{feed.remote_url}"
        except Exception as e:
            logger.warning("[Async] Remote fetch failed for '%s': %s. Checking fallback...", feed.name, e)
            if feed.path:
                local_path = base_dir / feed.path
                if local_path.is_file():
                    logger.info("[Async] Falling back to local fixture: %s", local_path)
                    with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                        return feed, f.read(), f"local_fallback:{local_path}"
            return feed, None, f"error:{e}"

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
