"""Feed fetcher supporting local filesystem and remote HTTP/HTTPS endpoints."""

import logging
from pathlib import Path
from typing import Optional, Tuple
import requests

from src.models import FeedDefinition

logger = logging.getLogger("ti_aggregator.fetcher")


def fetch_feed_content(feed: FeedDefinition, base_dir: Path) -> Tuple[Optional[str], str]:
    """Fetches feed content from remote URL or local file path.

    Returns:
        (content_string, source_description)
    """
    # Prefer remote if configured and specified as url
    if feed.source_type == "url" and feed.remote_url:
        try:
            logger.info("Fetching remote feed: %s (%s)", feed.name, feed.remote_url)
            headers = {"User-Agent": "ThreatIntelligenceAggregator/1.0 (+https://github.com/threat-intel)"}
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

    # Default or fallback to local file
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
