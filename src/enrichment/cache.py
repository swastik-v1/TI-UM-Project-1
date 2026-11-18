"""Enrichment coordinator with SQLite TTL cache management."""

import logging
from typing import Dict, List, Optional
from src.enrichment.base import EnrichmentProvider, EnrichmentResult
from src.models import IOCType
from src.storage.repository import IOCRepository

logger = logging.getLogger("ti_aggregator.enrichment.cache")


class EnrichmentManager:
    def __init__(
        self,
        repository: IOCRepository,
        providers: List[EnrichmentProvider],
        ttl_days_map: Dict[str, int],
    ):
        self.repository = repository
        self.providers = providers
        self.ttl_days_map = ttl_days_map

    def enrich_indicator(self, ioc_value: str, ioc_type: IOCType) -> Optional[EnrichmentResult]:
        """Looks up an indicator, using local SQLite cache if unexpired, or querying providers."""
        # 1. Check local SQLite cache
        cached = self.repository.get_cached_enrichment(ioc_value)
        if cached:
            logger.info("Cache HIT for %s from provider %s", ioc_value, cached["provider"])
            return EnrichmentResult(
                provider=cached["provider"],
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                reputation_score=float(cached.get("reputation_score", 0.0)),
                is_malicious=float(cached.get("reputation_score", 0.0)) >= 50.0,
                summary=f"Cached reputation ({cached['provider']}): {cached.get('reputation_score')}%",
                details=cached.get("raw_payload", {}),
                cached=True,
            )

        # 2. Check live configured providers
        for provider in self.providers:
            if provider.is_configured():
                res = provider.enrich(ioc_value, ioc_type)
                if res:
                    ttl_key = "ip" if ioc_type in (IOCType.IPV4, IOCType.IPV6) else ("domain" if ioc_type == IOCType.DOMAIN else "hash")
                    ttl = self.ttl_days_map.get(ttl_key, 7)
                    self.repository.set_cached_enrichment(
                        ioc_value=ioc_value,
                        provider=provider.name,
                        reputation_score=res.reputation_score,
                        raw_payload=res.details,
                        ttl_days=ttl,
                    )
                    return res

        return None
