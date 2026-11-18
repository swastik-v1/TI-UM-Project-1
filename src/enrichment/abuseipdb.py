"""AbuseIPDB enrichment client for IP reputation verification."""

import logging
import os
from typing import Optional
import requests

from src.enrichment.base import EnrichmentProvider, EnrichmentResult
from src.models import IOCType

logger = logging.getLogger("ti_aggregator.enrichment.abuseipdb")


class AbuseIPDBProvider(EnrichmentProvider):
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self.endpoint = "https://api.abuseipdb.com/api/v2/check"

    @property
    def name(self) -> str:
        return "abuseipdb"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc_value: str, ioc_type: IOCType) -> Optional[EnrichmentResult]:
        if ioc_type not in (IOCType.IPV4, IOCType.IPV6):
            return None

        if not self.is_configured():
            logger.debug("AbuseIPDB API key not configured; skipping live lookup for %s", ioc_value)
            return None

        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json",
            }
            params = {
                "ipAddress": ioc_value,
                "maxAgeInDays": "90",
                "verbose": "",
            }
            resp = requests.get(self.endpoint, headers=headers, params=params, timeout=8)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = float(data.get("abuseConfidenceScore", 0))
                total_reports = int(data.get("totalReports", 0))
                is_malicious = score >= 50 or total_reports >= 5
                summary = f"Abuse confidence: {score}%, Total reports: {total_reports}, ISP: {data.get('isp', 'Unknown')}"

                return EnrichmentResult(
                    provider=self.name,
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    reputation_score=score,
                    is_malicious=is_malicious,
                    summary=summary,
                    details=data,
                )
            else:
                logger.warning("AbuseIPDB returned status %s for IP %s", resp.status_code, ioc_value)
        except Exception as e:
            logger.error("Error querying AbuseIPDB for %s: %s", ioc_value, e)

        return None
