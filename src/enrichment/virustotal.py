"""VirusTotal v3 API client for multi-engine threat detection."""

import logging
import os
from typing import Optional
import requests

from src.enrichment.base import EnrichmentProvider, EnrichmentResult
from src.models import IOCType

logger = logging.getLogger("ti_aggregator.enrichment.virustotal")


class VirusTotalProvider(EnrichmentProvider):
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.base_url = "https://www.virustotal.com/api/v3"

    @property
    def name(self) -> str:
        return "virustotal"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc_value: str, ioc_type: IOCType) -> Optional[EnrichmentResult]:
        if not self.is_configured():
            return None

        # Build endpoint according to IOC type
        if ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            endpoint = f"{self.base_url}/files/{ioc_value}"
        elif ioc_type in (IOCType.IPV4, IOCType.IPV6):
            endpoint = f"{self.base_url}/ip_addresses/{ioc_value}"
        elif ioc_type == IOCType.DOMAIN:
            endpoint = f"{self.base_url}/domains/{ioc_value}"
        else:
            return None

        try:
            headers = {"x-apikey": self.api_key}
            resp = requests.get(endpoint, headers=headers, timeout=8)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))

                total_engines = malicious + suspicious + harmless + undetected
                ratio = (malicious / total_engines * 100) if total_engines > 0 else 0.0

                summary = f"{malicious}/{total_engines} engines flagged as malicious."
                return EnrichmentResult(
                    provider=self.name,
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    reputation_score=round(ratio, 1),
                    is_malicious=malicious >= 3,
                    summary=summary,
                    details=stats,
                )
            else:
                logger.warning("VirusTotal returned status %s for %s", resp.status_code, ioc_value)
        except Exception as e:
            logger.error("Error querying VirusTotal for %s: %s", ioc_value, e)

        return None
