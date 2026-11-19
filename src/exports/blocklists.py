"""Blocklist exporters for Firewalls, DNS sinkholes, Web Proxies, and EDR systems."""

import csv
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import List

from src.models import IOCType, IndicatorStatus, ScoredIndicator

logger = logging.getLogger("ti_aggregator.exports")


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def _filter_by_min_severity(indicators: List[ScoredIndicator], min_severity: str) -> List[ScoredIndicator]:
    allowed_map = {
        "LOW": {"LOW", "MEDIUM", "HIGH"},
        "MEDIUM": {"MEDIUM", "HIGH"},
        "HIGH": {"HIGH"},
    }
    allowed = allowed_map.get(min_severity.upper(), {"HIGH"})
    return [
        i for i in indicators
        if i.severity.value in allowed
        and not i.is_whitelisted
        and i.status == IndicatorStatus.ACTIVE
    ]


def export_firewall_ips(indicators: List[ScoredIndicator], output_path: Path, min_severity: str = "HIGH") -> int:
    """Exports IPv4 and IPv6 blocklist formatted for perimeter firewalls."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ip_iocs = [i for i in indicators if i.ioc_type in (IOCType.IPV4, IOCType.IPV6)]
    filtered = _filter_by_min_severity(ip_iocs, min_severity)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# Threat Intelligence Aggregator - Perimeter Firewall Blocklist\n")
        f.write(f"# Generated: {_utc_now_str()} UTC\n")
        f.write(f"# Minimum Severity: {min_severity.upper()}\n")
        f.write(f"# Total IP Count: {len(filtered)}\n#\n")
        for ioc in filtered:
            f.write(f"{ioc.value}\n")

    logger.info("Exported %d firewall IPs to %s", len(filtered), output_path)
    return len(filtered)


def export_dns_domains(indicators: List[ScoredIndicator], output_path: Path, min_severity: str = "HIGH") -> int:
    """Exports malicious domains in standard Pi-hole / Hosts sinkhole format (0.0.0.0 domain)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    domain_iocs = [i for i in indicators if i.ioc_type == IOCType.DOMAIN]
    filtered = _filter_by_min_severity(domain_iocs, min_severity)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# Threat Intelligence Aggregator - DNS Sinkhole Blocklist (Hosts Format)\n")
        f.write(f"# Generated: {_utc_now_str()} UTC\n")
        f.write(f"# Minimum Severity: {min_severity.upper()}\n")
        f.write(f"# Total Domain Count: {len(filtered)}\n#\n")
        for ioc in filtered:
            f.write(f"0.0.0.0 {ioc.value}\n")

    logger.info("Exported %d DNS sinkhole domains to %s", len(filtered), output_path)
    return len(filtered)


def export_proxy_urls(indicators: List[ScoredIndicator], output_path: Path, min_severity: str = "MEDIUM") -> int:
    """Exports plain text malicious URLs for web proxies and secure web gateways (SWG)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    url_iocs = [i for i in indicators if i.ioc_type == IOCType.URL]
    filtered = _filter_by_min_severity(url_iocs, min_severity)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# Threat Intelligence Aggregator - Web Proxy URL Blocklist\n")
        f.write(f"# Generated: {_utc_now_str()} UTC\n")
        f.write(f"# Minimum Severity: {min_severity.upper()}\n")
        f.write(f"# Total URL Count: {len(filtered)}\n#\n")
        for ioc in filtered:
            f.write(f"{ioc.value}\n")

    logger.info("Exported %d proxy URLs to %s", len(filtered), output_path)
    return len(filtered)


def export_edr_hashes(indicators: List[ScoredIndicator], output_path: Path, min_severity: str = "MEDIUM") -> int:
    """Exports CSV hash blocklist for EDR/AV agent import."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    hash_types = (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256)
    hash_iocs = [i for i in indicators if i.ioc_type in hash_types]
    filtered = _filter_by_min_severity(hash_iocs, min_severity)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["hash_value", "hash_type", "severity", "score", "first_seen", "last_seen", "sources"])
        for ioc in filtered:
            writer.writerow([
                ioc.value,
                ioc.ioc_type.value,
                ioc.severity.value,
                ioc.calculated_score,
                ioc.first_seen,
                ioc.last_seen,
                ";".join(ioc.sources),
            ])

    logger.info("Exported %d EDR hashes to %s", len(filtered), output_path)
    return len(filtered)


def export_full_json(indicators: List[ScoredIndicator], output_path: Path) -> int:
    """Exports all normalized indicators with metadata to structured JSON for SIEM/SOAR ingestion."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for ioc in indicators:
        records.append({
            "ioc_id": ioc.ioc_id,
            "value": ioc.value,
            "type": ioc.ioc_type.value,
            "severity": ioc.severity.value,
            "score": ioc.calculated_score,
            "first_seen": ioc.first_seen,
            "last_seen": ioc.last_seen,
            "occurrence_count": ioc.occurrence_count,
            "sources": ioc.sources,
            "contexts": ioc.contexts,
            "is_whitelisted": ioc.is_whitelisted,
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": _utc_now_str(), "total_iocs": len(records), "indicators": records}, f, indent=2)

    logger.info("Exported %d total indicators to %s", len(records), output_path)
    return len(records)
