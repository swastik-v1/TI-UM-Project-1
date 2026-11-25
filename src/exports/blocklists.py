"""Blocklist exporters for Firewalls, DNS sinkholes, Web Proxies, EDR, STIX 2.1 bundles, and Diff Previews."""

import csv
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Set
import uuid

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
        f.write(f"# ThreatForge - Perimeter Firewall Blocklist\n")
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
        f.write(f"# ThreatForge - DNS Sinkhole Blocklist (Hosts Format)\n")
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
        f.write(f"# ThreatForge - Web Proxy URL Blocklist\n")
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
            "decayed_score": ioc.decayed_score,
            "status": ioc.status.value,
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


def export_stix_bundle(indicators: List[ScoredIndicator], output_path: Path, min_severity: str = "MEDIUM") -> int:
    """Exports active threat indicators as an official OASIS STIX 2.1 JSON Bundle."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    filtered = _filter_by_min_severity(indicators, min_severity)
    now_iso = _utc_now_str()

    stix_objects = []
    for ioc in filtered:
        pattern = ""
        if ioc.ioc_type == IOCType.IPV4:
            pattern = f"[ipv4-addr:value = '{ioc.value}']"
        elif ioc.ioc_type == IOCType.IPV6:
            pattern = f"[ipv6-addr:value = '{ioc.value}']"
        elif ioc.ioc_type == IOCType.DOMAIN:
            pattern = f"[domain-name:value = '{ioc.value}']"
        elif ioc.ioc_type == IOCType.URL:
            pattern = f"[url:value = '{ioc.value}']"
        elif ioc.ioc_type == IOCType.EMAIL:
            pattern = f"[email-addr:value = '{ioc.value}']"
        elif ioc.ioc_type == IOCType.HASH_MD5:
            pattern = f"[file:hashes.MD5 = '{ioc.value}']"
        elif ioc.ioc_type == IOCType.HASH_SHA1:
            pattern = f"[file:hashes.'SHA-1' = '{ioc.value}']"
        elif ioc.ioc_type == IOCType.HASH_SHA256:
            pattern = f"[file:hashes.'SHA-256' = '{ioc.value}']"

        if not pattern:
            continue

        created_ts = (ioc.first_seen + "Z") if not ioc.first_seen.endswith("Z") else ioc.first_seen
        modified_ts = (ioc.last_seen + "Z") if not ioc.last_seen.endswith("Z") else ioc.last_seen

        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": created_ts,
            "modified": modified_ts,
            "name": f"Malicious {ioc.ioc_type.value.upper()}: {ioc.value}",
            "description": f"Consensus score: {ioc.calculated_score} ({ioc.severity.value}). Sources: {', '.join(ioc.sources)}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": created_ts,
            "confidence": int(min(100, max(10, ioc.calculated_score * 10))),
            "labels": ["malicious-activity", ioc.severity.value.lower()],
            "external_references": [
                {"source_name": s, "description": f"Reported by feed {s}"} for s in ioc.sources
            ],
        }
        stix_objects.append(indicator_obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": stix_objects,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    logger.info("Exported %d STIX 2.1 indicators to %s", len(stix_objects), output_path)
    return len(stix_objects)


def calculate_blocklist_diff(
    current_active_iocs: List[ScoredIndicator],
    previous_snapshot_values: Set[str],
) -> Dict[str, Any]:
    """Calculates added, expired/removed, and unchanged indicators relative to a previous run."""
    current_map = {ioc.value: ioc for ioc in current_active_iocs if ioc.status == IndicatorStatus.ACTIVE}
    current_values = set(current_map.keys())

    added_values = current_values - previous_snapshot_values
    removed_values = previous_snapshot_values - current_values
    unchanged_values = current_values & previous_snapshot_values

    added_list = [
        {"value": v, "type": current_map[v].ioc_type.value, "score": current_map[v].calculated_score, "severity": current_map[v].severity.value}
        for v in sorted(added_values)
    ]

    return {
        "added_count": len(added_values),
        "removed_or_expired_count": len(removed_values),
        "unchanged_count": len(unchanged_values),
        "total_active": len(current_values),
        "added": added_list,
        "removed_or_expired": sorted(list(removed_values)),
    }
