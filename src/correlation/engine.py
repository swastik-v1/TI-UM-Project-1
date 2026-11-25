"""Correlation Engine to process raw relations, apply decay aging, evaluate explainable heuristics, and classify threat severities."""

import logging
from typing import Any, Dict, List, Optional, Tuple

from src.correlation.scoring import calculate_decayed_score, calculate_ioc_score, classify_severity
from src.models import FeedDefinition, IndicatorStatus, IOCType
from src.normalization.heuristics import analyze_dga_heuristics, analyze_subnet_clustering
from src.storage.repository import IOCRepository

logger = logging.getLogger("ti_aggregator.correlation")


class CorrelationEngine:
    def __init__(
        self,
        repository: IOCRepository,
        feeds: List[FeedDefinition],
        thresholds: Dict[str, float],
        retention_settings: Optional[Dict[str, Any]] = None,
        heuristic_settings: Optional[Dict[str, Any]] = None,
    ):
        self.repository = repository
        self.feed_weights = {f.id: f.weight for f in feeds}
        self.thresholds = thresholds
        self.retention = retention_settings or {
            "enabled": True,
            "retention_days": 30,
            "decay_scores": True,
            "archive_expired": True,
        }
        self.heuristics = heuristic_settings or {
            "enabled": True,
            "dga_detection": True,
            "subnet_clustering": True,
            "dga_score_boost": 1.5,
            "subnet_cluster_boost": 1.0,
        }

    def run_correlation(self) -> Dict[str, int]:
        """Correlates all stored IOCs against feeds, applies aging decay & heuristics, and updates database.

        Returns:
            Dict containing counts of classified severities and expired indicators.
        """
        raw_items = self.repository.get_raw_correlations()
        logger.info("Running correlation engine over %d unique indicators...", len(raw_items))

        updates: List[Tuple[float, float, str, str, int]] = []
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "EXPIRED": 0}

        retention_enabled = self.retention.get("enabled", True)
        retention_days = int(self.retention.get("retention_days", 30))
        decay_enabled = self.retention.get("decay_scores", True)

        # Pre-compute subnet clusters if heuristic enabled
        heuristics_enabled = self.heuristics.get("enabled", True)
        subnet_boost = float(self.heuristics.get("subnet_cluster_boost", 1.0))
        dga_boost = float(self.heuristics.get("dga_score_boost", 1.5))
        dga_active = heuristics_enabled and self.heuristics.get("dga_detection", True)
        subnet_active = heuristics_enabled and self.heuristics.get("subnet_clustering", True)

        clustered_ips: Dict[str, str] = {}
        if subnet_active:
            ipv4_list = [item["value"] for item in raw_items if item["ioc_type"] == IOCType.IPV4]
            clusters = analyze_subnet_clustering(ipv4_list, min_cluster_size=3)
            for cidr, ip_members in clusters.items():
                for ip_str in ip_members:
                    clustered_ips[ip_str] = cidr

        for item in raw_items:
            ioc_id = item["ioc_id"]
            ioc_val = item["value"]
            ioc_type = item["ioc_type"]
            feed_ids = item["feed_ids"]
            last_seen = item["last_seen"]

            score = calculate_ioc_score(feed_ids, self.feed_weights, self.thresholds)

            # Heuristic boosts
            if dga_active and ioc_type == IOCType.DOMAIN:
                dga_result = analyze_dga_heuristics(ioc_val)
                if dga_result.get("is_likely_dga"):
                    score += dga_boost

            if subnet_active and ioc_type == IOCType.IPV4 and ioc_val in clustered_ips:
                score += subnet_boost

            score = round(score, 2)

            if retention_enabled:
                decayed_score, status = calculate_decayed_score(score, last_seen, retention_days)
                if not decay_enabled and status == IndicatorStatus.ACTIVE:
                    decayed_score = score
            else:
                decayed_score = score
                status = IndicatorStatus.ACTIVE

            effective_score = decayed_score if decay_enabled else score
            severity = classify_severity(effective_score, self.thresholds)

            if status == IndicatorStatus.EXPIRED:
                severity_counts["EXPIRED"] += 1
            else:
                severity_counts[severity.value] += 1

            updates.append((score, decayed_score, severity.value, status.value, ioc_id))

        self.repository.batch_update_scores_with_decay(updates)
        logger.info(
            "Correlation, heuristics & aging complete. High: %d, Medium: %d, Low: %d, Expired: %d",
            severity_counts["HIGH"],
            severity_counts["MEDIUM"],
            severity_counts["LOW"],
            severity_counts["EXPIRED"],
        )
        return severity_counts
