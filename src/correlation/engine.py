"""Correlation Engine to process raw relations and classify threat severities."""

import logging
from typing import Dict, List, Tuple

from src.correlation.scoring import calculate_ioc_score, classify_severity
from src.models import FeedDefinition
from src.storage.repository import IOCRepository

logger = logging.getLogger("ti_aggregator.correlation")


class CorrelationEngine:
    def __init__(
        self,
        repository: IOCRepository,
        feeds: List[FeedDefinition],
        thresholds: Dict[str, float],
    ):
        self.repository = repository
        self.feed_weights = {f.id: f.weight for f in feeds}
        self.thresholds = thresholds

    def run_correlation(self) -> Dict[str, int]:
        """Correlates all stored IOCs against feeds and updates scores.

        Returns:
            Dict containing counts of classified severities.
        """
        raw_items = self.repository.get_raw_correlations()
        logger.info("Running correlation engine over %d unique indicators...", len(raw_items))

        updates: List[Tuple[float, str, int]] = []
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

        for item in raw_items:
            ioc_id = item["ioc_id"]
            feed_ids = item["feed_ids"]

            score = calculate_ioc_score(feed_ids, self.feed_weights, self.thresholds)
            severity = classify_severity(score, self.thresholds)

            updates.append((score, severity.value, ioc_id))
            severity_counts[severity.value] += 1

        self.repository.batch_update_scores(updates)
        logger.info(
            "Correlation complete. High: %d, Medium: %d, Low: %d",
            severity_counts["HIGH"],
            severity_counts["MEDIUM"],
            severity_counts["LOW"],
        )
        return severity_counts
