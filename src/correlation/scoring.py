"""Deterministic scoring algorithm for cross-feed threat intelligence correlation."""

from typing import Dict, List
from src.models import Severity


def calculate_ioc_score(
    feed_ids: List[str],
    feed_weights: Dict[str, float],
    thresholds: Dict[str, float],
) -> float:
    """Calculates deterministic composite score for an indicator.

    Score = Sum(Feed Weights) + Overlap Bonus
    """
    if not feed_ids:
        return 0.0

    # 1. Base Score: sum of unique feed weights
    base_score = 0.0
    for fid in set(feed_ids):
        weight = feed_weights.get(fid, 1.0)
        base_score += weight

    # 2. Overlap Bonus: rewards indicators appearing across multiple independent feeds
    distinct_sources = len(set(feed_ids))
    bonus = 0.0
    if distinct_sources == 2:
        bonus = thresholds.get("overlap_bonus_two_sources", 1.5)
    elif distinct_sources >= 3:
        bonus_mult = thresholds.get("overlap_bonus_three_plus", 3.0)
        bonus = bonus_mult * (distinct_sources - 1)

    return round(base_score + bonus, 2)


def classify_severity(score: float, thresholds: Dict[str, float]) -> Severity:
    """Classifies risk severity into LOW, MEDIUM, or HIGH based on configured thresholds."""
    med_thresh = thresholds.get("threshold_medium", 3.0)
    high_thresh = thresholds.get("threshold_high", 6.0)

    if score >= high_thresh:
        return Severity.HIGH
    elif score >= med_thresh:
        return Severity.MEDIUM
    return Severity.LOW
