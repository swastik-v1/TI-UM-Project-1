"""Deterministic scoring and aging decay algorithms for threat correlation."""

from datetime import datetime, timezone
from typing import Dict, List, Tuple
from src.models import IndicatorStatus, Severity


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


def calculate_decayed_score(
    base_score: float,
    last_seen_iso: str,
    retention_days: int = 30,
) -> Tuple[float, IndicatorStatus]:
    """Calculates TTL decayed score and active/expired status based on elapsed time.

    Decayed Score = Base Score * (1 - days_elapsed / retention_days)
    """
    if retention_days <= 0:
        return base_score, IndicatorStatus.ACTIVE

    try:
        # Parse ISO string handling both Z and offset
        cleaned = last_seen_iso.replace("Z", "+00:00")
        last_dt = datetime.fromisoformat(cleaned)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
    except Exception:
        return base_score, IndicatorStatus.ACTIVE

    now = datetime.now(timezone.utc)
    elapsed_seconds = max(0.0, (now - last_dt).total_seconds())
    days_elapsed = elapsed_seconds / 86400.0

    if days_elapsed >= retention_days:
        return 0.0, IndicatorStatus.EXPIRED

    decay_ratio = 1.0 - (days_elapsed / retention_days)
    decayed_score = round(base_score * max(0.0, decay_ratio), 2)
    return decayed_score, IndicatorStatus.ACTIVE


def classify_severity(score: float, thresholds: Dict[str, float]) -> Severity:
    """Classifies risk severity into LOW, MEDIUM, or HIGH based on configured thresholds."""
    med_thresh = thresholds.get("threshold_medium", 3.0)
    high_thresh = thresholds.get("threshold_high", 6.0)

    if score >= high_thresh:
        return Severity.HIGH
    elif score >= med_thresh:
        return Severity.MEDIUM
    return Severity.LOW
