"""Unit tests for the automated aging and decay engine."""

from datetime import datetime, timezone, timedelta
import unittest

from src.correlation.scoring import calculate_decayed_score
from src.models import IndicatorStatus, IOCType, ScoredIndicator, Severity
from src.exports.blocklists import _filter_by_min_severity


class TestAgingAndDecay(unittest.TestCase):
    def test_recent_indicator_retains_score(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        score, status = calculate_decayed_score(base_score=10.0, last_seen_iso=now_iso, retention_days=30)
        self.assertEqual(status, IndicatorStatus.ACTIVE)
        self.assertAlmostEqual(score, 10.0, places=1)

    def test_half_decay(self):
        past_15_days = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
        score, status = calculate_decayed_score(base_score=10.0, last_seen_iso=past_15_days, retention_days=30)
        self.assertEqual(status, IndicatorStatus.ACTIVE)
        self.assertAlmostEqual(score, 5.0, places=1)

    def test_expired_indicator(self):
        past_45_days = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        score, status = calculate_decayed_score(base_score=10.0, last_seen_iso=past_45_days, retention_days=30)
        self.assertEqual(status, IndicatorStatus.EXPIRED)
        self.assertEqual(score, 0.0)

    def test_blocklist_filter_excludes_expired(self):
        active_ioc = ScoredIndicator(
            ioc_id=1,
            value="198.51.100.1",
            ioc_type=IOCType.IPV4,
            first_seen="2026-01-01",
            last_seen="2026-01-01",
            occurrence_count=2,
            calculated_score=8.0,
            severity=Severity.HIGH,
            is_whitelisted=False,
            status=IndicatorStatus.ACTIVE,
        )
        expired_ioc = ScoredIndicator(
            ioc_id=2,
            value="198.51.100.2",
            ioc_type=IOCType.IPV4,
            first_seen="2025-01-01",
            last_seen="2025-01-01",
            occurrence_count=5,
            calculated_score=15.0,
            severity=Severity.HIGH,
            is_whitelisted=False,
            status=IndicatorStatus.EXPIRED,
        )

        filtered = _filter_by_min_severity([active_ioc, expired_ioc], min_severity="HIGH")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].value, "198.51.100.1")


if __name__ == "__main__":
    unittest.main()
