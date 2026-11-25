"""Unit tests for blocklist diff preview calculations."""

import unittest
from src.exports.blocklists import calculate_blocklist_diff
from src.models import IndicatorStatus, IOCType, ScoredIndicator, Severity


class TestBlocklistDiff(unittest.TestCase):
    def test_diff_calculation(self):
        current = [
            ScoredIndicator(
                ioc_id=1,
                value="1.1.1.2",
                ioc_type=IOCType.IPV4,
                first_seen="2026-11-01",
                last_seen="2026-11-01",
                occurrence_count=1,
                calculated_score=6.0,
                severity=Severity.HIGH,
                is_whitelisted=False,
                status=IndicatorStatus.ACTIVE,
            ),
            ScoredIndicator(
                ioc_id=2,
                value="2.2.2.2",
                ioc_type=IOCType.IPV4,
                first_seen="2026-11-01",
                last_seen="2026-11-01",
                occurrence_count=2,
                calculated_score=8.0,
                severity=Severity.HIGH,
                is_whitelisted=False,
                status=IndicatorStatus.ACTIVE,
            ),
        ]
        previous_snapshot = {"2.2.2.2", "3.3.3.3"}

        diff = calculate_blocklist_diff(current, previous_snapshot)

        self.assertEqual(diff["added_count"], 1)
        self.assertEqual(diff["added"][0]["value"], "1.1.1.2")
        self.assertEqual(diff["removed_or_expired_count"], 1)
        self.assertIn("3.3.3.3", diff["removed_or_expired"])
        self.assertEqual(diff["unchanged_count"], 1)


if __name__ == "__main__":
    unittest.main()
