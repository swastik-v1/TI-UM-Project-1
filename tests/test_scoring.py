"""Unit tests for deterministic scoring and severity classification."""

import unittest
from src.correlation.scoring import calculate_ioc_score, classify_severity
from src.models import Severity


class TestScoring(unittest.TestCase):
    def setUp(self):
        self.weights = {
            "feed_high": 5.0,
            "feed_med": 3.0,
            "feed_low": 1.0,
        }
        self.thresholds = {
            "threshold_medium": 3.0,
            "threshold_high": 6.0,
            "overlap_bonus_two_sources": 1.5,
            "overlap_bonus_three_plus": 3.0,
        }

    def test_single_feed_score(self):
        # 1 low feed -> base=1.0, bonus=0 -> 1.0 -> LOW
        score = calculate_ioc_score(["feed_low"], self.weights, self.thresholds)
        self.assertEqual(score, 1.0)
        self.assertEqual(classify_severity(score, self.thresholds), Severity.LOW)

        # 1 high feed -> base=5.0, bonus=0 -> 5.0 -> MEDIUM
        score_high = calculate_ioc_score(["feed_high"], self.weights, self.thresholds)
        self.assertEqual(score_high, 5.0)
        self.assertEqual(classify_severity(score_high, self.thresholds), Severity.MEDIUM)

    def test_two_feeds_overlap_bonus(self):
        # 2 feeds -> base = 5.0 + 3.0 = 8.0, bonus = 1.5 -> 9.5 -> HIGH
        score = calculate_ioc_score(["feed_high", "feed_med"], self.weights, self.thresholds)
        self.assertEqual(score, 9.5)
        self.assertEqual(classify_severity(score, self.thresholds), Severity.HIGH)

    def test_three_feeds_overlap(self):
        # 3 feeds -> base = 5.0 + 3.0 + 1.0 = 9.0, bonus = 3.0 * (3-1) = 6.0 -> 15.0 -> HIGH
        score = calculate_ioc_score(["feed_high", "feed_med", "feed_low"], self.weights, self.thresholds)
        self.assertEqual(score, 15.0)
        self.assertEqual(classify_severity(score, self.thresholds), Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
