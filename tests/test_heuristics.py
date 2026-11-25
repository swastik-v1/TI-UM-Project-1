"""Unit tests for Shannon Entropy DGA detection and subnet clustering heuristics."""

import unittest
from src.normalization.heuristics import (
    calculate_shannon_entropy,
    analyze_dga_heuristics,
    analyze_subnet_clustering,
)


class TestHeuristics(unittest.TestCase):
    def test_shannon_entropy_calculation(self):
        # Repetitive string has low entropy
        low = calculate_shannon_entropy("aaaaaaa")
        self.assertEqual(low, 0.0)

        # High entropy randomized string
        high = calculate_shannon_entropy("xzkqp91amvl78")
        self.assertGreater(high, 3.5)

    def test_dga_domain_detection(self):
        # Known normal domains
        norm = analyze_dga_heuristics("google.com")
        self.assertFalse(norm["is_likely_dga"])

        norm2 = analyze_dga_heuristics("paypal-security-update.com")
        self.assertFalse(norm2["is_likely_dga"])

        # High entropy algorithmic DGA domain
        dga = analyze_dga_heuristics("xzkqp91amvl78w2p.biz")
        self.assertTrue(dga["is_likely_dga"])
        self.assertGreaterEqual(dga["entropy"], 3.5)

    def test_subnet_clustering(self):
        ips = [
            "198.51.100.10",
            "198.51.100.11",
            "198.51.100.12",  # 3 in 198.51.100.0/24
            "203.0.113.5",
        ]
        clusters = analyze_subnet_clustering(ips, min_cluster_size=3)
        self.assertIn("198.51.100.0/24", clusters)
        self.assertEqual(len(clusters["198.51.100.0/24"]), 3)
        self.assertNotIn("203.0.113.0/24", clusters)


if __name__ == "__main__":
    unittest.main()
