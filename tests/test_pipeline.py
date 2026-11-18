"""Integration tests verifying the complete end-to-end processing pipeline."""

import tempfile
import unittest
from pathlib import Path

from src.config_loader import AppConfig, BASE_DIR
from src.correlation.engine import CorrelationEngine
from src.exports.blocklists import export_firewall_ips, export_dns_domains, export_full_json
from src.ingestion.fetcher import fetch_feed_content
from src.ingestion.parsers import parse_raw_feed
from src.normalization.derived import extract_derived_indicators
from src.normalization.extractors import classify_and_normalize_ioc
from src.normalization.filter import IOCFilter
from src.storage.database import init_db
from src.storage.repository import IOCRepository


class TestPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_ti.db"
        init_db(self.db_path)
        self.repo = IOCRepository(self.db_path)
        self.config = AppConfig()

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_full_ingestion_and_correlation_cycle(self):
        ioc_filter = IOCFilter(
            safe_ips=self.config.safe_ips,
            safe_domains=self.config.safe_domains,
            suppression_rules=self.config.suppression_rules,
        )

        feeds = self.config.get_feeds()
        self.assertGreater(len(feeds), 0)

        # Ingest
        for feed in feeds:
            content, _ = fetch_feed_content(feed, BASE_DIR)
            self.assertIsNotNone(content, f"Failed to read feed fixture: {feed.name}")
            candidates = parse_raw_feed(content, feed.format, feed.id)

            for cand in candidates:
                ind = classify_and_normalize_ioc(cand)
                if not ind:
                    continue
                drop, _ = ioc_filter.should_suppress(ind)
                if not drop:
                    self.repo.save_parsed_indicator(ind)

                for derived in extract_derived_indicators(ind):
                    d_drop, _ = ioc_filter.should_suppress(derived)
                    if not d_drop:
                        self.repo.save_parsed_indicator(derived)

        # Correlate
        engine = CorrelationEngine(self.repo, feeds, self.config.scoring_thresholds)
        counts = engine.run_correlation()
        self.assertGreater(counts["HIGH"], 0, "Expected at least one High severity indicator from sample feeds")

        # Verify multi-source match: 185.220.101.5 should be HIGH
        high_c2 = self.repo.get_indicator_by_value("185.220.101.5")
        self.assertIsNotNone(high_c2)
        self.assertEqual(high_c2.severity.value, "HIGH")
        self.assertGreaterEqual(len(high_c2.sources), 2)

        # Test blocklist exports
        fw_path = Path(self.temp_dir.name) / "firewall.txt"
        exported_count = export_firewall_ips(self.repo.get_all_scored_indicators(), fw_path, min_severity="HIGH")
        self.assertGreater(exported_count, 0)
        self.assertTrue(fw_path.is_file())


if __name__ == "__main__":
    unittest.main()
