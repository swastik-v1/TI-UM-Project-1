"""Unit tests for the asynchronous multi-feed fetcher."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from src.ingestion.fetcher import fetch_all_feeds_async, fetch_all_feeds
from src.models import FeedDefinition


class TestAsyncFetcher(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        # Create two sample feed files
        self.f1_path = self.base_dir / "feed1.txt"
        self.f1_path.write_text("185.220.101.5\n45.154.255.88", encoding="utf-8")

        self.f2_path = self.base_dir / "feed2.txt"
        self.f2_path.write_text("194.26.29.112\n91.240.118.232", encoding="utf-8")

        self.feeds = [
            FeedDefinition(id="f1", name="Feed 1", source_type="file", path="feed1.txt", format="txt"),
            FeedDefinition(id="f2", name="Feed 2", source_type="file", path="feed2.txt", format="txt"),
        ]

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_fetch_all_feeds_concurrently(self):
        results = fetch_all_feeds(self.feeds, self.base_dir)
        self.assertEqual(len(results), 2)

        feed1_res = next(r for r in results if r[0].id == "f1")
        self.assertIn("185.220.101.5", feed1_res[1])

        feed2_res = next(r for r in results if r[0].id == "f2")
        self.assertIn("194.26.29.112", feed2_res[1])


if __name__ == "__main__":
    unittest.main()
