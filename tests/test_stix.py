"""Unit tests for STIX 2.1 bundle parsing and bundle export."""

import json
import tempfile
import unittest
from pathlib import Path

from src.ingestion.parsers import parse_raw_feed
from src.exports.blocklists import export_stix_bundle
from src.models import IndicatorStatus, IOCType, ScoredIndicator, Severity


class TestSTIX2(unittest.TestCase):
    def setUp(self):
        self.sample_stix = """
        {
          "type": "bundle",
          "id": "bundle--test-1",
          "spec_version": "2.1",
          "objects": [
            {
              "type": "indicator",
              "spec_version": "2.1",
              "id": "indicator--1",
              "created": "2026-10-30T10:00:00.000Z",
              "modified": "2026-10-30T10:00:00.000Z",
              "pattern": "[ipv4-addr:value = '198.51.100.77']",
              "pattern_type": "stix"
            },
            {
              "type": "indicator",
              "spec_version": "2.1",
              "id": "indicator--2",
              "created": "2026-10-30T10:00:00.000Z",
              "modified": "2026-10-30T10:00:00.000Z",
              "pattern": "[domain-name:value = 'malicious-c2.xyz']",
              "pattern_type": "stix"
            }
          ]
        }
        """

    def test_parse_stix2_bundle(self):
        candidates = parse_raw_feed(self.sample_stix, "stix", "test_stix_feed")
        self.assertEqual(len(candidates), 2)
        vals = {c.raw_value for c in candidates}
        self.assertIn("198.51.100.77", vals)
        self.assertIn("malicious-c2.xyz", vals)

    def test_export_stix2_bundle(self):
        iocs = [
            ScoredIndicator(
                ioc_id=1,
                value="198.51.100.99",
                ioc_type=IOCType.IPV4,
                first_seen="2026-10-30T00:00:00",
                last_seen="2026-10-30T00:00:00",
                occurrence_count=2,
                calculated_score=6.5,
                severity=Severity.HIGH,
                is_whitelisted=False,
                status=IndicatorStatus.ACTIVE,
                sources=["test_feed"],
            )
        ]
        with tempfile.TemporaryDirectory() as td:
            out_file = Path(td) / "bundle.json"
            exported = export_stix_bundle(iocs, out_file, min_severity="HIGH")
            self.assertEqual(exported, 1)
            self.assertTrue(out_file.is_file())

            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(data["type"], "bundle")
            self.assertEqual(data["spec_version"], "2.1")
            self.assertEqual(len(data["objects"]), 1)
            self.assertIn("198.51.100.99", data["objects"][0]["pattern"])


if __name__ == "__main__":
    unittest.main()
