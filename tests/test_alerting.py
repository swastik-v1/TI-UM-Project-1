"""Unit tests for the webhook alerting subsystem."""

import unittest
from src.alerting.dispatcher import WebhookDispatcher
from src.models import IndicatorStatus, IOCType, ScoredIndicator, Severity


class TestWebhookAlerting(unittest.TestCase):
    def setUp(self):
        self.qualifying_ioc = ScoredIndicator(
            ioc_id=1,
            value="185.220.101.5",
            ioc_type=IOCType.IPV4,
            first_seen="2026-11-01",
            last_seen="2026-11-19",
            occurrence_count=4,
            calculated_score=26.0,
            severity=Severity.HIGH,
            is_whitelisted=False,
            status=IndicatorStatus.ACTIVE,
            sources=["feodo_tracker", "blocklist_de", "internal_soc"],
        )
        self.low_ioc = ScoredIndicator(
            ioc_id=2,
            value="198.51.100.2",
            ioc_type=IOCType.IPV4,
            first_seen="2026-11-01",
            last_seen="2026-11-19",
            occurrence_count=1,
            calculated_score=2.0,
            severity=Severity.LOW,
            is_whitelisted=False,
            status=IndicatorStatus.ACTIVE,
            sources=["single_feed"],
        )

    def test_disabled_by_default(self):
        disp = WebhookDispatcher({"enabled": False, "url": ""})
        dispatched = disp.dispatch([self.qualifying_ioc])
        self.assertEqual(dispatched, 0)

    def test_format_slack(self):
        disp = WebhookDispatcher({"enabled": True, "service_type": "slack"})
        payload = disp.format_slack_payload([self.qualifying_ioc])
        self.assertIn("blocks", payload)
        self.assertGreater(len(payload["blocks"]), 0)

    def test_format_teams(self):
        disp = WebhookDispatcher({"enabled": True, "service_type": "teams"})
        payload = disp.format_teams_payload([self.qualifying_ioc])
        self.assertEqual(payload["@type"], "MessageCard")
        self.assertIn("sections", payload)

    def test_format_generic(self):
        disp = WebhookDispatcher({"enabled": True, "service_type": "generic"})
        payload = disp.format_generic_payload([self.qualifying_ioc])
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["threats"][0]["value"], "185.220.101.5")


if __name__ == "__main__":
    unittest.main()
