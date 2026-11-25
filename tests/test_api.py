"""Unit tests for the FastAPI REST API endpoints and administrative controls."""

import unittest
from fastapi.testclient import TestClient

from src.api import app


class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_get_dashboard(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("ThreatForge", resp.text)

    def test_get_stats(self):
        resp = self.client.get("/api/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_unique_iocs", data)
        self.assertIn("breakdown_by_type", data)

    def test_get_iocs(self):
        resp = self.client.get("/api/iocs?limit=10")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_pipeline_async_run_and_status(self):
        resp = self.client.post("/api/pipeline/run")
        self.assertEqual(resp.status_code, 202)
        data = resp.json()
        self.assertIn(data["status"], ("STARTED", "ALREADY_RUNNING"))

        status_resp = self.client.get("/api/pipeline/status")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.json()
        self.assertIn("status", status_data)

    def test_feeds_and_allowlist_endpoints(self):
        # Feeds
        f_resp = self.client.get("/api/feeds")
        self.assertEqual(f_resp.status_code, 200)

        # Allowlist
        al_resp = self.client.get("/api/allowlist")
        self.assertEqual(al_resp.status_code, 200)
        self.assertIn("ips", al_resp.json())

        # Add allowlist
        add_resp = self.client.post("/api/allowlist", json={"type": "ip", "value": "192.0.2.254", "reason": "Test"})
        self.assertEqual(add_resp.status_code, 200)

        # Remove allowlist
        del_resp = self.client.delete("/api/allowlist/192.0.2.254")
        self.assertEqual(del_resp.status_code, 200)

    def test_blocklist_diff(self):
        diff_resp = self.client.get("/api/blocklists/diff")
        self.assertEqual(diff_resp.status_code, 200)
        self.assertIn("total_active", diff_resp.json())

    def test_get_stix_bundle(self):
        resp = self.client.get("/api/blocklists/stix")
        self.assertIn(resp.status_code, (200, 404))

    def test_audit_logs(self):
        resp = self.client.get("/api/audit")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)


if __name__ == "__main__":
    unittest.main()
