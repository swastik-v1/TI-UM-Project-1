"""Unit tests for the FastAPI REST API endpoints."""

import unittest
from fastapi.testclient import TestClient

from src.api import app


class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_get_dashboard(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Threat Intelligence Aggregator", resp.text)

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

    def test_get_blocklist_firewall(self):
        resp = self.client.get("/api/blocklists/firewall")
        self.assertIn(resp.status_code, (200, 404))

    def test_get_unknown_blocklist(self):
        resp = self.client.get("/api/blocklists/invalid_target")
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
