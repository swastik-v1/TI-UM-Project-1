"""Unit tests for bogon suppression and allowlisting."""

import unittest
from src.models import IOCType, ParsedIndicator
from src.normalization.filter import IOCFilter


class TestIOCFilter(unittest.TestCase):
    def setUp(self):
        self.safe_ips = {"8.8.8.8", "1.1.1.1"}
        self.safe_domains = {"google.com", "microsoft.com"}
        self.rules = {
            "filter_rfc1918_private_ips": True,
            "filter_loopback": True,
            "filter_multicast": True,
            "filter_link_local": True,
        }
        self.filter = IOCFilter(self.safe_ips, self.safe_domains, self.rules)

    def test_rfc1918_suppression(self):
        # 10.0.0.1
        ind_10 = ParsedIndicator(value="10.0.0.1", ioc_type=IOCType.IPV4, feed_id="test")
        drop, reason = self.filter.should_suppress(ind_10)
        self.assertTrue(drop)
        self.assertIn("rfc1918", reason)

        # 192.168.1.100
        ind_192 = ParsedIndicator(value="192.168.1.100", ioc_type=IOCType.IPV4, feed_id="test")
        drop, reason = self.filter.should_suppress(ind_192)
        self.assertTrue(drop)

        # Loopback 127.0.0.1
        ind_loop = ParsedIndicator(value="127.0.0.1", ioc_type=IOCType.IPV4, feed_id="test")
        drop, reason = self.filter.should_suppress(ind_loop)
        self.assertTrue(drop)
        self.assertIn("loopback", reason)

    def test_safe_ip_allowlist(self):
        ind = ParsedIndicator(value="8.8.8.8", ioc_type=IOCType.IPV4, feed_id="test")
        drop, reason = self.filter.should_suppress(ind)
        self.assertTrue(drop)
        self.assertEqual(reason, "allowlist:safe_ip")

    def test_safe_domain_allowlist(self):
        ind = ParsedIndicator(value="google.com", ioc_type=IOCType.DOMAIN, feed_id="test")
        drop, reason = self.filter.should_suppress(ind)
        self.assertTrue(drop)
        self.assertEqual(reason, "allowlist:safe_domain")

        # Subdomain match
        ind_sub = ParsedIndicator(value="drive.google.com", ioc_type=IOCType.DOMAIN, feed_id="test")
        drop, reason = self.filter.should_suppress(ind_sub)
        self.assertTrue(drop)

    def test_valid_public_malicious_ip_passes(self):
        ind = ParsedIndicator(value="185.220.101.5", ioc_type=IOCType.IPV4, feed_id="test")
        drop, reason = self.filter.should_suppress(ind)
        self.assertFalse(drop)


if __name__ == "__main__":
    unittest.main()
