"""Unit tests for the refanging utility."""

import unittest
from src.ingestion.refanger import refang


class TestRefanger(unittest.TestCase):
    def test_refang_urls(self):
        self.assertEqual(refang("hxxp://malicious[.]com/payload"), "http://malicious.com/payload")
        self.assertEqual(refang("hxxps://bad-site[.]org/login.php"), "https://bad-site.org/login.php")
        self.assertEqual(refang("hXXp://test[.]xyz"), "http://test.xyz")

    def test_refang_ips(self):
        self.assertEqual(refang("192[.]168[.]1[.]1"), "192.168.1.1")
        self.assertEqual(refang("10(.)0(.)0(.)1"), "10.0.0.1")
        self.assertEqual(refang("[185.220.101.5]"), "185.220.101.5")

    def test_refang_emails(self):
        self.assertEqual(refang("attacker[@]phish[.]net"), "attacker@phish.net")
        self.assertEqual(refang("ceo[at]company(dot)com"), "ceo@company.com")

    def test_clean_string(self):
        self.assertEqual(refang("8.8.8.8"), "8.8.8.8")
        self.assertEqual(refang(""), "")
        self.assertEqual(refang(None), "")


if __name__ == "__main__":
    unittest.main()
