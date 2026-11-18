"""Unit tests for syntactic IOC extractors and classifiers."""

import unittest
from src.models import IOCType, RawCandidate
from src.normalization.extractors import classify_and_normalize_ioc


class TestExtractors(unittest.TestCase):
    def test_classify_ipv4(self):
        c = RawCandidate(raw_value="185.220.101.5", feed_id="test")
        res = classify_and_normalize_ioc(c)
        self.assertIsNotNone(res)
        self.assertEqual(res.ioc_type, IOCType.IPV4)
        self.assertEqual(res.value, "185.220.101.5")

    def test_classify_defanged_ipv4_with_port(self):
        c = RawCandidate(raw_value="185[.]220[.]101[.]5:8080", feed_id="test")
        res = classify_and_normalize_ioc(c)
        self.assertIsNotNone(res)
        self.assertEqual(res.ioc_type, IOCType.IPV4)
        self.assertEqual(res.value, "185.220.101.5")

    def test_classify_hashes(self):
        # MD5
        c_md5 = RawCandidate(raw_value="d41d8cd98f00b204e9800998ecf8427e", feed_id="test")
        res_md5 = classify_and_normalize_ioc(c_md5)
        self.assertEqual(res_md5.ioc_type, IOCType.HASH_MD5)

        # SHA256
        c_sha256 = RawCandidate(raw_value="E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", feed_id="test")
        res_sha256 = classify_and_normalize_ioc(c_sha256)
        self.assertEqual(res_sha256.ioc_type, IOCType.HASH_SHA256)
        self.assertEqual(res_sha256.value, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_classify_url(self):
        c = RawCandidate(raw_value="hxxp://evil-payload[.]top/loader.exe", feed_id="test")
        res = classify_and_normalize_ioc(c)
        self.assertIsNotNone(res)
        self.assertEqual(res.ioc_type, IOCType.URL)
        self.assertEqual(res.value, "http://evil-payload.top/loader.exe")

    def test_classify_domain(self):
        c = RawCandidate(raw_value="evil-c2[.]xyz", feed_id="test")
        res = classify_and_normalize_ioc(c)
        self.assertIsNotNone(res)
        self.assertEqual(res.ioc_type, IOCType.DOMAIN)
        self.assertEqual(res.value, "evil-c2.xyz")

    def test_reject_filename_as_domain(self):
        c = RawCandidate(raw_value="malware.exe", feed_id="test")
        res = classify_and_normalize_ioc(c)
        self.assertIsNone(res)

    def test_classify_email(self):
        c = RawCandidate(raw_value="phisher[@]evil-bank[.]com", feed_id="test")
        res = classify_and_normalize_ioc(c)
        self.assertIsNotNone(res)
        self.assertEqual(res.ioc_type, IOCType.EMAIL)
        self.assertEqual(res.value, "phisher@evil-bank.com")


if __name__ == "__main__":
    unittest.main()
