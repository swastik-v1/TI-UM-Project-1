"""Filter to suppress false positives: RFC 1918 bogons, loopbacks, and allowlisted entities."""

import ipaddress
import logging
from typing import Set, Tuple
from urllib.parse import urlparse

from src.models import IOCType, ParsedIndicator

logger = logging.getLogger("ti_aggregator.filter")


class IOCFilter:
    def __init__(self, safe_ips: Set[str], safe_domains: Set[str], suppression_rules: dict):
        self.safe_ips = set(safe_ips)
        self.safe_domains = {d.lower().strip() for d in safe_domains}
        self.filter_rfc1918 = suppression_rules.get("filter_rfc1918_private_ips", True)
        self.filter_loopback = suppression_rules.get("filter_loopback", True)
        self.filter_multicast = suppression_rules.get("filter_multicast", True)
        self.filter_link_local = suppression_rules.get("filter_link_local", True)

    def add_safe_ip(self, ip_str: str) -> None:
        self.safe_ips.add(ip_str.strip())

    def add_safe_domain(self, domain_str: str) -> None:
        self.safe_domains.add(domain_str.lower().strip())

    def is_bogon_ip(self, ip_str: str) -> Tuple[bool, str]:
        """Checks if an IP address belongs to private/bogon ranges."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if self.filter_loopback and ip.is_loopback:
                return True, "bogon:loopback"
            if self.filter_rfc1918 and ip.is_private:
                return True, "bogon:private_rfc1918"
            if self.filter_multicast and ip.is_multicast:
                return True, "bogon:multicast"
            if self.filter_link_local and ip.is_link_local:
                return True, "bogon:link_local"
            if ip.is_reserved:
                return True, "bogon:reserved"
            if ip.is_unspecified:
                return True, "bogon:unspecified"
        except ValueError:
            return True, "invalid_ip_format"
        return False, ""

    def is_safe_domain(self, domain_str: str) -> bool:
        """Checks domain or root domain against allowlisted safe domains."""
        domain_lower = domain_str.lower().strip()
        if domain_lower in self.safe_domains:
            return True
        # Check parent domain suffix (e.g. upload.google.com -> google.com)
        parts = domain_lower.split(".")
        if len(parts) > 2:
            root_domain = ".".join(parts[-2:])
            if root_domain in self.safe_domains:
                return True
        return False

    def should_suppress(self, indicator: ParsedIndicator) -> Tuple[bool, str]:
        """Evaluates whether an indicator should be rejected or suppressed.

        Returns:
            (should_drop, reason)
        """
        # IP checks
        if indicator.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            if indicator.value in self.safe_ips:
                return True, "allowlist:safe_ip"
            is_bogon, reason = self.is_bogon_ip(indicator.value)
            if is_bogon:
                return True, reason

        # Domain checks
        elif indicator.ioc_type == IOCType.DOMAIN:
            if self.is_safe_domain(indicator.value):
                return True, "allowlist:safe_domain"

        # URL checks
        elif indicator.ioc_type == IOCType.URL:
            try:
                host = urlparse(indicator.value).netloc.split(":")[0].strip("[]").lower()
                if host in self.safe_ips:
                    return True, "allowlist:safe_url_ip"
                if self.is_safe_domain(host):
                    return True, "allowlist:safe_url_domain"
                # Check if host in URL is a private IP
                is_bogon, reason = self.is_bogon_ip(host)
                if is_bogon and reason != "invalid_ip_format":
                    return True, f"url_host_{reason}"
            except Exception:
                pass

        # Email checks
        elif indicator.ioc_type == IOCType.EMAIL:
            _, _, domain_part = indicator.value.partition("@")
            if self.is_safe_domain(domain_part):
                return True, "allowlist:safe_email_domain"

        return False, ""
