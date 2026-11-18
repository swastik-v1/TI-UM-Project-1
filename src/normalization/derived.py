"""Extracts derived indicators (e.g., domain or IP from a URL)."""

from typing import List
from urllib.parse import urlparse

from src.models import IOCType, ParsedIndicator
from src.normalization.extractors import is_valid_domain, is_valid_ip


def extract_derived_indicators(indicator: ParsedIndicator) -> List[ParsedIndicator]:
    """Derives secondary indicators (such as domain or IP) from composite types like URLs."""
    derived = []

    if indicator.ioc_type == IOCType.URL:
        try:
            parsed = urlparse(indicator.value)
            netloc = parsed.netloc

            # Strip port if present
            host = netloc.split(":")[0] if ":" in netloc else netloc
            host = host.strip("[]")

            if not host:
                return derived

            # Check if host is an IP
            ip_check = is_valid_ip(host)
            if ip_check:
                derived.append(
                    ParsedIndicator(
                        value=ip_check[1],
                        ioc_type=ip_check[0],
                        feed_id=indicator.feed_id,
                        context=f"derived_from_url:{indicator.value} | {indicator.context}",
                        timestamp=indicator.timestamp,
                    )
                )
            else:
                # Check if host is a domain
                domain_check = is_valid_domain(host)
                if domain_check:
                    derived.append(
                        ParsedIndicator(
                            value=domain_check[1],
                            ioc_type=domain_check[0],
                            feed_id=indicator.feed_id,
                            context=f"derived_from_url:{indicator.value} | {indicator.context}",
                            timestamp=indicator.timestamp,
                        )
                    )
        except Exception:
            pass

    return derived
