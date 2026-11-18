"""Syntactic extractors and validators for all core IOC types."""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from src.models import IOCType, ParsedIndicator, RawCandidate
from src.ingestion.refanger import refang

# Regex patterns
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_EMAIL = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def is_valid_ip(val: str) -> Optional[Tuple[IOCType, str]]:
    """Checks if the string is a valid IPv4 or IPv6 address."""
    # Strip port if present for IPv4 (e.g. 1.2.3.4:8080)
    cleaned = val
    if ":" in cleaned and not cleaned.startswith("[") and cleaned.count(":") == 1:
        host, _, _ = cleaned.partition(":")
        cleaned = host

    try:
        ip = ipaddress.ip_address(cleaned)
        if isinstance(ip, ipaddress.IPv4Address):
            return IOCType.IPV4, str(ip)
        elif isinstance(ip, ipaddress.IPv6Address):
            return IOCType.IPV6, str(ip)
    except ValueError:
        pass
    return None


def is_valid_hash(val: str) -> Optional[Tuple[IOCType, str]]:
    """Checks if string is an MD5, SHA-1, or SHA-256 hash."""
    v = val.lower().strip()
    if RE_SHA256.match(v):
        return IOCType.HASH_SHA256, v
    if RE_SHA1.match(v):
        return IOCType.HASH_SHA1, v
    if RE_MD5.match(v):
        return IOCType.HASH_MD5, v
    return None


def is_valid_email(val: str) -> Optional[Tuple[IOCType, str]]:
    v = val.lower().strip()
    if RE_EMAIL.match(v):
        return IOCType.EMAIL, v
    return None


def is_valid_url(val: str) -> Optional[Tuple[IOCType, str]]:
    v = val.strip()
    if not (v.startswith("http://") or v.startswith("https://") or v.startswith("ftp://")):
        return None

    try:
        parsed = urlparse(v)
        if parsed.scheme and parsed.netloc:
            # Canonicalize: lowercase scheme and host, keep path
            canonical = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
            if parsed.query:
                canonical += f"?{parsed.query}"
            return IOCType.URL, canonical
    except Exception:
        pass
    return None


def is_valid_domain(val: str) -> Optional[Tuple[IOCType, str]]:
    v = val.lower().strip().rstrip(".")
    # Avoid classifying file names with extensions (e.g., payload.exe, loader.dll) as domains
    common_file_exts = {
        "exe", "dll", "zip", "rar", "7z", "tar", "gz", "ps1", "sh", "bat", "vbs",
        "iso", "bin", "elf", "pdf", "docx", "xlsx", "txt", "tmp"
    }
    tld = v.rsplit(".", 1)[-1]
    if tld in common_file_exts:
        return None

    if RE_DOMAIN.match(v):
        return IOCType.DOMAIN, v
    return None


def classify_and_normalize_ioc(candidate: RawCandidate) -> Optional[ParsedIndicator]:
    """Refangs and identifies the IOC type and canonical string value."""
    refanged_val = refang(candidate.raw_value)
    if not refanged_val:
        return None

    # 1. Check IP address
    ip_result = is_valid_ip(refanged_val)
    if ip_result:
        return ParsedIndicator(
            value=ip_result[1],
            ioc_type=ip_result[0],
            feed_id=candidate.feed_id,
            context=candidate.context,
            timestamp=candidate.timestamp,
        )

    # 2. Check Hashes
    hash_result = is_valid_hash(refanged_val)
    if hash_result:
        return ParsedIndicator(
            value=hash_result[1],
            ioc_type=hash_result[0],
            feed_id=candidate.feed_id,
            context=candidate.context,
            timestamp=candidate.timestamp,
        )

    # 3. Check Email
    email_result = is_valid_email(refanged_val)
    if email_result:
        return ParsedIndicator(
            value=email_result[1],
            ioc_type=email_result[0],
            feed_id=candidate.feed_id,
            context=candidate.context,
            timestamp=candidate.timestamp,
        )

    # 4. Check URL
    url_result = is_valid_url(refanged_val)
    if url_result:
        return ParsedIndicator(
            value=url_result[1],
            ioc_type=url_result[0],
            feed_id=candidate.feed_id,
            context=candidate.context,
            timestamp=candidate.timestamp,
        )

    # 5. Check Domain
    domain_result = is_valid_domain(refanged_val)
    if domain_result:
        return ParsedIndicator(
            value=domain_result[1],
            ioc_type=domain_result[0],
            feed_id=candidate.feed_id,
            context=candidate.context,
            timestamp=candidate.timestamp,
        )

    return None
