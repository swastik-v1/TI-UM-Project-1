"""Data models and enumerated types for the Threat Intelligence Aggregator."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set


def get_current_utc():
    return datetime.now(timezone.utc)


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class FeedDefinition:
    id: str
    name: str
    source_type: str  # "file" or "url"
    path: Optional[str] = None
    remote_url: Optional[str] = None
    format: str = "txt"  # "csv", "json", "txt"
    weight: float = 1.0
    description: str = ""


@dataclass
class RawCandidate:
    """An unparsed string extracted from a raw feed line or record."""
    raw_value: str
    feed_id: str
    context: str = ""
    timestamp: datetime = field(default_factory=get_current_utc)


@dataclass
class ParsedIndicator:
    """A syntactically valid and refanged indicator before normalization/filtering."""
    value: str
    ioc_type: IOCType
    feed_id: str
    context: str = ""
    timestamp: datetime = field(default_factory=get_current_utc)


@dataclass
class ScoredIndicator:
    """A normalized, cross-correlated indicator stored in the database."""
    ioc_id: Optional[int]
    value: str
    ioc_type: IOCType
    first_seen: str
    last_seen: str
    occurrence_count: int
    calculated_score: float
    severity: Severity
    is_whitelisted: bool
    sources: List[str] = field(default_factory=list)
    contexts: List[str] = field(default_factory=list)
