"""Base class and result definitions for external enrichment providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from src.models import IOCType


@dataclass
class EnrichmentResult:
    provider: str
    ioc_value: str
    ioc_type: IOCType
    reputation_score: float  # 0 to 100
    is_malicious: bool
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    cached: bool = False


class EnrichmentProvider(ABC):
    """Abstract interface for external threat verification APIs."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if required credentials / environment variables are set."""
        pass

    @abstractmethod
    def enrich(self, ioc_value: str, ioc_type: IOCType) -> Optional[EnrichmentResult]:
        """Queries the provider API for reputation and risk indicators."""
        pass
