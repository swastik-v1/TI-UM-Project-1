"""Correlation & Scoring subsystem: multi-source consensus and risk classification."""

from src.correlation.scoring import calculate_ioc_score, classify_severity
from src.correlation.engine import CorrelationEngine

__all__ = ["calculate_ioc_score", "classify_severity", "CorrelationEngine"]
