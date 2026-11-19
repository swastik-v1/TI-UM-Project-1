"""Alerting and notification subsystem for SIEM and SOC webhooks."""

from src.alerting.dispatcher import WebhookDispatcher

__all__ = ["WebhookDispatcher"]
