"""Webhook notification dispatcher supporting Slack, Microsoft Teams, and Generic SIEM endpoints."""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import requests

from src.models import IndicatorStatus, ScoredIndicator

logger = logging.getLogger("ti_aggregator.alerting")


class WebhookDispatcher:
    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get("enabled", False)
        self.url = config.get("url", "").strip()
        self.service_type = config.get("service_type", "generic").lower()
        self.min_severity = config.get("min_severity", "HIGH").upper()
        self.min_sources = int(config.get("min_sources", 2))

    def format_slack_payload(self, indicators: List[ScoredIndicator]) -> Dict[str, Any]:
        """Formats alert using Slack Block Kit."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 Threat Intelligence Alert: High-Risk Consensus Indicators",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Identified {len(indicators)} verified threats* appearing across multiple feeds with critical severity ratings.",
                },
            },
            {"type": "divider"},
        ]

        for ioc in indicators[:5]:  # limit to top 5 in alert preview
            sources_str = ", ".join(f"`{s}`" for s in ioc.sources)
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Indicator:*\n`{ioc.value}`"},
                    {"type": "mrkdwn", "text": f"*Type:*\n{ioc.ioc_type.value}"},
                    {"type": "mrkdwn", "text": f"*Composite Score:*\n*{ioc.calculated_score}* ({ioc.severity.value})"},
                    {"type": "mrkdwn", "text": f"*Sources:*\n{sources_str}"},
                ],
            })

        return {"blocks": blocks}

    def format_teams_payload(self, indicators: List[ScoredIndicator]) -> Dict[str, Any]:
        """Formats alert using Microsoft Teams MessageCard format."""
        facts = []
        for ioc in indicators[:5]:
            sources_str = ", ".join(ioc.sources)
            facts.append({"name": f"{ioc.ioc_type.value.upper()}: {ioc.value}", "value": f"Score {ioc.calculated_score} | Feeds: {sources_str}"})

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "D63031",
            "summary": "High-Risk Threat Intelligence Consensus Alert",
            "sections": [
                {
                    "activityTitle": "🚨 High-Risk Threat Intelligence Consensus Alert",
                    "activitySubtitle": f"{len(indicators)} indicators identified with multi-feed consensus",
                    "facts": facts,
                    "markdown": True,
                }
            ],
        }

    def format_generic_payload(self, indicators: List[ScoredIndicator]) -> Dict[str, Any]:
        """Formats alert as standard structured JSON for SIEM/SOAR/Discord ingestion."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": "HIGH_SEVERITY_THREAT_CONSENSUS",
            "count": len(indicators),
            "threats": [
                {
                    "value": ioc.value,
                    "type": ioc.ioc_type.value,
                    "score": ioc.calculated_score,
                    "severity": ioc.severity.value,
                    "sources": ioc.sources,
                    "first_seen": ioc.first_seen,
                    "last_seen": ioc.last_seen,
                }
                for ioc in indicators
            ],
        }

    def dispatch(self, indicators: List[ScoredIndicator]) -> int:
        """Filters indicators meeting criteria and dispatches alerts.

        Returns:
            Number of alerted indicators (0 if skipped or failed).
        """
        if not self.enabled:
            logger.debug("Webhook dispatcher is disabled; skipping.")
            return 0

        if not self.url:
            logger.warning("Webhook URL is empty; cannot dispatch alerts.")
            return 0

        # Filter candidates: matching severity, active status, and source threshold
        qualifying = [
            ioc for ioc in indicators
            if ioc.severity.value == self.min_severity
            and len(ioc.sources) >= self.min_sources
            and ioc.status == IndicatorStatus.ACTIVE
            and not ioc.is_whitelisted
        ]

        if not qualifying:
            logger.info("No indicators met webhook alert criteria (min_severity=%s, min_sources=%d).", self.min_severity, self.min_sources)
            return 0

        # Format payload
        if self.service_type == "slack":
            payload = self.format_slack_payload(qualifying)
        elif self.service_type == "teams":
            payload = self.format_teams_payload(qualifying)
        else:
            payload = self.format_generic_payload(qualifying)

        try:
            logger.info("Dispatching alert for %d high-severity threats to webhook (%s)...", len(qualifying), self.service_type)
            headers = {"Content-Type": "application/json"}
            resp = requests.post(self.url, data=json.dumps(payload), headers=headers, timeout=5)
            if resp.status_code in (200, 201, 204):
                logger.info("Webhook alert successfully delivered (HTTP %d).", resp.status_code)
                return len(qualifying)
            else:
                logger.warning("Webhook endpoint returned unexpected status %d: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            logger.error("Failed to deliver webhook alert: %s", e)

        return 0
