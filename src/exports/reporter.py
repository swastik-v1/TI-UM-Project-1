"""Threat Intelligence Executive Report Generator (Markdown & Plaintext)."""

from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any, Dict, List

from src.models import ScoredIndicator

logger = logging.getLogger("ti_aggregator.reporter")


def generate_threat_report(
    metrics: Dict[str, Any],
    top_indicators: List[ScoredIndicator],
    output_path: Path,
) -> str:
    """Generates an executive threat intelligence summary report in Markdown."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    total_iocs = metrics.get("total_unique_iocs", 0)
    by_type = metrics.get("breakdown_by_type", {})
    by_sev = metrics.get("breakdown_by_severity", {})
    feeds = metrics.get("feeds", [])

    lines = [
        "# Threat Intelligence Aggregator - Executive Intelligence Report",
        "",
        f"**Generated:** {generated_time}  ",
        f"**Pipeline Mode:** Rules-Based Deterministic (No AI/ML)  ",
        f"**Database:** Embedded SQLite Engine",
        "",
        "---",
        "",
        "## 1. Executive Summary & Key Metrics",
        "",
        f"During this aggregation cycle, the Threat Intelligence Aggregator parsed, normalized, and correlated indicators across all configured internal and external threat feeds.",
        "",
        f"- **Total Unique Indicators of Compromise (IOCs):** `{total_iocs}`",
        f"- **High Severity Indicators (Active Block Candidates):** `{by_sev.get('HIGH', 0)}`",
        f"- **Medium Severity Indicators (Watchlist / Monitoring):** `{by_sev.get('MEDIUM', 0)}`",
        f"- **Low Severity Indicators (Single-Source / Hunting):** `{by_sev.get('LOW', 0)}`",
        "",
        "### Indicator Breakdown by Type",
        "| IOC Type | Indicator Count | Share of Total |",
        "| :--- | :--- | :--- |",
    ]

    for ioc_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total_iocs * 100) if total_iocs > 0 else 0.0
        lines.append(f"| `{ioc_type}` | {count} | {pct:.1f}% |")

    lines.extend([
        "",
        "---",
        "",
        "## 2. Ingested Feed Processing Status",
        "",
        "| Feed ID | Feed Name | Source Type | Weight | Status | Indicators Ingested |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for f in feeds:
        lines.append(
            f"| `{f.get('feed_id')}` | {f.get('name')} | `{f.get('source_type', 'file')}` | {f.get('weight')} | **{f.get('status')}** | {f.get('ioc_count', 0)} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Top High-Risk Recurring Threats (Multi-Source Consensus)",
        "",
        "The following indicators demonstrated high cross-feed overlap or appeared in authoritative threat feeds. These represent verified adversarial infrastructure recommended for perimeter enforcement.",
        "",
        "| Indicator Value | Type | Calculated Score | Severity | Sources (Feeds) | Context / Tags |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    if not top_indicators:
        lines.append("| *No high-priority indicators found* | - | - | - | - | - |")
    else:
        for ioc in top_indicators[:10]:
            sources_str = ", ".join(f"`{s}`" for s in ioc.sources) if ioc.sources else "N/A"
            ctx_summary = "; ".join(ioc.contexts[:2]) if ioc.contexts else "N/A"
            if len(ctx_summary) > 60:
                ctx_summary = ctx_summary[:57] + "..."
            lines.append(
                f"| `{ioc.value}` | `{ioc.ioc_type.value}` | **{ioc.calculated_score}** | **{ioc.severity.value}** | {sources_str} | {ctx_summary} |"
            )

    lines.extend([
        "",
        "---",
        "",
        "## 4. Automated Defensive Blocklists Generated",
        "",
        "The following ready-to-deploy blocklists have been generated in the `exports/` directory:",
        "",
        "1. **Perimeter Firewall Blocklist:** `exports/blocklist_firewall.txt` (Drop list for edge firewalls & iptables)",
        "2. **DNS Sinkhole / RPZ List:** `exports/blocklist_dns.txt` (Pi-hole, Bind RPZ, and Unbound sinks)",
        "3. **Web Proxy Egress Filter:** `exports/blocklist_proxy.txt` (Squid / SWG malicious URL blocklist)",
        "4. **EDR / AV Hash Watchlist:** `exports/blocklist_edr.csv` (File hash hunting and containment rules)",
        "5. **Complete SIEM Export:** `exports/threat_intel_full.json` (Structured JSON for SOAR playbooks)",
        "",
        "> [!TIP]",
        "> High severity blocklists should be configured with automated cron or scheduled polling (e.g. every 1-4 hours) to keep defensive perimeter policies synchronized with emerging threats.",
        "",
    ])

    report_content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    logger.info("Threat intelligence report written to %s", output_path)
    return report_content
