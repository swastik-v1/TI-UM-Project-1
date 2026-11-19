"""Configuration loader for Threat Intelligence Aggregator."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from src.models import FeedDefinition

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"


def load_yaml(file_path: Path) -> Dict[str, Any]:
    """Safely loads a YAML file, returning an empty dict if not found."""
    if not file_path.is_file():
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
        except yaml.YAMLError:
            return {}


class AppConfig:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or CONFIG_DIR
        self.feeds_data = load_yaml(self.config_dir / "feeds.yaml")
        self.allowlist_data = load_yaml(self.config_dir / "allowlist.yaml")
        self.settings_data = load_yaml(self.config_dir / "settings.yaml")

    def get_feeds(self) -> List[FeedDefinition]:
        """Parses feed configurations into FeedDefinition instances."""
        feed_list = []
        raw_feeds = self.feeds_data.get("feeds", [])
        for f in raw_feeds:
            feed_list.append(
                FeedDefinition(
                    id=f.get("id", ""),
                    name=f.get("name", "Unnamed Feed"),
                    source_type=f.get("source_type", "file"),
                    path=f.get("path"),
                    remote_url=f.get("remote_url"),
                    format=f.get("format", "txt").lower(),
                    weight=float(f.get("weight", 1.0)),
                    description=f.get("description", ""),
                )
            )
        return feed_list

    @property
    def suppression_rules(self) -> Dict[str, bool]:
        return self.allowlist_data.get("suppression", {
            "filter_rfc1918_private_ips": True,
            "filter_loopback": True,
            "filter_multicast": True,
            "filter_link_local": True,
        })

    @property
    def safe_ips(self) -> set[str]:
        return set(self.allowlist_data.get("safe_ips", []))

    @property
    def safe_domains(self) -> set[str]:
        return {d.lower().strip() for d in self.allowlist_data.get("safe_domains", [])}

    @property
    def database_path(self) -> Path:
        db_rel = self.settings_data.get("database", {}).get("path", "data/ti_aggregator.db")
        return BASE_DIR / db_rel

    @property
    def scoring_thresholds(self) -> Dict[str, float]:
        scoring = self.settings_data.get("scoring", {})
        return {
            "threshold_medium": float(scoring.get("threshold_medium", 3.0)),
            "threshold_high": float(scoring.get("threshold_high", 6.0)),
            "overlap_bonus_two_sources": float(scoring.get("overlap_bonus_two_sources", 1.5)),
            "overlap_bonus_three_plus": float(scoring.get("overlap_bonus_three_plus", 3.0)),
        }

    @property
    def retention_settings(self) -> Dict[str, Any]:
        retention = self.settings_data.get("retention", {})
        return {
            "enabled": retention.get("enabled", True),
            "retention_days": int(retention.get("retention_days", 30)),
            "decay_scores": retention.get("decay_scores", True),
            "archive_expired": retention.get("archive_expired", True),
        }

    @property
    def webhook_settings(self) -> Dict[str, Any]:
        hooks = self.settings_data.get("webhooks", {})
        return {
            "enabled": hooks.get("enabled", False) or bool(os.getenv("WEBHOOK_URL")),
            "service_type": hooks.get("service_type", "generic").lower(),
            "url": os.getenv("WEBHOOK_URL") or hooks.get("url", ""),
            "min_severity": hooks.get("min_severity", "HIGH").upper(),
            "min_sources": int(hooks.get("min_sources", 2)),
        }

    @property
    def api_settings(self) -> Dict[str, Any]:
        api = self.settings_data.get("api", {})
        return {
            "host": api.get("host", "127.0.0.1"),
            "port": int(api.get("port", 8000)),
        }

    @property
    def export_paths(self) -> Dict[str, Path]:
        exports = self.settings_data.get("exports", {})
        return {
            "firewall_ips": BASE_DIR / exports.get("firewall_ips", "exports/blocklist_firewall.txt"),
            "dns_domains": BASE_DIR / exports.get("dns_domains", "exports/blocklist_dns.txt"),
            "proxy_urls": BASE_DIR / exports.get("proxy_urls", "exports/blocklist_proxy.txt"),
            "edr_hashes": BASE_DIR / exports.get("edr_hashes", "exports/blocklist_edr.csv"),
            "all_json": BASE_DIR / exports.get("all_json", "exports/threat_intel_full.json"),
            "summary_report": BASE_DIR / exports.get("summary_report", "exports/threat_report.md"),
        }

    @property
    def export_min_severities(self) -> Dict[str, str]:
        exports = self.settings_data.get("exports", {})
        return {
            "firewall": exports.get("min_severity_for_firewall", "HIGH").upper(),
            "dns": exports.get("min_severity_for_dns", "HIGH").upper(),
            "proxy": exports.get("min_severity_for_proxy", "MEDIUM").upper(),
            "edr": exports.get("min_severity_for_edr", "MEDIUM").upper(),
        }

    @property
    def cache_ttl_days(self) -> Dict[str, int]:
        enrich = self.settings_data.get("enrichment", {})
        return {
            "ip": int(enrich.get("cache_ttl_ip_days", 3)),
            "domain": int(enrich.get("cache_ttl_domain_days", 7)),
            "hash": int(enrich.get("cache_ttl_hash_days", 30)),
        }
