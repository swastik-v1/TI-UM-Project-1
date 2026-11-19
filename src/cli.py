"""Command Line Interface (CLI) for the Threat Intelligence Aggregator."""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

from src.alerting.dispatcher import WebhookDispatcher
from src.config_loader import AppConfig, BASE_DIR
from src.correlation.engine import CorrelationEngine
from src.enrichment.abuseipdb import AbuseIPDBProvider
from src.enrichment.cache import EnrichmentManager
from src.enrichment.virustotal import VirusTotalProvider
from src.exports.blocklists import (
    export_dns_domains,
    export_edr_hashes,
    export_firewall_ips,
    export_full_json,
    export_proxy_urls,
)
from src.exports.reporter import generate_threat_report
from src.ingestion.fetcher import fetch_all_feeds
from src.ingestion.parsers import parse_raw_feed
from src.normalization.derived import extract_derived_indicators
from src.normalization.extractors import classify_and_normalize_ioc
from src.normalization.filter import IOCFilter
from src.storage.database import init_db
from src.storage.repository import IOCRepository

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ti_aggregator.cli")


def run_full_pipeline(config: AppConfig, enrich_high: bool = False) -> None:
    """Executes the complete threat intelligence aggregation cycle."""
    print("=" * 70)
    print("   THREAT INTELLIGENCE AGGREGATOR - PIPELINE EXECUTION")
    print("=" * 70)

    # 1. Initialize Storage
    db_path = config.database_path
    init_db(db_path)
    repo = IOCRepository(db_path)
    print(f"[*] Initialized SQLite database at: {db_path.name}")

    # 2. Setup Filter
    ioc_filter = IOCFilter(
        safe_ips=config.safe_ips,
        safe_domains=config.safe_domains,
        suppression_rules=config.suppression_rules,
    )

    # 3. Fetch & Ingest Feeds Concurrently (Async Fetcher)
    feeds = config.get_feeds()
    total_parsed = 0
    total_suppressed = 0

    print(f"\n[+] Concurrently fetching {len(feeds)} threat feeds (async)...")
    fetched_results = fetch_all_feeds(feeds, BASE_DIR)

    for feed, content, source_desc in fetched_results:
        if not content:
            print(f"    [-] Failed to fetch feed '{feed.name}': {source_desc}")
            repo.record_feed_status(
                feed_id=feed.id,
                name=feed.name,
                source_type=feed.source_type,
                path_or_url=str(feed.path or feed.remote_url),
                format_str=feed.format,
                weight=feed.weight,
                status="FAILED",
                ioc_count=0,
            )
            continue

        raw_candidates = parse_raw_feed(content, feed.format, feed.id)
        ingested_count = 0

        for candidate in raw_candidates:
            indicator = classify_and_normalize_ioc(candidate)
            if not indicator:
                continue

            should_drop, reason = ioc_filter.should_suppress(indicator)
            if should_drop:
                total_suppressed += 1
                continue

            repo.save_parsed_indicator(indicator)
            ingested_count += 1
            total_parsed += 1

            derived_list = extract_derived_indicators(indicator)
            for derived in derived_list:
                d_drop, _ = ioc_filter.should_suppress(derived)
                if not d_drop:
                    repo.save_parsed_indicator(derived)
                    ingested_count += 1
                    total_parsed += 1

        repo.record_feed_status(
            feed_id=feed.id,
            name=feed.name,
            source_type=feed.source_type,
            path_or_url=str(feed.path or feed.remote_url),
            format_str=feed.format,
            weight=feed.weight,
            status="SUCCESS",
            ioc_count=ingested_count,
        )
        print(f"    [✓] Feed '{feed.name}': Ingested {ingested_count} indicators (Weight: {feed.weight})")

    print(f"\n[*] Total valid indicators stored: {total_parsed}")
    print(f"[*] Total false positives / bogons suppressed: {total_suppressed}")

    # 4. Correlation & Deterministic Scoring Engine with Aging/Decay
    print("\n[+] Running Correlation, Scoring & TTL Aging Engine...")
    engine = CorrelationEngine(
        repository=repo,
        feeds=feeds,
        thresholds=config.scoring_thresholds,
        retention_settings=config.retention_settings,
    )
    sev_counts = engine.run_correlation()
    print(f"    [✓] High Severity:    {sev_counts['HIGH']}")
    print(f"    [✓] Medium Severity:  {sev_counts['MEDIUM']}")
    print(f"    [✓] Low Severity:     {sev_counts['LOW']}")
    print(f"    [✓] Expired (Decayed): {sev_counts['EXPIRED']}")

    # 5. Optional Gated Enrichment
    if enrich_high:
        print("\n[+] Gated Enrichment requested for High Severity IOCs...")
        enrich_mgr = EnrichmentManager(
            repository=repo,
            providers=[AbuseIPDBProvider(), VirusTotalProvider()],
            ttl_days_map=config.cache_ttl_days,
        )
        high_iocs = repo.get_all_scored_indicators(min_severity="HIGH")
        for ioc in high_iocs[:10]:
            res = enrich_mgr.enrich_indicator(ioc.value, ioc.ioc_type)
            if res:
                print(f"    [+] Enriched {ioc.value} ({res.provider}): {res.summary}")

    # 6. Webhook Alerting
    dispatcher = WebhookDispatcher(config.webhook_settings)
    alerted = dispatcher.dispatch(repo.get_all_scored_indicators(min_severity="HIGH"))
    if alerted > 0:
        print(f"    [✓] Webhook alerts dispatched for {alerted} critical indicators.")

    # 7. Generate Blocklists
    print("\n[+] Generating Defensive Blocklists (Active IOCs only)...")
    all_scored = repo.get_all_scored_indicators(status="ACTIVE")
    paths = config.export_paths
    min_sevs = config.export_min_severities

    fw_count = export_firewall_ips(all_scored, paths["firewall_ips"], min_sevs["firewall"])
    dns_count = export_dns_domains(all_scored, paths["dns_domains"], min_sevs["dns"])
    proxy_count = export_proxy_urls(all_scored, paths["proxy_urls"], min_sevs["proxy"])
    edr_count = export_edr_hashes(all_scored, paths["edr_hashes"], min_sevs["edr"])
    json_count = export_full_json(all_scored, paths["all_json"])

    print(f"    [✓] Firewall Blocklist:  {fw_count} IPs -> {paths['firewall_ips'].name}")
    print(f"    [✓] DNS Sinkhole List:   {dns_count} Domains -> {paths['dns_domains'].name}")
    print(f"    [✓] Web Proxy Filter:    {proxy_count} URLs -> {paths['proxy_urls'].name}")
    print(f"    [✓] EDR Hash Watchlist:  {edr_count} Hashes -> {paths['edr_hashes'].name}")
    print(f"    [✓] Full JSON Feed:      {json_count} IOCs -> {paths['all_json'].name}")

    # 8. Generate Executive Report
    print("\n[+] Generating Executive Intelligence Report...")
    metrics = repo.get_metrics()
    report_file = paths["summary_report"]
    generate_threat_report(metrics, all_scored[:10], report_file)
    print(f"    [✓] Executive report generated: {report_file.name}")

    print("\n" + "=" * 70)
    print("   PIPELINE COMPLETE - BLOCKLISTS READY FOR DEPLOYMENT")
    print("=" * 70)


def cmd_lookup(config: AppConfig, ioc_val: str, enrich: bool = False) -> None:
    """Searches for an indicator in the aggregator database."""
    db_path = config.database_path
    if not db_path.is_file():
        print(f"[-] Database not found at {db_path}. Run 'python -m src.cli run' first.")
        return

    repo = IOCRepository(db_path)
    ioc = repo.get_indicator_by_value(ioc_val)
    if not ioc:
        print(f"[-] Indicator '{ioc_val}' was not found in the Threat Intelligence database.")
        return

    print("=" * 60)
    print(f"   INDICATOR DETAILS: {ioc.value}")
    print("=" * 60)
    print(f" Type:             {ioc.ioc_type.value}")
    print(f" Status:           {ioc.status.value}")
    print(f" Severity:         {ioc.severity.value}")
    print(f" Composite Score:  {ioc.calculated_score}")
    print(f" Decayed Score:    {ioc.decayed_score}")
    print(f" Occurrence Count: {ioc.occurrence_count}")
    print(f" First Seen:       {ioc.first_seen}")
    print(f" Last Seen:        {ioc.last_seen}")
    print(f" Reporting Feeds:  {', '.join(ioc.sources)}")
    if ioc.contexts:
        print(f" Raw Contexts:     {'; '.join(ioc.contexts)}")

    if enrich:
        print("\n[+] Performing live / cached external API enrichment...")
        enrich_mgr = EnrichmentManager(
            repository=repo,
            providers=[AbuseIPDBProvider(), VirusTotalProvider()],
            ttl_days_map=config.cache_ttl_days,
        )
        res = enrich_mgr.enrich_indicator(ioc.value, ioc.ioc_type)
        if res:
            print(f" Provider:         {res.provider}")
            print(f" Reputation Score: {res.reputation_score}%")
            print(f" Malicious Flag:   {res.is_malicious}")
            print(f" Summary:          {res.summary}")
            print(f" Cache Status:     {'CACHED' if res.cached else 'LIVE QUERY'}")
        else:
            print(" [-] No enrichment provider returned data (check API keys or rate limits).")


def cmd_stats(config: AppConfig) -> None:
    """Prints current database intelligence metrics."""
    db_path = config.database_path
    if not db_path.is_file():
        print(f"[-] Database not found at {db_path}. Run pipeline first.")
        return

    repo = IOCRepository(db_path)
    metrics = repo.get_metrics()

    print("=" * 60)
    print("   THREAT INTELLIGENCE AGGREGATOR - DATABASE METRICS")
    print("=" * 60)
    print(f"Total Unique Indicators: {metrics['total_unique_iocs']}")
    print("\n[Breakdown by Type]")
    for k, v in metrics["breakdown_by_type"].items():
        print(f"  {k:<12}: {v}")

    print("\n[Breakdown by Severity (Active)]")
    for k, v in metrics["breakdown_by_severity"].items():
        print(f"  {k:<12}: {v}")

    print("\n[Breakdown by Status (TTL Aging)]")
    for k, v in metrics.get("breakdown_by_status", {}).items():
        print(f"  {k:<12}: {v}")

    print("\n[Ingested Feeds]")
    for f in metrics["feeds"]:
        print(f"  - {f['name']} ({f['feed_id']}): {f['ioc_count']} IOCs (Status: {f['status']})")

    print("\n[Top 5 High-Risk Active Indicators]")
    for t in metrics["top_threats"][:5]:
        print(f"  - {t['value']} [{t['ioc_type']}] | Score: {t['calculated_score']} (Decayed: {t.get('decayed_score', t['calculated_score'])}) | Feeds: {t['feed_count']}")


def cmd_serve(config: AppConfig, host: Optional[str] = None, port: Optional[int] = None) -> None:
    """Starts the FastAPI Web Dashboard & REST API server."""
    try:
        import uvicorn
        import fastapi
    except ImportError as e:
        print("\n" + "=" * 68)
        print(" [!] Missing required packages for Web Dashboard (uvicorn / fastapi).")
        print(f"     Details: {e}")
        print("=" * 68)
        print(" You are likely running system Python instead of your project venv.")
        print("\n Option 1: Run with virtual environment activated:")
        print("     .\\.venv\\Scripts\\activate")
        print("     python -m src.cli serve")
        print("\n Option 2: Run directly using the virtualenv python binary:")
        print("     .\\.venv\\Scripts\\python.exe -m src.cli serve")
        print("\n Option 3: Install dependencies into your current Python environment:")
        print("     pip install -r requirements.txt")
        print("=" * 68 + "\n")
        sys.exit(1)

    api_cfg = config.api_settings
    h = host or api_cfg["host"]
    p = port or api_cfg["port"]
    print("=" * 68)
    print(f" [+] Threat Intelligence Web Dashboard is online!")
    print(f" [+] Open your browser at: http://{h}:{p}")
    print("=" * 68)
    uvicorn.run("src.api:app", host=h, port=p, reload=False)


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Aggregator CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Run the full ingestion, correlation, and export pipeline")
    run_parser.add_argument("--enrich", action="store_true", help="Perform gated API enrichment on high-severity IOCs")

    # Command: stats
    subparsers.add_parser("stats", help="Display summary metrics of the threat intelligence database")

    # Command: lookup
    lookup_parser = subparsers.add_parser("lookup", help="Inspect a specific indicator")
    lookup_parser.add_argument("ioc", help="Indicator string to search for (IP, Domain, URL, Hash, Email)")
    lookup_parser.add_argument("--enrich", action="store_true", help="Cross-check with external APIs")

    # Command: serve
    serve_parser = subparsers.add_parser("serve", help="Start the FastAPI REST API & Interactive Web Dashboard")
    serve_parser.add_argument("--host", default=None, help="Host address (default 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=None, help="Port number (default 8000)")

    args = parser.parse_args()
    config = AppConfig()

    if args.command == "run" or args.command is None:
        run_full_pipeline(config, enrich_high=getattr(args, "enrich", False))
    elif args.command == "stats":
        cmd_stats(config)
    elif args.command == "lookup":
        cmd_lookup(config, args.ioc, enrich=args.enrich)
    elif args.command == "serve":
        cmd_serve(config, host=args.host, port=args.port)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
