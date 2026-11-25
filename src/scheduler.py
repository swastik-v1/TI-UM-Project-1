"""Background scheduler worker to periodically trigger threat intelligence aggregation."""

import logging
import signal
import sys
import time
from src.config_loader import AppConfig

logger = logging.getLogger("ti_aggregator.scheduler")

_running = True


def _handle_exit(signum, frame):
    global _running
    logger.info("Received termination signal %d. Shutting down scheduler gracefully...", signum)
    _running = False


def run_scheduler_loop(config: AppConfig, interval_minutes: int = 60) -> None:
    """Runs periodic pipeline execution loop until stopped."""
    from src.cli import run_full_pipeline

    global _running
    signal.signal(signal.SIGINT, _handle_exit)
    signal.signal(signal.SIGTERM, _handle_exit)

    interval_seconds = max(60, interval_minutes * 60)
    print("=" * 65)
    print("   THREAT INTELLIGENCE AGGREGATOR - BACKGROUND SCHEDULER")
    print("=" * 65)
    print(f"[*] Scheduler active. Polling interval: every {interval_minutes} minutes ({interval_seconds}s).")
    print("[*] Press Ctrl+C to terminate.")

    # Run initial pipeline execution immediately on startup
    try:
        logger.info("Running initial startup ingestion...")
        run_full_pipeline(config, enrich_high=False)
    except Exception as e:
        logger.error("Error during initial pipeline execution: %s", e)

    while _running:
        logger.info("Sleeping for %d seconds until next aggregation cycle...", interval_seconds)
        # Sleep in short increments to respond quickly to shutdown signals
        for _ in range(interval_seconds):
            if not _running:
                break
            time.sleep(1)

        if not _running:
            break

        try:
            logger.info("Triggering scheduled aggregation cycle...")
            run_full_pipeline(config, enrich_high=False)
        except Exception as e:
            logger.error("Scheduled pipeline cycle failed: %s", e)

    print("\n[*] Scheduler worker has stopped.")


if __name__ == "__main__":
    cfg = AppConfig()
    run_scheduler_loop(cfg, interval_minutes=60)
