"""Asynchronous background pipeline job manager for non-blocking execution."""

import asyncio
from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, Optional, Tuple
import uuid

logger = logging.getLogger("ti_aggregator.pipeline_job")


class PipelineJobManager:
    """Coordinates asynchronous pipeline runs with live status tracking."""

    def __init__(self):
        self._lock = threading.Lock()
        self.job_id: Optional[str] = None
        self.status: str = "IDLE"  # "IDLE", "RUNNING", "COMPLETED", "FAILED"
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self.error: Optional[str] = None
        self.result_summary: Dict[str, Any] = {}
        self.logs: list[str] = []

    def get_status(self) -> Dict[str, Any]:
        """Returns the current state of the pipeline executor."""
        with self._lock:
            return {
                "job_id": self.job_id,
                "status": self.status,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "error": self.error,
                "summary": self.result_summary,
                "recent_logs": self.logs[-10:],
            }

    def start_job(self, config_obj: Any, enrich_high: bool = False) -> Tuple[bool, str]:
        """Initiates a background pipeline execution thread."""
        with self._lock:
            if self.status == "RUNNING":
                return False, f"Job {self.job_id} is already in progress"

            self.job_id = str(uuid.uuid4())[:8]
            self.status = "RUNNING"
            self.started_at = datetime.now(timezone.utc).isoformat()
            self.completed_at = None
            self.error = None
            self.result_summary = {}
            self.logs = [f"Pipeline run {self.job_id} queued at {self.started_at}"]

        thread = threading.Thread(
            target=self._execute_worker,
            args=(config_obj, enrich_high),
            daemon=True,
        )
        thread.start()
        return True, self.job_id

    def _execute_worker(self, config_obj: Any, enrich_high: bool) -> None:
        from src.cli import run_full_pipeline
        try:
            with self._lock:
                self.logs.append("Executing threat feed ingestion and correlation...")

            run_full_pipeline(config_obj, enrich_high=enrich_high)

            with self._lock:
                self.status = "COMPLETED"
                self.completed_at = datetime.now(timezone.utc).isoformat()
                self.logs.append(f"Pipeline completed successfully at {self.completed_at}")
        except Exception as e:
            logger.error("Background pipeline job failed: %s", e, exc_info=True)
            with self._lock:
                self.status = "FAILED"
                self.completed_at = datetime.now(timezone.utc).isoformat()
                self.error = str(e)
                self.logs.append(f"Error: {e}")


# Singleton instance
pipeline_job_manager = PipelineJobManager()
