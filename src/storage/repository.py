"""Database repository handling CRUD operations, upserts, aging, and analytics."""

from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import sqlite3

from src.models import IOCType, IndicatorStatus, ParsedIndicator, ScoredIndicator, Severity
from src.storage.database import get_db_connection


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IOCRepository:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def record_feed_status(
        self,
        feed_id: str,
        name: str,
        source_type: str,
        path_or_url: str,
        format_str: str,
        weight: float,
        status: str,
        ioc_count: int,
    ) -> None:
        """Records feed metadata and execution status."""
        now = utc_now_iso()
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO feeds (feed_id, name, source_type, path_or_url, format, weight, last_fetched, status, ioc_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(feed_id) DO UPDATE SET
                    name = excluded.name,
                    source_type = excluded.source_type,
                    path_or_url = excluded.path_or_url,
                    format = excluded.format,
                    last_fetched = excluded.last_fetched,
                    status = excluded.status,
                    ioc_count = excluded.ioc_count,
                    weight = excluded.weight
                """,
                (feed_id, name, source_type, path_or_url, format_str, weight, now, status, ioc_count),
            )
            conn.commit()

    def ensure_feed_exists(self, feed_id: str, feed_name: Optional[str] = None) -> None:
        """Ensures a feed row exists so foreign key references are valid."""
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO feeds (feed_id, name, source_type, path_or_url, format, weight)
                VALUES (?, ?, 'feed', '', 'txt', 1.0)
                ON CONFLICT(feed_id) DO NOTHING
                """,
                (feed_id, feed_name or feed_id),
            )
            conn.commit()

    def save_parsed_indicator(self, indicator: ParsedIndicator) -> int:
        """Upserts a parsed indicator and links it to its reporting feed.

        Returns:
            ioc_id (int)
        """
        now_str = indicator.timestamp.isoformat()
        self.ensure_feed_exists(indicator.feed_id)

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO iocs (value, ioc_type, first_seen, last_seen, occurrence_count, status)
                VALUES (?, ?, ?, ?, 1, 'ACTIVE')
                ON CONFLICT(value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    occurrence_count = iocs.occurrence_count + 1,
                    status = 'ACTIVE'
                RETURNING ioc_id
                """,
                (indicator.value, indicator.ioc_type.value, now_str, now_str),
            )
            row = cursor.fetchone()
            ioc_id = row[0]

            cursor.execute(
                """
                INSERT INTO ioc_feed_relations (ioc_id, feed_id, raw_context, observed_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ioc_id, feed_id) DO UPDATE SET
                    raw_context = CASE
                        WHEN excluded.raw_context != '' THEN excluded.raw_context
                        ELSE ioc_feed_relations.raw_context
                    END,
                    observed_at = excluded.observed_at
                """,
                (ioc_id, indicator.feed_id, indicator.context, now_str),
            )
            conn.commit()
            return ioc_id

    def get_raw_correlations(self) -> List[Dict[str, Any]]:
        """Retrieves raw relation data for all IOCs to calculate scores."""
        query = """
            SELECT
                i.ioc_id,
                i.value,
                i.ioc_type,
                i.first_seen,
                i.last_seen,
                i.occurrence_count,
                i.is_whitelisted,
                i.status,
                GROUP_CONCAT(DISTINCT r.feed_id) AS feed_ids,
                GROUP_CONCAT(DISTINCT r.raw_context) AS contexts,
                COUNT(DISTINCT r.feed_id) AS distinct_feed_count
            FROM iocs i
            JOIN ioc_feed_relations r ON i.ioc_id = r.ioc_id
            GROUP BY i.ioc_id
        """
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            rows = cursor.execute(query).fetchall()
            results = []
            for r in rows:
                feed_ids = [fid.strip() for fid in (r["feed_ids"] or "").split(",") if fid.strip()]
                contexts = [c.strip() for c in (r["contexts"] or "").split(",") if c.strip()]
                results.append({
                    "ioc_id": r["ioc_id"],
                    "value": r["value"],
                    "ioc_type": IOCType(r["ioc_type"]),
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                    "occurrence_count": r["occurrence_count"],
                    "is_whitelisted": bool(r["is_whitelisted"]),
                    "status": r["status"] if "status" in r.keys() else "ACTIVE",
                    "feed_ids": feed_ids,
                    "contexts": contexts,
                    "distinct_feed_count": r["distinct_feed_count"],
                })
            return results

    def batch_update_scores(self, updates: List[Tuple[float, str, int]]) -> None:
        """Updates score and severity: [(score, severity_str, ioc_id), ...]"""
        if not updates:
            return
        with get_db_connection(self.db_path) as conn:
            conn.executemany(
                "UPDATE iocs SET calculated_score = ?, severity = ? WHERE ioc_id = ?",
                updates,
            )
            conn.commit()

    def batch_update_scores_with_decay(
        self, updates: List[Tuple[float, float, str, str, int]]
    ) -> None:
        """Updates scores with aging decay: [(score, decayed_score, severity, status, ioc_id), ...]"""
        if not updates:
            return
        with get_db_connection(self.db_path) as conn:
            conn.executemany(
                """
                UPDATE iocs
                SET calculated_score = ?,
                    decayed_score = ?,
                    severity = ?,
                    status = ?
                WHERE ioc_id = ?
                """,
                updates,
            )
            conn.commit()

    def get_all_scored_indicators(
        self,
        min_severity: Optional[str] = None,
        ioc_type: Optional[IOCType] = None,
        status: Optional[str] = "ACTIVE",
    ) -> List[ScoredIndicator]:
        """Fetches scored indicators with optional filters."""
        query = """
            SELECT
                i.ioc_id,
                i.value,
                i.ioc_type,
                i.first_seen,
                i.last_seen,
                i.occurrence_count,
                i.calculated_score,
                i.decayed_score,
                i.severity,
                i.status,
                i.is_whitelisted,
                GROUP_CONCAT(DISTINCT r.feed_id) AS feed_ids,
                GROUP_CONCAT(DISTINCT r.raw_context) AS contexts
            FROM iocs i
            LEFT JOIN ioc_feed_relations r ON i.ioc_id = r.ioc_id
            WHERE 1=1
        """
        params = []
        if status and status.upper() != "ALL":
            query += " AND i.status = ?"
            params.append(status.upper())

        if min_severity:
            sev_levels = {"LOW": ["LOW", "MEDIUM", "HIGH"], "MEDIUM": ["MEDIUM", "HIGH"], "HIGH": ["HIGH"]}
            allowed = sev_levels.get(min_severity.upper(), ["HIGH"])
            placeholders = ",".join("?" for _ in allowed)
            query += f" AND i.severity IN ({placeholders})"
            params.extend(allowed)

        if ioc_type:
            query += " AND i.ioc_type = ?"
            params.append(ioc_type.value)

        query += " GROUP BY i.ioc_id ORDER BY i.calculated_score DESC, i.occurrence_count DESC"

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            rows = cursor.execute(query, params).fetchall()
            indicators = []
            for r in rows:
                sources = [s.strip() for s in (r["feed_ids"] or "").split(",") if s.strip()]
                contexts = [c.strip() for c in (r["contexts"] or "").split(",") if c.strip()]
                status_val = r["status"] if "status" in r.keys() and r["status"] else "ACTIVE"
                indicators.append(
                    ScoredIndicator(
                        ioc_id=r["ioc_id"],
                        value=r["value"],
                        ioc_type=IOCType(r["ioc_type"]),
                        first_seen=r["first_seen"],
                        last_seen=r["last_seen"],
                        occurrence_count=r["occurrence_count"],
                        calculated_score=float(r["calculated_score"]),
                        decayed_score=float(r["decayed_score"]) if "decayed_score" in r.keys() and r["decayed_score"] is not None else float(r["calculated_score"]),
                        severity=Severity(r["severity"]),
                        status=IndicatorStatus(status_val),
                        is_whitelisted=bool(r["is_whitelisted"]),
                        sources=sources,
                        contexts=contexts,
                    )
                )
            return indicators

    def get_indicator_by_value(self, value: str) -> Optional[ScoredIndicator]:
        """Searches for a specific indicator by exact string value."""
        query = """
            SELECT
                i.ioc_id,
                i.value,
                i.ioc_type,
                i.first_seen,
                i.last_seen,
                i.occurrence_count,
                i.calculated_score,
                i.decayed_score,
                i.severity,
                i.status,
                i.is_whitelisted,
                GROUP_CONCAT(DISTINCT r.feed_id) AS feed_ids,
                GROUP_CONCAT(DISTINCT r.raw_context) AS contexts
            FROM iocs i
            LEFT JOIN ioc_feed_relations r ON i.ioc_id = r.ioc_id
            WHERE i.value = ?
            GROUP BY i.ioc_id
        """
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            r = cursor.execute(query, (value.strip(),)).fetchone()
            if not r:
                return None
            sources = [s.strip() for s in (r["feed_ids"] or "").split(",") if s.strip()]
            contexts = [c.strip() for c in (r["contexts"] or "").split(",") if c.strip()]
            status_val = r["status"] if "status" in r.keys() and r["status"] else "ACTIVE"
            return ScoredIndicator(
                ioc_id=r["ioc_id"],
                value=r["value"],
                ioc_type=IOCType(r["ioc_type"]),
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                occurrence_count=r["occurrence_count"],
                calculated_score=float(r["calculated_score"]),
                decayed_score=float(r["decayed_score"]) if "decayed_score" in r.keys() and r["decayed_score"] is not None else float(r["calculated_score"]),
                severity=Severity(r["severity"]),
                status=IndicatorStatus(status_val),
                is_whitelisted=bool(r["is_whitelisted"]),
                sources=sources,
                contexts=contexts,
            )

    def get_metrics(self) -> Dict[str, Any]:
        """Computes summary metrics for reporting and dashboard."""
        with get_db_connection(self.db_path) as conn:
            c = conn.cursor()

            total_unique = c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

            # Breakdown by type
            type_rows = c.execute("SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type").fetchall()
            by_type = {row[0]: row[1] for row in type_rows}

            # Breakdown by severity
            sev_rows = c.execute("SELECT severity, COUNT(*) FROM iocs WHERE status = 'ACTIVE' GROUP BY severity").fetchall()
            by_severity = {row[0]: row[1] for row in sev_rows}

            # Breakdown by status
            status_rows = c.execute("SELECT status, COUNT(*) FROM iocs GROUP BY status").fetchall()
            by_status = {row[0]: row[1] for row in status_rows}

            # Feed processing counts
            feed_rows = c.execute("SELECT feed_id, name, status, ioc_count, weight FROM feeds").fetchall()
            feeds_summary = [dict(row) for row in feed_rows]

            # Top 10 active threats
            top_rows = c.execute(
                """
                SELECT value, ioc_type, calculated_score, decayed_score, severity, status, occurrence_count,
                       (SELECT COUNT(DISTINCT feed_id) FROM ioc_feed_relations WHERE ioc_id = iocs.ioc_id) as feed_count
                FROM iocs
                WHERE status = 'ACTIVE'
                ORDER BY calculated_score DESC, occurrence_count DESC
                LIMIT 10
                """
            ).fetchall()
            top_threats = [dict(row) for row in top_rows]

            return {
                "total_unique_iocs": total_unique,
                "breakdown_by_type": by_type,
                "breakdown_by_severity": by_severity,
                "breakdown_by_status": by_status,
                "feeds": feeds_summary,
                "top_threats": top_threats,
            }

    # Caching methods
    def get_cached_enrichment(self, ioc_value: str) -> Optional[Dict[str, Any]]:
        now_str = utc_now_iso()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM enrichment_cache WHERE ioc_value = ? AND expires_at > ?",
                (ioc_value, now_str),
            ).fetchone()
            if row:
                return {
                    "ioc_value": row["ioc_value"],
                    "provider": row["provider"],
                    "reputation_score": row["reputation_score"],
                    "raw_payload": json.loads(row["raw_payload"]) if row["raw_payload"] else {},
                    "cached_at": row["cached_at"],
                    "expires_at": row["expires_at"],
                }
            return None

    def set_cached_enrichment(
        self,
        ioc_value: str,
        provider: str,
        reputation_score: float,
        raw_payload: dict,
        ttl_days: int = 7,
    ) -> None:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=ttl_days)
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO enrichment_cache (ioc_value, provider, reputation_score, raw_payload, cached_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_value) DO UPDATE SET
                    provider = excluded.provider,
                    reputation_score = excluded.reputation_score,
                    raw_payload = excluded.raw_payload,
                    cached_at = excluded.cached_at,
                    expires_at = excluded.expires_at
                """,
                (
                    ioc_value,
                    provider,
                    reputation_score,
                    json.dumps(raw_payload),
                    now.isoformat(),
                    expires.isoformat(),
                ),
            )
            conn.commit()

    # Audit Logging
    def record_audit_log(self, action: str, target: str, details: str = "", user: str = "analyst") -> None:
        """Records an action in the audit trail."""
        now = utc_now_iso()
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (timestamp, action, target, details, user)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now, action, target, details, user),
            )
            conn.commit()

    def get_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent audit log events."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # Blocklist Snapshots for Diff Previews
    def save_blocklist_snapshot(self, active_ioc_values: List[str]) -> int:
        """Saves current exported IOC values to compute diffs in subsequent runs."""
        now = utc_now_iso()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO blocklist_snapshots (created_at, total_iocs, iocs_json)
                VALUES (?, ?, ?)
                RETURNING snapshot_id
                """,
                (now, len(active_ioc_values), json.dumps(active_ioc_values)),
            )
            row = cursor.fetchone()
            conn.commit()
            return row[0]

    def get_latest_blocklist_snapshot(self) -> Set[str]:
        """Returns the set of active IOC values from the most recent export snapshot."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT iocs_json FROM blocklist_snapshots ORDER BY snapshot_id DESC LIMIT 1"
            ).fetchone()
            if row and row["iocs_json"]:
                try:
                    return set(json.loads(row["iocs_json"]))
                except Exception:
                    return set()
            return set()

    # Feed Management
    def get_all_feeds(self) -> List[Dict[str, Any]]:
        """Returns all configured feeds and their live statuses."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT * FROM feeds ORDER BY feed_id ASC").fetchall()
            return [dict(r) for r in rows]

    def update_feed_config(self, feed_id: str, status: Optional[str] = None, weight: Optional[float] = None) -> bool:
        """Updates feed enabled status or confidence weight."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            if status is not None and weight is not None:
                cursor.execute("UPDATE feeds SET status = ?, weight = ? WHERE feed_id = ?", (status, weight, feed_id))
            elif status is not None:
                cursor.execute("UPDATE feeds SET status = ? WHERE feed_id = ?", (status, feed_id))
            elif weight is not None:
                cursor.execute("UPDATE feeds SET weight = ? WHERE feed_id = ?", (weight, feed_id))
            conn.commit()
            return cursor.rowcount > 0

    # Dynamic Allowlist Management
    def add_dynamic_allowlist(self, entry_type: str, value: str, reason: str = "") -> bool:
        """Adds an IP or domain to the dynamic allowlist."""
        now = utc_now_iso()
        val_clean = value.lower().strip()
        with get_db_connection(self.db_path) as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO dynamic_allowlist (entry_type, value, added_at, reason)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(value) DO UPDATE SET reason = excluded.reason
                    """,
                    (entry_type.lower(), val_clean, now, reason),
                )
                conn.commit()
                return True
            except Exception:
                return False

    def remove_dynamic_allowlist(self, value: str) -> bool:
        """Removes an indicator from the dynamic allowlist."""
        val_clean = value.lower().strip()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM dynamic_allowlist WHERE value = ?", (val_clean,))
            conn.commit()
            return cursor.rowcount > 0

    def get_dynamic_allowlist(self) -> Dict[str, Set[str]]:
        """Returns dynamic safe IPs and safe domains from the database."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT entry_type, value FROM dynamic_allowlist").fetchall()
            safe_ips = set()
            safe_domains = set()
            for r in rows:
                if r["entry_type"] == "ip":
                    safe_ips.add(r["value"])
                else:
                    safe_domains.add(r["value"])
            return {"ips": safe_ips, "domains": safe_domains}
