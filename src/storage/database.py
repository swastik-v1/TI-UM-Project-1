"""SQLite database schema initialization, WAL concurrency mode, connection management, and auto-migrations."""

from pathlib import Path
import sqlite3

BASE_SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS feeds (
    feed_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    path_or_url TEXT NOT NULL,
    format TEXT NOT NULL,
    weight REAL DEFAULT 1.0,
    last_fetched TIMESTAMP,
    status TEXT DEFAULT 'ACTIVE',
    ioc_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS iocs (
    ioc_id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT UNIQUE NOT NULL,
    ioc_type TEXT NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    occurrence_count INTEGER DEFAULT 1,
    calculated_score REAL DEFAULT 0.0,
    decayed_score REAL DEFAULT 0.0,
    severity TEXT DEFAULT 'LOW',
    status TEXT DEFAULT 'ACTIVE',
    is_whitelisted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ioc_feed_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL,
    feed_id TEXT NOT NULL,
    raw_context TEXT,
    observed_at TIMESTAMP NOT NULL,
    FOREIGN KEY(ioc_id) REFERENCES iocs(ioc_id) ON DELETE CASCADE,
    FOREIGN KEY(feed_id) REFERENCES feeds(feed_id) ON DELETE CASCADE,
    UNIQUE(ioc_id, feed_id)
);

CREATE TABLE IF NOT EXISTS enrichment_cache (
    ioc_value TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    reputation_score REAL,
    raw_payload TEXT,
    cached_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT,
    user TEXT DEFAULT 'analyst'
);

CREATE TABLE IF NOT EXISTS blocklist_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP NOT NULL,
    total_iocs INTEGER NOT NULL,
    iocs_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dynamic_allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_type TEXT NOT NULL, -- 'ip' or 'domain'
    value TEXT UNIQUE NOT NULL,
    added_at TIMESTAMP NOT NULL,
    reason TEXT
);
"""

INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_ioc_score ON iocs(calculated_score);
CREATE INDEX IF NOT EXISTS idx_ioc_status ON iocs(status);
CREATE INDEX IF NOT EXISTS idx_rel_ioc_feed ON ioc_feed_relations(ioc_id, feed_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp);
"""


def get_db_connection(db_path: Path) -> sqlite3.Connection:
    """Returns a sqlite3 connection configured with dict-like row access, WAL mode, and busy timeout."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    # Enable WAL mode for multi-worker concurrency (allows simultaneous reader/writer)
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 10000;")
    except sqlite3.OperationalError:
        pass
    return conn


def _run_migrations(conn: sqlite3.Connection) -> None:
    """Safely adds missing columns and tables to existing databases."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(iocs)")
    existing_cols = {row["name"] for row in cursor.fetchall()}

    if "decayed_score" not in existing_cols:
        cursor.execute("ALTER TABLE iocs ADD COLUMN decayed_score REAL DEFAULT 0.0")
    if "status" not in existing_cols:
        cursor.execute("ALTER TABLE iocs ADD COLUMN status TEXT DEFAULT 'ACTIVE'")

    # Ensure auxiliary tables exist
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            details TEXT,
            user TEXT DEFAULT 'analyst'
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS blocklist_snapshots (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TIMESTAMP NOT NULL,
            total_iocs INTEGER NOT NULL,
            iocs_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dynamic_allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_type TEXT NOT NULL,
            value TEXT UNIQUE NOT NULL,
            added_at TIMESTAMP NOT NULL,
            reason TEXT
        )
        """
    )
    conn.commit()


def init_db(db_path: Path) -> None:
    """Initializes the database schema and applies migrations if needed."""
    conn = get_db_connection(db_path)
    try:
        conn.executescript(BASE_SCHEMA_SQL)
        _run_migrations(conn)
        conn.executescript(INDEXES_SQL)
        conn.commit()
    finally:
        conn.close()
