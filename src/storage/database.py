"""SQLite database schema initialization and connection management."""

from pathlib import Path
import sqlite3

SCHEMA_SQL = """
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
    severity TEXT DEFAULT 'LOW',
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

CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_ioc_score ON iocs(calculated_score);
CREATE INDEX IF NOT EXISTS idx_rel_ioc_feed ON ioc_feed_relations(ioc_id, feed_id);
"""


def get_db_connection(db_path: Path) -> sqlite3.Connection:
    """Returns a sqlite3 connection configured with dict-like row access."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path) -> None:
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()
