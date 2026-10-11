"""
GHOST RECON v2.0 — core/db.py
Thread-safe SQLite database layer with full schema, migrations, and query helpers.

Design:
  - Single connection per GhostDB instance with check_same_thread=False
  - All write operations serialized through threading.Lock
  - Read operations are safe without locking (SQLite WAL mode)
  - Every table carries first_seen / last_seen for continuous-monitoring diffs
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA
# ═══════════════════════════════════════════════════════════════════════════════

_SCHEMA_VERSION = 1

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- ─── Schema version tracking ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_meta (
    key     TEXT PRIMARY KEY,
    value   TEXT
);

-- ─── Core scan metadata ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    domain          TEXT NOT NULL,
    root_domain     TEXT NOT NULL,
    scope           TEXT DEFAULT 'single',
    stealth         TEXT DEFAULT 'medium',
    started_at      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    completed_at    TEXT,
    current_step    INTEGER DEFAULT 0,
    config_json     TEXT,
    waf_detected    TEXT DEFAULT '[]',
    cdn_detected    TEXT DEFAULT '',
    origin_ip       TEXT DEFAULT '',
    tech_stack      TEXT DEFAULT '',
    server_header   TEXT DEFAULT '',
    powered_by      TEXT DEFAULT '',
    http_code       INTEGER DEFAULT 0,
    security_headers TEXT DEFAULT '{}',
    wildcard_ip     TEXT DEFAULT ''
);

-- ─── Discovered subdomains ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subdomains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    fqdn            TEXT NOT NULL,
    ip_addresses    TEXT DEFAULT '[]',
    cname           TEXT DEFAULT '',
    status          TEXT DEFAULT 'unknown',
    http_code       INTEGER DEFAULT 0,
    title           TEXT DEFAULT '',
    tech_stack      TEXT DEFAULT '',
    waf             TEXT DEFAULT '',
    cdn             TEXT DEFAULT '',
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(scan_id, fqdn)
);
CREATE INDEX IF NOT EXISTS idx_sub_scan ON subdomains(scan_id);
CREATE INDEX IF NOT EXISTS idx_sub_status ON subdomains(scan_id, status);

-- ─── URLs ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS urls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    source          TEXT DEFAULT 'unknown',
    normalized      TEXT DEFAULT '',
    endpoint_key    TEXT DEFAULT '',
    classification  TEXT DEFAULT 'unknown',
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(scan_id, normalized)
);
CREATE INDEX IF NOT EXISTS idx_url_scan ON urls(scan_id);
CREATE INDEX IF NOT EXISTS idx_url_class ON urls(scan_id, classification);

-- ─── JavaScript files ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS js_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    hash            TEXT DEFAULT '',
    size            INTEGER DEFAULT 0,
    priority_score  INTEGER DEFAULT 50,
    secrets_found   INTEGER DEFAULT 0,
    routes_found    INTEGER DEFAULT 0,
    analyzed        INTEGER DEFAULT 0,
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(scan_id, url)
);
CREATE INDEX IF NOT EXISTS idx_js_scan ON js_files(scan_id);

-- ─── Parameters ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS params (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    source          TEXT DEFAULT 'unknown',
    gf_patterns     TEXT DEFAULT '[]',
    tested          INTEGER DEFAULT 0,
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(scan_id, name)
);
CREATE INDEX IF NOT EXISTS idx_param_scan ON params(scan_id);

-- ─── Findings ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    severity        TEXT NOT NULL,
    cvss_score      REAL DEFAULT 0.0,
    cvss_vector     TEXT DEFAULT '',
    category        TEXT NOT NULL,
    cwe             TEXT DEFAULT '',
    owasp           TEXT DEFAULT '',
    mitre_tactic    TEXT DEFAULT '',
    mitre_technique TEXT DEFAULT '',
    url             TEXT DEFAULT '',
    title           TEXT NOT NULL,
    detail          TEXT DEFAULT '',
    impact          TEXT DEFAULT '',
    exploit         TEXT DEFAULT '',
    confidence      TEXT DEFAULT 'LOW',
    phase           TEXT DEFAULT '',
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    is_new          INTEGER DEFAULT 1,
    UNIQUE(scan_id, category, url, title)
);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_sev  ON findings(scan_id, severity);

-- ─── Port scan results ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ip              TEXT NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT DEFAULT 'tcp',
    service         TEXT DEFAULT '',
    version         TEXT DEFAULT '',
    source          TEXT DEFAULT 'unknown',
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(scan_id, ip, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_port_scan ON ports(scan_id);

-- ─── Secrets ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    pattern_name    TEXT NOT NULL,
    value_preview   TEXT DEFAULT '',
    source_url      TEXT DEFAULT '',
    source_type     TEXT DEFAULT 'unknown',
    severity        TEXT DEFAULT 'MEDIUM',
    cwe             TEXT DEFAULT '',
    validated       INTEGER DEFAULT 0,
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(scan_id, pattern_name, value_preview, source_url)
);
CREATE INDEX IF NOT EXISTS idx_secret_scan ON secrets(scan_id);

-- ─── Live hosts (alive subdomains with HTTP response data) ───────────────────
CREATE TABLE IF NOT EXISTS live_hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    http_code       INTEGER DEFAULT 0,
    title           TEXT DEFAULT '',
    content_length  INTEGER DEFAULT 0,
    tech            TEXT DEFAULT '',
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(scan_id, url)
);
CREATE INDEX IF NOT EXISTS idx_live_scan ON live_hosts(scan_id);

-- ─── Paths (200 OK and 403 blocked) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS paths (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    status_code     INTEGER NOT NULL,
    size            INTEGER DEFAULT 0,
    source          TEXT DEFAULT 'ffuf',
    bypass_tested   INTEGER DEFAULT 0,
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(scan_id, url, status_code)
);
CREATE INDEX IF NOT EXISTS idx_path_scan ON paths(scan_id);
CREATE INDEX IF NOT EXISTS idx_path_code ON paths(scan_id, status_code);

-- ─── API endpoints ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    path            TEXT NOT NULL,
    source          TEXT DEFAULT 'js_mine',
    method          TEXT DEFAULT 'GET',
    tested          INTEGER DEFAULT 0,
    first_seen      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(scan_id, path, method)
);
CREATE INDEX IF NOT EXISTS idx_api_scan ON api_endpoints(scan_id);

-- ─── Checkpoints ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS checkpoints (
    scan_id         TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    step            INTEGER NOT NULL DEFAULT 0,
    ctx_snapshot    TEXT DEFAULT '{}',
    updated_at      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class GhostDB:
    """Thread-safe SQLite database for GHOST RECON state management.

    All write operations are serialized through a reentrant lock.
    Read operations use check_same_thread=False which is safe with WAL mode.
    """

    def __init__(self, db_path: str | Path):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._init_schema()

    def _connect(self) -> None:
        """Open SQLite connection with optimal settings."""
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            timeout=30.0,
        )
        self._conn.row_factory = sqlite3.Row
        # Enable WAL + foreign keys via pragma (not in schema, must be per-conn)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 5000")

    def _init_schema(self) -> None:
        """Create tables if they don't exist. Idempotent."""
        with self._lock:
            self._conn.executescript(_SCHEMA_SQL)
            # Track schema version
            self._conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
                ("schema_version", str(_SCHEMA_VERSION)),
            )
            self._conn.commit()

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    # ─── Core Operations ──────────────────────────────────────────────────────

    @contextmanager
    def transaction(self):
        """Context manager for explicit transactions with auto-rollback."""
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a single SQL statement (thread-safe for writes)."""
        with self._lock:
            cursor = self._conn.execute(sql, params)
            self._conn.commit()
            return cursor

    def execute_many(self, sql: str, params_list: List[tuple]) -> None:
        """Execute parameterized SQL for many rows in a single transaction."""
        with self._lock:
            self._conn.executemany(sql, params_list)
            self._conn.commit()

    # ─── High-Performance Bulk Inserts (single-transaction executemany) ────────

    def bulk_insert_urls(self, scan_id: str, rows: List[tuple]) -> int:
        """Bulk insert URLs. Each row = (url, source, normalized, endpoint_key, classification, first_seen, last_seen).
        Returns count inserted. Uses single-transaction executemany to avoid I/O bottleneck."""
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                """INSERT OR IGNORE INTO urls
                   (scan_id, url, source, normalized, endpoint_key, classification, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [(scan_id,) + r for r in rows],
            )
            self._conn.commit()
        return len(rows)

    def bulk_insert_js(self, scan_id: str, rows: List[tuple]) -> int:
        """Bulk insert JS files. Each row = (url, hash, size, priority_score, first_seen, last_seen).
        Returns count inserted."""
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                """INSERT OR IGNORE INTO js_files
                   (scan_id, url, hash, size, priority_score, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [(scan_id,) + r for r in rows],
            )
            self._conn.commit()
        return len(rows)

    def bulk_insert_params(self, scan_id: str, rows: List[tuple]) -> int:
        """Bulk insert params. Each row = (name, source, first_seen).
        Returns count inserted."""
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                """INSERT OR IGNORE INTO params
                   (scan_id, name, source, first_seen)
                   VALUES (?, ?, ?, ?)""",
                [(scan_id,) + r for r in rows],
            )
            self._conn.commit()
        return len(rows)

    def fetch_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """Fetch a single row. No lock needed for reads in WAL mode."""
        return self._conn.execute(sql, params).fetchone()

    def fetch_all(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        """Fetch all rows."""
        return self._conn.execute(sql, params).fetchall()

    def fetch_scalar(self, sql: str, params: tuple = ()) -> Any:
        """Fetch a single scalar value."""
        row = self._conn.execute(sql, params).fetchone()
        return row[0] if row else None

    # ─── Upsert Helpers ───────────────────────────────────────────────────────

    def upsert(
        self,
        table: str,
        data: Dict[str, Any],
        conflict_columns: List[str],
        update_columns: Optional[List[str]] = None,
    ) -> int:
        """INSERT OR UPDATE with explicit conflict resolution.

        Args:
            table: Table name
            data: Column→value mapping
            conflict_columns: Columns that form the UNIQUE constraint
            update_columns: Columns to update on conflict (default: all non-conflict)

        Returns:
            lastrowid of the inserted/updated row
        """
        columns = list(data.keys())
        placeholders = ", ".join("?" for _ in columns)
        col_str = ", ".join(columns)

        if update_columns is None:
            update_columns = [c for c in columns if c not in conflict_columns]

        if update_columns:
            update_clause = ", ".join(
                f"{c} = excluded.{c}" for c in update_columns
            )
            # Always bump last_seen if the column exists
            if "last_seen" in columns and "last_seen" not in update_columns:
                update_clause += ", last_seen = excluded.last_seen"
            sql = (
                f"INSERT INTO {table} ({col_str}) VALUES ({placeholders}) "
                f"ON CONFLICT({', '.join(conflict_columns)}) "
                f"DO UPDATE SET {update_clause}"
            )
        else:
            sql = (
                f"INSERT OR IGNORE INTO {table} ({col_str}) "
                f"VALUES ({placeholders})"
            )

        values = tuple(data[c] for c in columns)
        with self._lock:
            cursor = self._conn.execute(sql, values)
            self._conn.commit()
            return cursor.lastrowid

    # ─── Scan Management ──────────────────────────────────────────────────────

    def create_scan(
        self,
        target: str,
        domain: str,
        root_domain: str,
        scope: str = "single",
        stealth: str = "medium",
        config_json: str = "{}",
    ) -> str:
        """Create a new scan record. Returns scan_id (UUID)."""
        scan_id = str(uuid.uuid4())
        self.execute(
            """INSERT INTO scans
               (scan_id, target, domain, root_domain, scope, stealth, config_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, target, domain, root_domain, scope, stealth, config_json),
        )
        # Initialize checkpoint at step 0
        self.execute(
            "INSERT INTO checkpoints (scan_id, step) VALUES (?, 0)",
            (scan_id,),
        )
        return scan_id

    def update_scan(self, scan_id: str, **fields) -> None:
        """Update scan-level metadata fields."""
        if not fields:
            return
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = tuple(fields.values()) + (scan_id,)
        self.execute(
            f"UPDATE scans SET {set_clause} WHERE scan_id = ?", values
        )

    def complete_scan(self, scan_id: str) -> None:
        """Mark scan as completed."""
        self.execute(
            "UPDATE scans SET completed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') "
            "WHERE scan_id = ?",
            (scan_id,),
        )

    def get_scan(self, scan_id: str) -> Optional[sqlite3.Row]:
        """Retrieve scan record."""
        return self.fetch_one("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))

    def get_latest_scan(self, domain: str) -> Optional[sqlite3.Row]:
        """Get the most recent completed scan for a domain (for diffing)."""
        return self.fetch_one(
            """SELECT * FROM scans
               WHERE domain = ? AND completed_at IS NOT NULL
               ORDER BY started_at DESC LIMIT 1""",
            (domain,),
        )

    # ─── Checkpoint Management ────────────────────────────────────────────────

    def save_checkpoint(self, scan_id: str, step: int, snapshot: dict) -> None:
        """Save execution checkpoint after a step completes."""
        self.execute(
            """INSERT OR REPLACE INTO checkpoints
               (scan_id, step, ctx_snapshot, updated_at)
               VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))""",
            (scan_id, step, json.dumps(snapshot, default=str)),
        )
        self.execute(
            "UPDATE scans SET current_step = ? WHERE scan_id = ?",
            (step, scan_id),
        )

    def load_checkpoint(self, scan_id: str) -> Tuple[int, dict]:
        """Load last checkpoint. Returns (completed_step, ctx_snapshot)."""
        row = self.fetch_one(
            "SELECT step, ctx_snapshot FROM checkpoints WHERE scan_id = ?",
            (scan_id,),
        )
        if row:
            try:
                snapshot = json.loads(row["ctx_snapshot"])
            except (json.JSONDecodeError, TypeError):
                snapshot = {}
            return row["step"], snapshot
        return 0, {}

    # ─── Diffing ──────────────────────────────────────────────────────────────

    def diff_scans(
        self, current_id: str, previous_id: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Compare two scans. Returns new/removed/changed assets."""
        result: Dict[str, List[Dict[str, Any]]] = {
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_findings": [],
            "resolved_findings": [],
            "new_ports": [],
            "closed_ports": [],
            "new_urls": [],
        }

        # New subdomains
        rows = self.fetch_all(
            """SELECT fqdn, ip_addresses, status FROM subdomains
               WHERE scan_id = ? AND fqdn NOT IN
                   (SELECT fqdn FROM subdomains WHERE scan_id = ?)""",
            (current_id, previous_id),
        )
        result["new_subdomains"] = [dict(r) for r in rows]

        # Removed subdomains
        rows = self.fetch_all(
            """SELECT fqdn, ip_addresses, status FROM subdomains
               WHERE scan_id = ? AND fqdn NOT IN
                   (SELECT fqdn FROM subdomains WHERE scan_id = ?)""",
            (previous_id, current_id),
        )
        result["removed_subdomains"] = [dict(r) for r in rows]

        # New findings (by category + url + title composite key)
        rows = self.fetch_all(
            """SELECT * FROM findings
               WHERE scan_id = ?
                 AND (category || '|' || url || '|' || title) NOT IN
                     (SELECT category || '|' || url || '|' || title
                      FROM findings WHERE scan_id = ?)""",
            (current_id, previous_id),
        )
        result["new_findings"] = [dict(r) for r in rows]

        # Resolved findings (in previous but not current)
        rows = self.fetch_all(
            """SELECT * FROM findings
               WHERE scan_id = ?
                 AND (category || '|' || url || '|' || title) NOT IN
                     (SELECT category || '|' || url || '|' || title
                      FROM findings WHERE scan_id = ?)""",
            (previous_id, current_id),
        )
        result["resolved_findings"] = [dict(r) for r in rows]

        # New ports
        rows = self.fetch_all(
            """SELECT ip, port, protocol, service FROM ports
               WHERE scan_id = ?
                 AND (ip || ':' || port || '/' || protocol) NOT IN
                     (SELECT ip || ':' || port || '/' || protocol
                      FROM ports WHERE scan_id = ?)""",
            (current_id, previous_id),
        )
        result["new_ports"] = [dict(r) for r in rows]

        # Closed ports
        rows = self.fetch_all(
            """SELECT ip, port, protocol, service FROM ports
               WHERE scan_id = ?
                 AND (ip || ':' || port || '/' || protocol) NOT IN
                     (SELECT ip || ':' || port || '/' || protocol
                      FROM ports WHERE scan_id = ?)""",
            (previous_id, current_id),
        )
        result["closed_ports"] = [dict(r) for r in rows]

        return result

    # ─── Statistics ───────────────────────────────────────────────────────────

    def scan_stats(self, scan_id: str) -> Dict[str, int]:
        """Get counts for all asset types in a scan."""
        tables = [
            ("subdomains", "subdomains"),
            ("live_hosts", "live_hosts"),
            ("urls", "urls"),
            ("js_files", "js_files"),
            ("params", "params"),
            ("findings", "findings"),
            ("ports", "ports"),
            ("secrets", "secrets"),
            ("api_endpoints", "api_endpoints"),
        ]
        stats: Dict[str, int] = {}
        for label, table in tables:
            stats[label] = self.fetch_scalar(
                f"SELECT COUNT(*) FROM {table} WHERE scan_id = ?", (scan_id,)
            ) or 0

        # Severity breakdown
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            stats[f"findings_{sev.lower()}"] = self.fetch_scalar(
                "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND severity = ?",
                (scan_id, sev),
            ) or 0

        # Path counts
        stats["paths_200"] = self.fetch_scalar(
            "SELECT COUNT(*) FROM paths WHERE scan_id = ? AND status_code = 200",
            (scan_id,),
        ) or 0
        stats["paths_403"] = self.fetch_scalar(
            "SELECT COUNT(*) FROM paths WHERE scan_id = ? AND status_code = 403",
            (scan_id,),
        ) or 0

        return stats

    # ─── Cleanup ──────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "GhostDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY: Generate scan_id for resume lookups
# ═══════════════════════════════════════════════════════════════════════════════

def find_scan_db(workspace_dir: str | Path) -> Optional[Path]:
    """Locate the ghost.db file inside a workspace directory for --resume."""
    ws = Path(workspace_dir)
    db_path = ws / "ghost.db"
    if db_path.exists():
        return db_path
    # Search one level deep
    for p in ws.glob("*/ghost.db"):
        return p
    return None


def get_resume_info(db_path: str | Path) -> Optional[Dict[str, Any]]:
    """Extract resume information from an existing database."""
    try:
        db = GhostDB(db_path)
        row = db.fetch_one(
            """SELECT s.scan_id, s.target, s.domain, s.current_step,
                      c.step, c.ctx_snapshot
               FROM scans s
               LEFT JOIN checkpoints c ON s.scan_id = c.scan_id
               WHERE s.completed_at IS NULL
               ORDER BY s.started_at DESC LIMIT 1"""
        )
        if row:
            info = dict(row)
            try:
                info["ctx_snapshot"] = json.loads(info.get("ctx_snapshot") or "{}")
            except (json.JSONDecodeError, TypeError):
                info["ctx_snapshot"] = {}
            db.close()
            return info
        db.close()
    except Exception:
        pass
    return None
