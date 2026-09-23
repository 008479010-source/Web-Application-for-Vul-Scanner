"""
SQLite persistence for the things that need to outlive an in-memory scan
job: engagement (scope & authorization) records, an append-only audit log
of engagement/scan lifecycle events, and a local cache of NVD CVE lookups
(so repeat scans of the same software version don't re-hit the NVD API
and risk its rate limit).

Uses only the standard library (sqlite3) - no new dependency.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

import config

os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    engagement_name TEXT NOT NULL,
    scope_description TEXT NOT NULL,
    authorized_by TEXT NOT NULL,
    authorization_date TEXT NOT NULL,
    testing_window_start TEXT NOT NULL,
    testing_window_end TEXT NOT NULL,
    rules_of_engagement TEXT,
    contact_name TEXT,
    contact_email TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    engagement_id TEXT,
    job_id TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS cve_cache (
    cache_key TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    results_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextlib.contextmanager
def _connect():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _lock, _connect() as conn:
        conn.executescript(_SCHEMA)


# Initialize on import so any module that touches the database (job_manager,
# app.py, or a test importing either) can rely on the schema already being
# there - CREATE TABLE IF NOT EXISTS makes this idempotent and cheap.
init_db()


# ---------- engagements ----------

def create_engagement(fields: dict) -> str:
    engagement_id = uuid.uuid4().hex[:10]
    with _lock, _connect() as conn:
        conn.execute(
            """INSERT INTO engagements
               (id, client_name, engagement_name, scope_description, authorized_by,
                authorization_date, testing_window_start, testing_window_end,
                rules_of_engagement, contact_name, contact_email, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement_id,
                fields["client_name"],
                fields["engagement_name"],
                fields["scope_description"],
                fields["authorized_by"],
                fields["authorization_date"],
                fields["testing_window_start"],
                fields["testing_window_end"],
                fields.get("rules_of_engagement", ""),
                fields.get("contact_name", ""),
                fields.get("contact_email", ""),
                _now(),
            ),
        )
    record_audit_event("engagement_created", engagement_id=engagement_id, detail=fields.get("engagement_name"))
    return engagement_id


def get_engagement(engagement_id: str) -> dict | None:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
        return dict(row) if row else None


def list_engagements() -> list[dict]:
    with _lock, _connect() as conn:
        rows = conn.execute("SELECT * FROM engagements ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def engagement_window_status(engagement: dict) -> str:
    """Returns 'active', 'not_started', or 'expired' based on the current time.

    Start/end come from plain <input type="date"> values (date-only, no
    time), so a naive comparison would treat the end date as expiring at
    midnight - meaning an engagement authorized "through today" would show
    as already expired. Treat the end date as inclusive of its whole day.
    """
    now = datetime.now(timezone.utc)
    start = datetime.fromisoformat(engagement["testing_window_start"])
    end = datetime.fromisoformat(engagement["testing_window_end"])
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
    if now < start:
        return "not_started"
    if now > end:
        return "expired"
    return "active"


# ---------- audit log ----------

def record_audit_event(event_type: str, engagement_id: str | None = None,
                        job_id: str | None = None, detail=None) -> None:
    detail_text = json.dumps(detail) if isinstance(detail, (dict, list)) else (detail or "")
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, event_type, engagement_id, job_id, detail) VALUES (?, ?, ?, ?, ?)",
            (_now(), event_type, engagement_id, job_id, detail_text),
        )


def list_audit_events(limit: int = 200) -> list[dict]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- CVE cache ----------
# Cheap local cache for NVD keywordSearch results, keyed by normalized
# product+version. NVD's public rate limit is small and process-global
# (see modules/cve_match.py), so avoiding repeat live lookups for the same
# software version - across scans, not just within one - matters a lot in
# practice.

def get_cve_cache(cache_key: str) -> list | None:
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT results_json, expires_at FROM cve_cache WHERE cache_key = ?", (cache_key,)
        ).fetchone()
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return json.loads(row["results_json"])


def store_cve_cache(cache_key: str, product: str, version: str, results: list, ttl_seconds: int) -> None:
    now = datetime.now(timezone.utc)
    expires_at = now.timestamp() + ttl_seconds
    with _lock, _connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO cve_cache
               (cache_key, product, version, results_json, fetched_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                cache_key, product, version, json.dumps(results),
                now.isoformat(),
                datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat(),
            ),
        )
