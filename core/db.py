"""
core/db.py

Engagement (assessment scope) storage. NexAudit requires an active,
named "engagement" record before any scan can be started. This keeps
every scan and report tied to a documented authorization.
"""

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "nexaudit.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    client TEXT,
    authorized_by TEXT NOT NULL,
    authorization_ref TEXT,
    start_date TEXT NOT NULL,
    end_date TEXT,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    bssid TEXT,
    essid TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements (id)
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    interface TEXT NOT NULL,
    csv_prefix TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements (id)
);
"""


@dataclass
class Engagement:
    id: Optional[int]
    name: str
    client: str
    authorized_by: str
    authorization_ref: str
    start_date: str
    end_date: str
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@contextmanager
def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def create_engagement(e: Engagement) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO engagements
               (name, client, authorized_by, authorization_ref,
                start_date, end_date, notes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (e.name, e.client, e.authorized_by, e.authorization_ref,
             e.start_date, e.end_date, e.notes, e.created_at),
        )
        return cur.lastrowid


def list_engagements() -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM engagements ORDER BY created_at DESC"
        ).fetchall()


def get_engagement(engagement_id: int) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()


def add_scope_entry(engagement_id: int, bssid: str = "", essid: str = ""):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scope_entries (engagement_id, bssid, essid) VALUES (?, ?, ?)",
            (engagement_id, bssid.strip().upper(), essid.strip()),
        )


def list_scope(engagement_id: int) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM scope_entries WHERE engagement_id = ?", (engagement_id,)
        ).fetchall()


def record_scan_start(engagement_id: int, interface: str, csv_prefix: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scan_sessions (engagement_id, interface, csv_prefix, started_at)
               VALUES (?, ?, ?, ?)""",
            (engagement_id, interface, csv_prefix, datetime.utcnow().isoformat()),
        )
        return cur.lastrowid


def record_scan_end(session_id: int):
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_sessions SET ended_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), session_id),
        )


def list_scan_sessions(engagement_id: int) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM scan_sessions WHERE engagement_id = ? ORDER BY started_at DESC",
            (engagement_id,),
        ).fetchall()
