"""SQLite storage for past scans — powers the scan-history view.

Plain sqlite3, one connection per operation, keyed by db path so tests can
point at a temp file. Stores the deterministic report verbatim plus enough
structured fields to render history without re-parsing it.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from scanning.models import ScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score REAL,
    report TEXT NOT NULL,
    narrative TEXT,
    gate_findings TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _connect(db_path: Path | str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA)
    return conn


def save_scan(
    db_path: Path | str,
    name: str,
    source: str,
    result: ScanResult,
    report: str,
    narrative: str | None = None,
) -> int:
    with _connect(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO scans (name, source, verdict, score, report, narrative, gate_findings, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                name,
                source,
                result.verdict,
                result.score,
                report,
                narrative,
                json.dumps([asdict(f) for f in result.gate_findings]),
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ),
        )
        return cursor.lastrowid


def list_scans(db_path: Path | str) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, name, source, verdict, score, created_at FROM scans ORDER BY id DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def get_scan(db_path: Path | str, scan_id: int) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None
