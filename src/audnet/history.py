"""SQLite-backed audit history store."""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audnet.models import AuditReport

logger = logging.getLogger(__name__)

_DEFAULT_HISTORY_DIR = Path.home() / ".net-audit"

_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    run_at TEXT NOT NULL,
    device_name TEXT NOT NULL,
    overall_pass INTEGER NOT NULL,
    checks_json TEXT NOT NULL
);
"""

_CREATE_INDEX_SQL = """\
CREATE INDEX IF NOT EXISTS idx_runs_device_name ON runs(device_name);
CREATE INDEX IF NOT EXISTS idx_runs_run_at ON runs(run_at);
"""


def _db_path(history_dir: Path) -> Path:
    return history_dir / "history.db"


def init_db(history_dir: Path | None = None) -> Path:
    """Create the history database and schema if they don't exist.

    Returns the path to the database file.
    """
    if history_dir is None:
        history_dir = _DEFAULT_HISTORY_DIR
    history_dir.mkdir(parents=True, exist_ok=True)
    db_file = _db_path(history_dir)
    with sqlite3.connect(db_file) as conn:
        conn.executescript(_CREATE_TABLE_SQL)
        conn.executescript(_CREATE_INDEX_SQL)
    return db_file


def save_run(
    reports: list[AuditReport],
    history_dir: Path | None = None,
) -> int:
    """Save audit reports to the history database.

    Returns the number of report rows inserted.
    """
    if history_dir is None:
        history_dir = _DEFAULT_HISTORY_DIR
    history_dir.mkdir(parents=True, exist_ok=True)
    db_file = _db_path(history_dir)
    # Ensure schema exists (idempotent — safe to call every run)
    with sqlite3.connect(db_file) as conn:
        conn.executescript(_CREATE_TABLE_SQL)
        conn.executescript(_CREATE_INDEX_SQL)

    run_at = datetime.now(timezone.utc).isoformat()
    rows_inserted = 0
    with sqlite3.connect(db_file) as conn:
        for report in reports:
            checks_data: list[dict[str, Any]] = []
            for c in report.checks:
                checks_data.append(
                    {
                        "check_name": c.check_name,
                        "passed": c.passed,
                        "severity": c.severity,
                        "detail": c.detail,
                    }
                )
            conn.execute(
                "INSERT INTO runs (run_at, device_name, overall_pass, checks_json) VALUES (?, ?, ?, ?)",
                (
                    run_at,
                    report.device_name,
                    1 if report.overall_pass else 0,
                    json.dumps(checks_data),
                ),
            )
            rows_inserted += 1
        conn.commit()
    logger.debug("Saved %d audit reports to %s", rows_inserted, db_file)
    return rows_inserted


def get_runs(
    device_name: str | None = None,
    history_dir: Path | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query historical audit runs.

    Returns a list of dicts with keys: id, run_at, device_name, overall_pass, checks.
    """
    if history_dir is None:
        history_dir = _DEFAULT_HISTORY_DIR
    db_file = _db_path(history_dir)
    if not db_file.exists():
        return []
    with sqlite3.connect(db_file) as conn:
        conn.row_factory = sqlite3.Row
        if device_name:
            rows = conn.execute(
                "SELECT * FROM runs WHERE device_name = ? ORDER BY id DESC LIMIT ?",
                (device_name, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    result = []
    for row in rows:
        result.append(
            {
                "id": row["id"],
                "run_at": row["run_at"],
                "device_name": row["device_name"],
                "overall_pass": bool(row["overall_pass"]),
                "checks": json.loads(row["checks_json"]),
            }
        )
    return result
