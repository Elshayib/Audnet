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
    since: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Query historical audit runs.

    Args:
        device_name: Filter to a single device.
        history_dir: Directory containing history.db.
        limit: Maximum number of rows to return.
        since: Time window like "7d", "30d", "24h".
        status: Filter by "pass" or "fail".

    Returns a list of dicts with keys: id, run_at, device_name, overall_pass, checks.
    """
    if history_dir is None:
        history_dir = _DEFAULT_HISTORY_DIR
    db_file = _db_path(history_dir)
    if not db_file.exists():
        return []

    # Build query
    where_parts: list[str] = []
    params: list[Any] = []
    if device_name:
        where_parts.append("device_name = ?")
        params.append(device_name)
    if status == "pass":
        where_parts.append("overall_pass = 1")
    elif status == "fail":
        where_parts.append("overall_pass = 0")
    if since:
        delta = _parse_duration(since)
        cutoff = datetime.now(timezone.utc) - delta
        where_parts.append("run_at >= ?")
        params.append(cutoff.isoformat())

    where_clause = ""
    if where_parts:
        where_clause = "WHERE " + " AND ".join(where_parts)

    query = f"SELECT * FROM runs {where_clause} ORDER BY id DESC LIMIT ?"  # nosec B608
    params.append(limit)

    with sqlite3.connect(db_file) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()

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


def _parse_duration(since: str) -> Any:
    """Parse a duration string like '7d', '30d', '24h' into a timedelta."""
    from datetime import timedelta

    since = since.strip().lower()
    if since.endswith("d"):
        return timedelta(days=int(since[:-1]))
    elif since.endswith("h"):
        return timedelta(hours=int(since[:-1]))
    elif since.endswith("w"):
        return timedelta(weeks=int(since[:-1]))
    else:
        raise ValueError(f"Invalid duration '{since}'. Use Nd (days), Nh (hours), or Nw (weeks).")


def get_last_runs(
    history_dir: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Get the most recent run for each device.

    Returns a dict of {device_name: run_dict} where run_dict has
    keys: id, run_at, device_name, overall_pass, checks.
    """
    if history_dir is None:
        history_dir = _DEFAULT_HISTORY_DIR
    db_file = _db_path(history_dir)
    if not db_file.exists():
        return {}
    with sqlite3.connect(db_file) as conn:
        conn.row_factory = sqlite3.Row
        # Get the latest run id per device
        latest_ids = conn.execute(
            "SELECT device_name, MAX(id) as max_id FROM runs GROUP BY device_name"
        ).fetchall()
        if not latest_ids:
            return {}
        # Fetch those rows
        ids = [row["max_id"] for row in latest_ids]
        placeholders = ",".join("?" * len(ids))
        # placeholders is only "?" chars — safe. ids are passed as params.
        rows = conn.execute(
            f"SELECT * FROM runs WHERE id IN ({placeholders})",  # nosec B608
            ids,
        ).fetchall()
    result = {}
    for row in rows:
        device = row["device_name"]
        result[device] = {
            "id": row["id"],
            "run_at": row["run_at"],
            "device_name": device,
            "overall_pass": bool(row["overall_pass"]),
            "checks": json.loads(row["checks_json"]),
        }
    return result


def diff_runs(
    current_reports: list[AuditReport],
    history_dir: Path | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Compare current audit reports against the most recent stored runs.

    Returns a dict with three keys:
      - "new_failures": checks that passed last run but fail now
      - "resolved": checks that failed last run but pass now
      - "unchanged": checks that fail in both runs

    Each entry is a dict: {"device": str, "check": str, "severity": str, "detail": str}.
    """
    last_runs = get_last_runs(history_dir=history_dir)
    new_failures: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []

    for report in current_reports:
        last = last_runs.get(report.device_name)
        if last is None:
            # No prior run — nothing to diff against
            continue

        # Build lookup of last run's checks by name
        last_checks: dict[str, dict[str, Any]] = {}
        for c in last.get("checks", []):
            last_checks[c["check_name"]] = c

        for check in report.checks:
            prev = last_checks.get(check.check_name)
            if prev is None:
                # New check not seen before — skip
                continue

            entry = {
                "device": report.device_name,
                "check": check.check_name,
                "severity": check.severity,
                "detail": check.detail,
            }

            if prev["passed"] and not check.passed:
                new_failures.append(entry)
            elif not prev["passed"] and check.passed:
                resolved.append(entry)
            elif not prev["passed"] and not check.passed:
                unchanged.append(entry)
            # Both passing — no change to report

    return {
        "new_failures": new_failures,
        "resolved": resolved,
        "unchanged": unchanged,
    }
