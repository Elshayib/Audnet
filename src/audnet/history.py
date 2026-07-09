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


def _connect(db_file: Path) -> sqlite3.Connection:
    """Open SQLite with WAL + busy timeout for concurrent audit writers.

    Callers must close the connection (use a try/finally). Prefer
    :func:`_db_session` for automatic cleanup.
    """
    conn = sqlite3.connect(db_file, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _db_session(db_file: Path) -> Any:
    """Context manager that opens, yields, and always closes a connection."""
    from contextlib import contextmanager
    from collections.abc import Iterator

    @contextmanager
    def _cm() -> Iterator[sqlite3.Connection]:
        conn = _connect(db_file)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    return _cm()


def init_db(history_dir: Path | None = None) -> Path:
    """Create the history database and schema if they don't exist.

    Returns the path to the database file.
    """
    if history_dir is None:
        history_dir = _DEFAULT_HISTORY_DIR
    history_dir.mkdir(parents=True, exist_ok=True)
    db_file = _db_path(history_dir)
    with _db_session(db_file) as conn:
        conn.executescript(_CREATE_TABLE_SQL)
        conn.executescript(_CREATE_INDEX_SQL)
    return db_file


def save_run(
    reports: list[AuditReport],
    history_dir: Path | None = None,
) -> int:
    """Save audit reports to the history database.

    Collection-error reports (``checks == []`` and ``overall_pass is False``)
    are still stored for audit trail completeness, but :func:`get_last_runs`
    and :func:`diff_runs` skip them as drift baselines so a failed collection
    cannot wipe regression detection.

    Returns the number of report rows inserted.
    """
    if history_dir is None:
        history_dir = _DEFAULT_HISTORY_DIR
    history_dir.mkdir(parents=True, exist_ok=True)
    db_file = _db_path(history_dir)

    run_at = datetime.now(timezone.utc).isoformat()
    rows_inserted = 0
    with _db_session(db_file) as conn:
        conn.executescript(_CREATE_TABLE_SQL)
        conn.executescript(_CREATE_INDEX_SQL)
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

    with _db_session(db_file) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()

        result = []
        for row in rows:
            try:
                checks = json.loads(row["checks_json"])
            except (json.JSONDecodeError, TypeError):
                logger.warning("Corrupt checks_json for run id=%s — skipping", row["id"])
                continue
            result.append(
                {
                    "id": row["id"],
                    "run_at": row["run_at"],
                    "device_name": row["device_name"],
                    "overall_pass": bool(row["overall_pass"]),
                    "checks": checks,
                }
            )
    return result


def _parse_duration(since: str) -> Any:
    """Parse a duration string like '7d', '30d', '24h' into a timedelta."""
    from datetime import timedelta

    since = since.strip().lower()
    if not since or since[-1] not in ("d", "h", "w"):
        raise ValueError(f"Invalid duration '{since}'. Use Nd (days), Nh (hours), or Nw (weeks).")
    num_part = since[:-1]
    if not num_part or not num_part.lstrip("-").isdigit():
        raise ValueError(f"Invalid duration '{since}'. Use Nd (days), Nh (hours), or Nw (weeks).")
    amount = int(num_part)
    if amount < 0:
        raise ValueError(f"Invalid duration '{since}': must be non-negative")
    if since.endswith("d"):
        return timedelta(days=amount)
    if since.endswith("h"):
        return timedelta(hours=amount)
    return timedelta(weeks=amount)


def _is_complete_baseline(run: dict[str, Any]) -> bool:
    """Return True if a historical run can be used as a drift baseline.

    Empty-check failure rows (typical of collection errors) must not become
    the baseline — they would hide real regressions on the next healthy run.
    """
    checks = run.get("checks") or []
    if not checks:
        # Empty checks + fail = collection error or bad filter; skip for drift
        return False
    return True


def get_last_runs(
    history_dir: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Get the most recent *complete* run for each device.

    Skips empty-check rows so collection failures do not poison drift.

    Returns a dict of {device_name: run_dict} where run_dict has
    keys: id, run_at, device_name, overall_pass, checks.
    """
    if history_dir is None:
        history_dir = _DEFAULT_HISTORY_DIR
    db_file = _db_path(history_dir)
    if not db_file.exists():
        return {}
    with _db_session(db_file) as conn:
        conn.row_factory = sqlite3.Row
        # Latest complete run per device (non-empty checks_json array)
        rows = conn.execute(
            """
            SELECT r.* FROM runs r
            INNER JOIN (
                SELECT device_name, MAX(id) AS max_id
                FROM runs
                WHERE checks_json IS NOT NULL
                  AND checks_json != '[]'
                  AND length(checks_json) > 2
                GROUP BY device_name
            ) latest ON r.id = latest.max_id
            """
        ).fetchall()
        result = {}
        for row in rows:
            device = row["device_name"]
            try:
                checks = json.loads(row["checks_json"])
            except (json.JSONDecodeError, TypeError):
                continue
            run = {
                "id": row["id"],
                "run_at": row["run_at"],
                "device_name": device,
                "overall_pass": bool(row["overall_pass"]),
                "checks": checks,
            }
            if _is_complete_baseline(run):
                result[device] = run
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
        # Skip incomplete current reports (collection errors) for drift
        if not report.checks:
            continue

        last = last_runs.get(report.device_name)
        if last is None:
            # No prior complete run — nothing to diff against
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
