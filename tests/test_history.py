"""Tests for the SQLite audit history store."""

from pathlib import Path

from audnet.history import init_db, save_run, get_runs
from audnet.models import AuditReport, ComplianceResult


def _make_report(
    device: str, passed: bool, checks: list[ComplianceResult] | None = None
) -> AuditReport:
    if checks is None:
        checks = [
            ComplianceResult(
                check_name="ssh_v2_only",
                passed=passed,
                severity="critical",
                detail="SSHv2 enabled" if passed else "SSHv1 only",
            )
        ]
    return AuditReport(device_name=device, overall_pass=passed, checks=checks)


class TestInitDb:
    def test_creates_db_file(self, tmp_path: Path):
        db_path = init_db(tmp_path)
        assert db_path.exists()
        assert db_path == tmp_path / "history.db"

    def test_creates_parent_dirs(self, tmp_path: Path):
        nested = tmp_path / "deep" / "nested"
        db_path = init_db(nested)
        assert db_path.exists()

    def test_idempotent(self, tmp_path: Path):
        init_db(tmp_path)
        init_db(tmp_path)  # second call must not fail


class TestSaveRun:
    def test_saves_single_report(self, tmp_path: Path):
        report = _make_report("rtr01", passed=True)
        count = save_run([report], history_dir=tmp_path)
        assert count == 1

    def test_saves_multiple_reports(self, tmp_path: Path):
        reports = [
            _make_report("rtr01", passed=True),
            _make_report("sw01", passed=False),
        ]
        count = save_run(reports, history_dir=tmp_path)
        assert count == 2

    def test_saves_check_details(self, tmp_path: Path):
        report = _make_report("rtr01", passed=True)
        save_run([report], history_dir=tmp_path)
        runs = get_runs(history_dir=tmp_path)
        assert len(runs) == 1
        assert runs[0]["device_name"] == "rtr01"
        assert runs[0]["overall_pass"] is True
        assert len(runs[0]["checks"]) == 1
        assert runs[0]["checks"][0]["check_name"] == "ssh_v2_only"

    def test_saves_failed_check(self, tmp_path: Path):
        report = _make_report("rtr01", passed=False)
        save_run([report], history_dir=tmp_path)
        runs = get_runs(history_dir=tmp_path)
        assert runs[0]["overall_pass"] is False
        assert runs[0]["checks"][0]["passed"] is False

    def test_empty_reports(self, tmp_path: Path):
        count = save_run([], history_dir=tmp_path)
        assert count == 0

    def test_creates_db_if_missing(self, tmp_path: Path):
        """save_run should work even without prior init_db."""
        report = _make_report("rtr01", passed=True)
        count = save_run([report], history_dir=tmp_path)
        assert count == 1

    def test_multiple_saves_append(self, tmp_path: Path):
        save_run([_make_report("rtr01", passed=True)], history_dir=tmp_path)
        save_run([_make_report("rtr01", passed=False)], history_dir=tmp_path)
        runs = get_runs(history_dir=tmp_path)
        assert len(runs) == 2
        # Most recent first
        assert runs[0]["overall_pass"] is False
        assert runs[1]["overall_pass"] is True


class TestGetRuns:
    def test_empty_db(self, tmp_path: Path):
        runs = get_runs(history_dir=tmp_path)
        assert runs == []

    def test_filter_by_device(self, tmp_path: Path):
        save_run(
            [_make_report("rtr01", passed=True), _make_report("sw01", passed=False)],
            history_dir=tmp_path,
        )
        runs = get_runs(device_name="rtr01", history_dir=tmp_path)
        assert len(runs) == 1
        assert runs[0]["device_name"] == "rtr01"

    def test_limit(self, tmp_path: Path):
        for i in range(5):
            save_run([_make_report(f"rtr{i:02d}", passed=True)], history_dir=tmp_path)
        runs = get_runs(history_dir=tmp_path, limit=3)
        assert len(runs) == 3

    def test_returns_checks_as_list(self, tmp_path: Path):
        checks = [
            ComplianceResult(check_name="a", passed=True, severity="high", detail="ok"),
            ComplianceResult(check_name="b", passed=False, severity="low", detail="bad"),
        ]
        report = _make_report("rtr01", passed=False, checks=checks)
        save_run([report], history_dir=tmp_path)
        runs = get_runs(history_dir=tmp_path)
        assert len(runs[0]["checks"]) == 2
        names = {c["check_name"] for c in runs[0]["checks"]}
        assert names == {"a", "b"}
