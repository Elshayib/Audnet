"""Tests for the history subcommand and filtering."""

import json
from datetime import timedelta
from pathlib import Path

from typer.testing import CliRunner

from audnet.cli import app
from audnet.history import save_run, get_runs, _parse_duration
from audnet.models import AuditReport, ComplianceResult

runner = CliRunner()


def _make_report(device: str, passed: bool) -> AuditReport:
    return AuditReport(
        device_name=device,
        overall_pass=passed,
        checks=[
            ComplianceResult(
                check_name="ssh_v2_only",
                passed=passed,
                severity="critical",
                detail="ok" if passed else "bad",
            )
        ],
    )


def _seed_history(tmp_path: Path, reports: list[AuditReport]) -> Path:
    hist = tmp_path / "history"
    save_run(reports, history_dir=hist)
    return hist


class TestParseDuration:
    def test_days(self):
        d = _parse_duration("7d")
        assert d == timedelta(days=7)

    def test_hours(self):
        d = _parse_duration("24h")
        assert d == timedelta(hours=24)

    def test_weeks(self):
        d = _parse_duration("2w")
        assert d == timedelta(weeks=2)

    def test_invalid(self):
        import pytest

        with pytest.raises(ValueError, match="Invalid duration"):
            _parse_duration("xyz")


class TestGetRunsFiltering:
    def test_filter_by_device(self, tmp_path: Path):
        save_run(
            [_make_report("rtr01", True), _make_report("sw01", False)],
            history_dir=tmp_path,
        )
        runs = get_runs(device_name="rtr01", history_dir=tmp_path)
        assert len(runs) == 1
        assert runs[0]["device_name"] == "rtr01"

    def test_filter_by_status_pass(self, tmp_path: Path):
        save_run(
            [_make_report("rtr01", True), _make_report("sw01", False)],
            history_dir=tmp_path,
        )
        runs = get_runs(status="pass", history_dir=tmp_path)
        assert len(runs) == 1
        assert runs[0]["overall_pass"] is True

    def test_filter_by_status_fail(self, tmp_path: Path):
        save_run(
            [_make_report("rtr01", True), _make_report("sw01", False)],
            history_dir=tmp_path,
        )
        runs = get_runs(status="fail", history_dir=tmp_path)
        assert len(runs) == 1
        assert runs[0]["overall_pass"] is False

    def test_filter_by_last(self, tmp_path: Path):
        for i in range(5):
            save_run([_make_report(f"rtr{i:02d}", True)], history_dir=tmp_path)
        runs = get_runs(history_dir=tmp_path, limit=3)
        assert len(runs) == 3

    def test_filter_by_since(self, tmp_path: Path):
        # Save a run with a backdated timestamp by manipulating the DB directly
        save_run([_make_report("rtr01", True)], history_dir=tmp_path)
        runs = get_runs(history_dir=tmp_path, since="1d")
        assert len(runs) == 1

    def test_combined_device_and_status(self, tmp_path: Path):
        save_run(
            [_make_report("rtr01", True), _make_report("rtr01", False)],
            history_dir=tmp_path,
        )
        runs = get_runs(device_name="rtr01", status="fail", history_dir=tmp_path)
        assert len(runs) == 1
        assert runs[0]["overall_pass"] is False


class TestHistoryCli:
    def test_history_table_output(self, tmp_path: Path):
        hist = _seed_history(tmp_path, [_make_report("rtr01", True)])
        result = runner.invoke(app, ["history", "--history-dir", str(hist)])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "rtr01" in result.output
        assert "PASS" in result.output

    def test_history_json_output(self, tmp_path: Path):
        hist = _seed_history(tmp_path, [_make_report("rtr01", True)])
        result = runner.invoke(app, ["history", "--history-dir", str(hist), "--format", "json"])
        assert result.exit_code == 0, f"Output: {result.output}"
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["device_name"] == "rtr01"

    def test_history_empty(self, tmp_path: Path):
        hist = tmp_path / "empty_hist"
        hist.mkdir()
        result = runner.invoke(app, ["history", "--history-dir", str(hist)])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "No history records found" in result.output

    def test_history_filter_device(self, tmp_path: Path):
        hist = _seed_history(
            tmp_path,
            [_make_report("rtr01", True), _make_report("sw01", False)],
        )
        result = runner.invoke(app, ["history", "--history-dir", str(hist), "--device", "rtr01"])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "rtr01" in result.output
        assert "sw01" not in result.output

    def test_history_filter_status_pass(self, tmp_path: Path):
        hist = _seed_history(
            tmp_path,
            [_make_report("rtr01", True), _make_report("sw01", False)],
        )
        result = runner.invoke(app, ["history", "--history-dir", str(hist), "--status", "pass"])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "rtr01" in result.output
        assert "sw01" not in result.output

    def test_history_filter_status_fail(self, tmp_path: Path):
        hist = _seed_history(
            tmp_path,
            [_make_report("rtr01", True), _make_report("sw01", False)],
        )
        result = runner.invoke(app, ["history", "--history-dir", str(hist), "--status", "fail"])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "sw01" in result.output
        assert "rtr01" not in result.output

    def test_history_last_n(self, tmp_path: Path):
        for i in range(5):
            save_run([_make_report(f"rtr{i:02d}", True)], history_dir=tmp_path)
        hist = tmp_path
        result = runner.invoke(app, ["history", "--history-dir", str(hist), "--last", "3"])
        assert result.exit_code == 0, f"Output: {result.output}"

    def test_history_since(self, tmp_path: Path):
        hist = _seed_history(tmp_path, [_make_report("rtr01", True)])
        result = runner.invoke(app, ["history", "--history-dir", str(hist), "--since", "7d"])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "rtr01" in result.output
