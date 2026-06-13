"""Tests for drift/regression detection."""

from pathlib import Path

from audnet.history import save_run, get_last_runs, diff_runs
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


class TestGetLastRuns:
    def test_empty_db(self, tmp_path: Path):
        result = get_last_runs(history_dir=tmp_path)
        assert result == {}

    def test_single_device(self, tmp_path: Path):
        save_run([_make_report("rtr01", passed=True)], history_dir=tmp_path)
        result = get_last_runs(history_dir=tmp_path)
        assert "rtr01" in result
        assert result["rtr01"]["overall_pass"] is True

    def test_returns_latest_run(self, tmp_path: Path):
        save_run([_make_report("rtr01", passed=True)], history_dir=tmp_path)
        save_run([_make_report("rtr01", passed=False)], history_dir=tmp_path)
        result = get_last_runs(history_dir=tmp_path)
        assert result["rtr01"]["overall_pass"] is False

    def test_multiple_devices(self, tmp_path: Path):
        save_run(
            [_make_report("rtr01", passed=True), _make_report("sw01", passed=False)],
            history_dir=tmp_path,
        )
        result = get_last_runs(history_dir=tmp_path)
        assert len(result) == 2
        assert result["rtr01"]["overall_pass"] is True
        assert result["sw01"]["overall_pass"] is False

    def test_mixed_latest(self, tmp_path: Path):
        """Different devices updated at different times."""
        save_run([_make_report("rtr01", passed=True)], history_dir=tmp_path)
        save_run([_make_report("sw01", passed=False)], history_dir=tmp_path)
        save_run([_make_report("rtr01", passed=False)], history_dir=tmp_path)
        result = get_last_runs(history_dir=tmp_path)
        assert result["rtr01"]["overall_pass"] is False
        assert result["sw01"]["overall_pass"] is False


class TestDiffRuns:
    def test_no_prior_run(self, tmp_path: Path):
        """No history means no drift to report."""
        report = _make_report("rtr01", passed=True)
        drift = diff_runs([report], history_dir=tmp_path)
        assert drift["new_failures"] == []
        assert drift["resolved"] == []
        assert drift["unchanged"] == []

    def test_new_failure(self, tmp_path: Path):
        """Check that passed last run but fails now."""
        save_run([_make_report("rtr01", passed=True)], history_dir=tmp_path)
        report = _make_report("rtr01", passed=False)
        drift = diff_runs([report], history_dir=tmp_path)
        assert len(drift["new_failures"]) == 1
        assert drift["new_failures"][0]["device"] == "rtr01"
        assert drift["new_failures"][0]["check"] == "ssh_v2_only"
        assert drift["resolved"] == []
        assert drift["unchanged"] == []

    def test_resolved(self, tmp_path: Path):
        """Check that failed last run but passes now."""
        save_run([_make_report("rtr01", passed=False)], history_dir=tmp_path)
        report = _make_report("rtr01", passed=True)
        drift = diff_runs([report], history_dir=tmp_path)
        assert drift["new_failures"] == []
        assert len(drift["resolved"]) == 1
        assert drift["resolved"][0]["device"] == "rtr01"
        assert drift["resolved"][0]["check"] == "ssh_v2_only"
        assert drift["unchanged"] == []

    def test_unchanged_failure(self, tmp_path: Path):
        """Check that fails in both runs."""
        save_run([_make_report("rtr01", passed=False)], history_dir=tmp_path)
        report = _make_report("rtr01", passed=False)
        drift = diff_runs([report], history_dir=tmp_path)
        assert drift["new_failures"] == []
        assert drift["resolved"] == []
        assert len(drift["unchanged"]) == 1
        assert drift["unchanged"][0]["device"] == "rtr01"

    def test_unchanged_pass(self, tmp_path: Path):
        """Check that passes in both runs — no drift entry."""
        save_run([_make_report("rtr01", passed=True)], history_dir=tmp_path)
        report = _make_report("rtr01", passed=True)
        drift = diff_runs([report], history_dir=tmp_path)
        assert drift["new_failures"] == []
        assert drift["resolved"] == []
        assert drift["unchanged"] == []

    def test_mixed_changes(self, tmp_path: Path):
        """Multiple checks with different outcomes."""
        checks_before = [
            ComplianceResult(
                check_name="ssh_v2_only", passed=True, severity="critical", detail="ok"
            ),
            ComplianceResult(
                check_name="ntp_config", passed=False, severity="medium", detail="bad"
            ),
            ComplianceResult(
                check_name="syslog_config", passed=False, severity="low", detail="bad"
            ),
        ]
        report_before = AuditReport(device_name="rtr01", overall_pass=False, checks=checks_before)
        save_run([report_before], history_dir=tmp_path)

        checks_now = [
            ComplianceResult(
                check_name="ssh_v2_only", passed=False, severity="critical", detail="regressed"
            ),
            ComplianceResult(
                check_name="ntp_config", passed=True, severity="medium", detail="fixed"
            ),
            ComplianceResult(
                check_name="syslog_config", passed=False, severity="low", detail="still bad"
            ),
        ]
        report_now = AuditReport(device_name="rtr01", overall_pass=False, checks=checks_now)
        drift = diff_runs([report_now], history_dir=tmp_path)

        assert len(drift["new_failures"]) == 1
        assert drift["new_failures"][0]["check"] == "ssh_v2_only"
        assert len(drift["resolved"]) == 1
        assert drift["resolved"][0]["check"] == "ntp_config"
        assert len(drift["unchanged"]) == 1
        assert drift["unchanged"][0]["check"] == "syslog_config"

    def test_multiple_devices(self, tmp_path: Path):
        save_run(
            [_make_report("rtr01", passed=True), _make_report("sw01", passed=False)],
            history_dir=tmp_path,
        )
        current = [
            _make_report("rtr01", passed=False),
            _make_report("sw01", passed=True),
        ]
        drift = diff_runs(current, history_dir=tmp_path)
        assert len(drift["new_failures"]) == 1
        assert drift["new_failures"][0]["device"] == "rtr01"
        assert len(drift["resolved"]) == 1
        assert drift["resolved"][0]["device"] == "sw01"

    def test_unknown_device_skipped(self, tmp_path: Path):
        """Device with no prior run is skipped gracefully."""
        save_run([_make_report("rtr01", passed=True)], history_dir=tmp_path)
        current = [
            _make_report("rtr01", passed=False),
            _make_report("new_device", passed=False),
        ]
        drift = diff_runs(current, history_dir=tmp_path)
        # Only rtr01 should produce drift; new_device has no prior run
        assert len(drift["new_failures"]) == 1
        assert drift["new_failures"][0]["device"] == "rtr01"
