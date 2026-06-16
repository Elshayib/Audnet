from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

import pytest
from audnet.cli import app
from audnet.models import DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig


@pytest.fixture(autouse=True)
def _disable_scrapli(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent scrapli auto-detection in CLI tests (scrapli is optional)."""
    import builtins as _builtins

    _real_import = _builtins.__import__

    def _blocked_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "scrapli" or name.startswith("scrapli."):
            raise ImportError("scrapli not available in tests")
        return _real_import(name, *args, **kwargs)

    monkeypatch.setattr(_builtins, "__import__", _blocked_import)


runner = CliRunner()


def _mock_snapshot(name: str, config_lines: list[str]) -> DeviceSnapshot:
    return DeviceSnapshot(
        device_name=name,
        interfaces=ParsedInterfaces(interfaces=[]),
        version=ParsedVersion(),
        config=ParsedConfig(lines=config_lines),
    )


def _mock_device(
    name: str,
    device_type: str = "cisco_ios",
    **kwargs: Any,
) -> MagicMock:
    """Create a MagicMock Device with device_type set (required for Scrapli backend)."""
    m = MagicMock(name=name, **kwargs)
    m.name = name
    m.device_type = device_type
    m.host = getattr(m, "host", "10.0.0.1")
    m.username = getattr(m, "username", "admin")
    m.password = getattr(m, "password", "x")
    return m


def _write_inventory(tmp_path: Path, devices: list[dict] | None = None) -> Path:
    inv = tmp_path / "devices.yaml"
    if devices is None:
        devices = [{"name": "rtr01", "host": "10.0.0.1", "username": "admin", "password": "***"}]
    lines = ["devices:"]
    for d in devices:
        lines.append(f"  - name: {d['name']}")
        lines.append(f"    host: {d['host']}")
        lines.append(f"    username: {d['username']}")
        lines.append(f"    password: {d['password']}")
    inv.write_text("\n".join(lines) + "\n")
    return inv


def _write_baseline(tmp_path: Path) -> Path:
    bl = tmp_path / "baseline.yaml"
    bl.write_text(
        'checks:\n  ssh_v2_only:\n    description: "SSHv2 must be enabled"\n    severity: critical\n    rule: ssh_v2_only\n'
    )
    return bl


class TestCliVersion:
    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "audnet" in result.output


class TestCliAudit:
    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_pass(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app, ["audit", "--inventory", str(inv), "--baseline", str(bl), "--output", str(out)]
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "PASS" in result.output
        assert Path(f"{out}.md").exists()

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_fail(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 1"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app, ["audit", "--inventory", str(inv), "--baseline", str(bl), "--output", str(out)]
        )
        assert result.exit_code == 1, f"Output: {result.output}"
        assert "FAIL" in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_collection_error(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        snap = DeviceSnapshot(
            device_name="rtr01",
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
            collection_error="Connection timed out",
        )
        mock_collect.return_value = [snap]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app, ["audit", "--inventory", str(inv), "--baseline", str(bl), "--output", str(out)]
        )
        assert result.exit_code == 1, f"Output: {result.output}"
        assert "ERROR" in result.output
        assert "Connection timed out" in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_html_only(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--format",
                "html",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert Path(f"{out}.html").exists()
        assert not Path(f"{out}.md").exists()

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_multiple_devices(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [
                _mock_device("rtr01", host="10.0.0.1", username="admin", password="x"),
                _mock_device("sw01", host="10.0.0.2", username="admin", password="x"),
            ],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [
            _mock_snapshot("rtr01", ["ip ssh version 2"]),
            _mock_snapshot("sw01", ["ip ssh version 1"]),
        ]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app, ["audit", "--inventory", str(inv), "--baseline", str(bl), "--output", str(out)]
        )
        assert result.exit_code == 1, f"Output: {result.output}"
        assert "rtr01" in result.output
        assert "sw01" in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_verbose_flag(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--verbose",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_device_filter(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--device filters to a single device by name."""
        mock_inv.return_value = (
            {},
            [
                _mock_device("rtr01", host="10.0.0.1", username="admin", password="x"),
                _mock_device("sw01", host="10.0.0.2", username="admin", password="x"),
            ],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [
            _mock_snapshot("rtr01", ["ip ssh version 2"]),
        ]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--device",
                "rtr01",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "rtr01" in result.output
        # sw01 should not appear since we filtered to rtr01
        assert "sw01" not in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_device_filter_not_found(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--device with nonexistent name prints error and exits."""
        mock_inv.return_value = (
            {},
            [
                _mock_device("rtr01", host="10.0.0.1", username="admin", password="x"),
            ],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = []
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--device",
                "nonexistent",
            ],
        )
        assert result.exit_code == 0
        assert "not found" in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_check_filter(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--check filters results to specified check names."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"},
                "inactive_ports": {"severity": "high", "rule": "no_open_ports"},
            }
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--check",
                "ssh_v2_only",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "PASS" in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_json_output(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--json outputs a JSON summary to stdout."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--json",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        # JSON output should be parseable
        import json as _json

        # Find the JSON array in output (after the table output)
        json_start = result.output.find("[")
        assert json_start != -1, "No JSON array found in output"
        parsed = _json.loads(result.output[json_start:])
        assert isinstance(parsed, list)
        assert len(parsed) == 1
        assert parsed[0]["device_name"] == "rtr01"
        assert parsed[0]["overall_pass"] is True

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_check_filter_invalid(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--check with unknown check name prints a warning."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--check",
                "nonexistent_check",
            ],
        )
        assert result.exit_code == 1, f"Output: {result.output}"
        assert "Warning" in result.output
        assert "nonexistent_check" in result.output
        assert "unknown check" in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_check_filter_comma_separated(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--check with comma-separated values works correctly."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"},
                "inactive_ports": {"severity": "high", "rule": "no_open_ports"},
            }
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--check",
                "ssh_v2_only,inactive_ports",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "PASS" in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_history_dir(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--history-dir saves audit results to the specified directory."""
        from audnet.history import get_runs

        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        hist = tmp_path / "history"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--history-dir",
                str(hist),
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        runs = get_runs(history_dir=hist)
        assert len(runs) == 1
        assert runs[0]["device_name"] == "rtr01"
        assert runs[0]["overall_pass"] is True

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_audit_no_history(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--no-history skips writing to the history database."""
        from audnet.history import get_runs

        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        hist = tmp_path / "history"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--history-dir",
                str(hist),
                "--no-history",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        runs = get_runs(history_dir=hist)
        assert len(runs) == 0


class TestCliDryRun:
    """Tests for --dry-run mode."""

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_dry_run_no_ssh_connections(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--dry-run does not call collect_all (no SSH connections)."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        mock_collect.assert_not_called()

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_dry_run_shows_devices_and_checks(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--dry-run lists devices and checks that would be audited."""
        mock_inv.return_value = (
            {},
            [
                _mock_device("rtr01", host="10.0.0.1", username="admin", password="x"),
                _mock_device("sw01", host="10.0.0.2", username="admin", password="x"),
            ],
        )
        mock_bl.return_value = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"},
                "inactive_ports": {"severity": "high", "rule": "no_open_ports"},
            }
        }
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "DRY RUN" in result.output
        assert "rtr01" in result.output
        assert "sw01" in result.output
        assert "ssh_v2_only" in result.output
        assert "inactive_ports" in result.output
        assert "Dry run complete" in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_dry_run_with_check_filter(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--dry-run with --check shows filtered checks."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"},
                "inactive_ports": {"severity": "high", "rule": "no_open_ports"},
            }
        }
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--dry-run",
                "--check",
                "ssh_v2_only",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "DRY RUN" in result.output
        mock_collect.assert_not_called()

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_dry_run_with_device_filter(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--dry-run with --device shows only the filtered device."""
        dev1 = MagicMock(host="10.0.0.1", username="admin", password="x")
        dev1.name = "rtr01"
        dev2 = MagicMock(host="10.0.0.2", username="admin", password="x")
        dev2.name = "sw01"
        mock_inv.return_value = ({}, [dev1, dev2])
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--dry-run",
                "--device",
                "rtr01",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "DRY RUN" in result.output
        assert "rtr01" in result.output
        assert "sw01" not in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_dry_run_short_flag(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """-n is a valid short flag for --dry-run."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "-n",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "DRY RUN" in result.output
        mock_collect.assert_not_called()

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_dry_run_validates_config(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--dry-run validates inventory and baseline loading."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
        assert "config and baseline are valid" in result.output

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_strict_flag_passed_to_load_inventory(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--strict is forwarded to load_inventory."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--strict",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        mock_inv.assert_called_once_with(str(inv), strict=True)

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_device_and_check_filter_combined(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--device and --check can be used together."""
        d1 = _mock_device("device_rtr01")
        d1.name = "rtr01"
        d1.host = "10.0.0.1"
        d2 = _mock_device("device_rtr02")
        d2.name = "rtr02"
        d2.host = "10.0.0.2"
        mock_inv.return_value = ({}, [d1, d2])
        mock_bl.return_value = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"},
                "inactive_ports": {"severity": "high", "rule": "no_open_ports"},
            }
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--device",
                "rtr01",
                "--check",
                "ssh_v2_only",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        # Only rtr01 should be collected
        mock_collect.assert_called_once()
        collected_devices = mock_collect.call_args[0][0]
        assert len(collected_devices) == 1
        assert collected_devices[0].name == "rtr01"

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_json_output_with_device_filter(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--json combined with --device produces filtered JSON output."""
        d1 = _mock_device("device_rtr01")
        d1.name = "rtr01"
        d1.host = "10.0.0.1"
        d2 = _mock_device("device_rtr02")
        d2.name = "rtr02"
        d2.host = "10.0.0.2"
        mock_inv.return_value = ({}, [d1, d2])
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--device",
                "rtr01",
                "--json",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        import json as _json

        json_start = result.output.find("[")
        assert json_start != -1
        parsed = _json.loads(result.output[json_start:])
        assert len(parsed) == 1
        assert parsed[0]["device_name"] == "rtr01"

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_json_output_with_check_filter(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--json combined with --check produces filtered JSON output."""
        d1 = _mock_device("device_rtr01")
        d1.name = "rtr01"
        d1.host = "10.0.0.1"
        mock_inv.return_value = ({}, [d1])
        mock_bl.return_value = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"},
                "inactive_ports": {"severity": "high", "rule": "no_open_ports"},
            }
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--check",
                "ssh_v2_only",
                "--json",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        import json as _json

        json_start = result.output.find("[")
        assert json_start != -1
        parsed = _json.loads(result.output[json_start:])
        assert len(parsed) == 1
        assert parsed[0]["overall_pass"] is True
        # Only ssh_v2_only check should be present
        check_names = [c["check_name"] for c in parsed[0]["checks"]]
        assert "ssh_v2_only" in check_names
        assert "inactive_ports" not in check_names

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_all_filters_combined(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--device, --check, --json, and --dry-run can be combined."""
        d1 = _mock_device("device_rtr01")
        d1.name = "rtr01"
        d1.host = "10.0.0.1"
        d2 = _mock_device("device_rtr02")
        d2.name = "rtr02"
        d2.host = "10.0.0.2"
        mock_inv.return_value = ({}, [d1, d2])
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--device",
                "rtr01",
                "--check",
                "ssh_v2_only",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        mock_collect.assert_not_called()
        assert "DRY RUN" in result.output
        assert "rtr01" in result.output


class TestCliExitCode:
    """Tests for non-zero exit code on compliance failures."""

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_no_fail_flag_ignores_compliance_failures(
        self, mock_inv, mock_bl, mock_collect, tmp_path
    ):
        """--no-fail always exits 0 even when checks fail."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 1"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--no-fail",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "FAIL" in result.output


class TestCliAsyncMode:
    """Tests for --async flag integration with async collector."""

    @patch("audnet.cli._collect_all_async")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_async_flag_calls_async_collector(
        self, mock_inv, mock_bl, mock_collect_async, tmp_path
    ):
        """--async flag routes to collect_all_async instead of collect_all."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }

        async def _fake_async(*args, **kwargs):
            return [_mock_snapshot("rtr01", ["ip ssh version 2"])]

        mock_collect_async.side_effect = _fake_async
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--async",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        mock_collect_async.assert_called_once()

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli._collect_all_async")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_default_uses_sync_collector(
        self, mock_inv, mock_bl, mock_collect_async, mock_collect_sync, tmp_path
    ):
        """Without --async, sync collect_all is used."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect_sync.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        mock_collect_sync.assert_called_once()
        mock_collect_async.assert_not_called()


class TestCliListVendors:
    """Tests for the list-vendors subcommand."""

    def test_list_vendors_shows_cisco_ios(self):
        result = runner.invoke(app, ["list-vendors"])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "cisco_ios" in result.output

    def test_list_vendors_shows_cisco_nxos(self):
        result = runner.invoke(app, ["list-vendors"])
        assert result.exit_code == 0
        assert "cisco_nxos" in result.output

    def test_list_vendors_shows_arista_eos(self):
        result = runner.invoke(app, ["list-vendors"])
        assert result.exit_code == 0
        assert "arista_eos" in result.output

    def test_list_vendors_json_flag(self):
        result = runner.invoke(app, ["list-vendors", "--json"])
        assert result.exit_code == 0
        import json as _json

        json_start = result.output.find("[")
        assert json_start != -1
        parsed = _json.loads(result.output[json_start:])
        device_types = [v["device_type"] for v in parsed]
        assert "cisco_ios" in device_types
        assert "arista_eos" in device_types
        assert "cisco_nxos" in device_types

    def test_list_vendors_json_has_description(self):
        result = runner.invoke(app, ["list-vendors", "--json"])
        assert result.exit_code == 0
        import json as _json

        json_start = result.output.find("[")
        parsed = _json.loads(result.output[json_start:])
        ios = next(v for v in parsed if v["device_type"] == "cisco_ios")
        assert ios["description"]

    def test_list_vendors_sorted(self):
        result = runner.invoke(app, ["list-vendors", "--json"])
        assert result.exit_code == 0
        import json as _json

        json_start = result.output.find("[")
        parsed = _json.loads(result.output[json_start:])
        types = [v["device_type"] for v in parsed]
        assert types == sorted(types)


class TestCliListChecks:
    """Tests for the list-checks subcommand."""

    def test_list_checks_shows_ssh_v2_only(self):
        result = runner.invoke(app, ["list-checks"])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "ssh_v2_only" in result.output

    def test_list_checks_shows_all_rules(self):
        result = runner.invoke(app, ["list-checks"])
        assert result.exit_code == 0
        for rule in ("ssh_v2_only", "no_open_ports", "ntp_approved", "syslog_approved"):
            assert rule in result.output

    def test_list_checks_json_flag(self):
        result = runner.invoke(app, ["list-checks", "--json"])
        assert result.exit_code == 0
        import json as _json

        json_start = result.output.find("[")
        assert json_start != -1
        parsed = _json.loads(result.output[json_start:])
        rules = [c["rule"] for c in parsed]
        assert "ssh_v2_only" in rules
        assert "ntp_approved" in rules

    def test_list_checks_json_sorted(self):
        result = runner.invoke(app, ["list-checks", "--json"])
        assert result.exit_code == 0
        import json as _json

        json_start = result.output.find("[")
        parsed = _json.loads(result.output[json_start:])
        rules = [c["rule"] for c in parsed]
        assert rules == sorted(rules)


class TestCliTimeout:
    """Tests for --timeout flag propagation to collect_all."""

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_timeout_passed_to_collect_all(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--timeout value is forwarded to collect_all(timeout=...)."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--timeout",
                "60",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        mock_collect.assert_called_once()
        _, kwargs = mock_collect.call_args
        assert kwargs.get("timeout") == 60.0

    @patch("audnet.cli.collect_all")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_default_timeout_is_none(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """Without --timeout, collect_all receives timeout=None."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
            ],
        )
        mock_collect.assert_called_once()
        _, kwargs = mock_collect.call_args
        assert kwargs.get("timeout") is None

    @patch("audnet.cli._collect_all_async")
    @patch("audnet.cli.load_baseline")
    @patch("audnet.cli.load_inventory")
    def test_timeout_passed_to_async_collector(
        self, mock_inv, mock_bl, mock_collect_async, tmp_path
    ):
        """--timeout is also forwarded to collect_all_async when --async is set."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_bl.return_value = {
            "checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only"}}
        }

        async def _fake_async(*args, **kwargs):
            return [_mock_snapshot("rtr01", ["ip ssh version 2"])]

        mock_collect_async.side_effect = _fake_async
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(
            app,
            [
                "audit",
                "--inventory",
                str(inv),
                "--baseline",
                str(bl),
                "--output",
                str(out),
                "--async",
                "--timeout",
                "45",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        mock_collect_async.assert_called_once()
        _, kwargs = mock_collect_async.call_args
        assert kwargs.get("timeout") == 45.0

    def test_timeout_in_help_output(self):
        """--timeout is documented in --help."""
        import re

        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0
        # Strip Rich ANSI escape codes before checking (CI adds color codes that
        # break plain substring matching on option flags like "--timeout").
        _ansi = re.compile(r"\x1b\[[0-9;]*m")
        clean = _ansi.sub("", result.output)
        assert "--timeout" in clean


class TestCliRemediate:
    """Tests for the ``audnet remediate`` CLI subcommand."""

    @patch("audnet.cli.load_inventory")
    @patch("audnet.remediate.apply_config")
    def test_dry_run_default(self, mock_apply, mock_inv, tmp_path):
        """Without --no-dry-run the command defaults to dry_run=True."""
        from audnet.remediate import RemediationStatus
        from audnet.models import Device

        mock_inv.return_value = (
            {},
            [Device(name="rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_apply.return_value = MagicMock(
            device_name="rtr01",
            status=RemediationStatus.DRY_RUN,
            diff=MagicMock(added_lines=["ntp server 1.1.1.1"], removed_lines=[]),
            rolled_back=False,
            error=None,
            duration_seconds=0.1,
        )

        inv = _write_inventory(tmp_path)
        cfg = tmp_path / "snippet.txt"
        cfg.write_text("ntp server 1.1.1.1\n")

        result = runner.invoke(
            app,
            [
                "remediate",
                "--inventory",
                str(inv),
                "--config",
                str(cfg),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        mock_apply.assert_called_once()
        _, kwargs = mock_apply.call_args
        assert kwargs["dry_run"] is True

    @patch("audnet.cli.load_inventory")
    @patch("audnet.remediate.apply_config")
    def test_no_dry_run_flag(self, mock_apply, mock_inv, tmp_path):
        """--no-dry-run sets dry_run=False and passes to apply_config."""
        from audnet.models import Device

        mock_inv.return_value = (
            {},
            [Device(name="rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_apply.return_value = MagicMock(
            device_name="rtr01",
            status=MagicMock(value="success"),
            diff=MagicMock(added_lines=["ntp server 1.1.1.1"], removed_lines=[]),
            rolled_back=False,
            error=None,
            duration_seconds=0.1,
        )

        inv = _write_inventory(tmp_path)
        cfg = tmp_path / "snippet.txt"
        cfg.write_text("ntp server 1.1.1.1\n")

        result = runner.invoke(
            app,
            [
                "remediate",
                "--inventory",
                str(inv),
                "--config",
                str(cfg),
                "--no-dry-run",
                "--auto-approve",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        _, kwargs = mock_apply.call_args
        assert kwargs["dry_run"] is False

    @patch("audnet.cli.load_inventory")
    def test_inventory_not_found(self, mock_inv, tmp_path):
        """Missing inventory file exits with code 1 and clear error."""
        cfg = tmp_path / "snippet.txt"
        cfg.write_text("ntp server 1.1.1.1\n")

        result = runner.invoke(
            app,
            [
                "remediate",
                "--inventory",
                str(tmp_path / "nope.yaml"),
                "--config",
                str(cfg),
            ],
        )
        assert result.exit_code == 1
        assert "Inventory file not found" in result.output

    @patch("audnet.cli.load_inventory")
    def test_config_not_found(self, mock_inv, tmp_path):
        """Missing config snippet file exits with code 1 and clear error."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        inv = _write_inventory(tmp_path)

        result = runner.invoke(
            app,
            [
                "remediate",
                "--inventory",
                str(inv),
                "--config",
                str(tmp_path / "nope.txt"),
            ],
        )
        assert result.exit_code == 1
        assert "Config file not found" in result.output

    @patch("audnet.cli.load_inventory")
    @patch("audnet.remediate.apply_config")
    def test_device_filter(self, mock_apply, mock_inv, tmp_path):
        """--device filters to named devices only."""
        from audnet.models import Device

        dev1 = Device(name="rtr01", host="10.0.0.1", username="admin", password="x")
        dev2 = Device(name="rtr02", host="10.0.0.2", username="admin", password="x")
        mock_inv.return_value = ({}, [dev1, dev2])
        mock_apply.return_value = MagicMock(
            device_name="rtr01",
            status=MagicMock(value="dry_run"),
            diff=MagicMock(added_lines=[], removed_lines=[]),
            rolled_back=False,
            error=None,
            duration_seconds=0.1,
        )

        inv = _write_inventory(
            tmp_path,
            devices=[
                {"name": "rtr01", "host": "10.0.0.1", "username": "admin", "password": "x"},
                {"name": "rtr02", "host": "10.0.0.2", "username": "admin", "password": "x"},
            ],
        )
        cfg = tmp_path / "snippet.txt"
        cfg.write_text("ntp server 1.1.1.1\n")

        result = runner.invoke(
            app,
            [
                "remediate",
                "--inventory",
                str(inv),
                "--config",
                str(cfg),
                "--device",
                "rtr01",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        mock_apply.assert_called_once()
        device_arg = mock_apply.call_args[0][0]
        assert device_arg.name == "rtr01"

    @patch("audnet.cli.load_inventory")
    def test_device_not_in_inventory(self, mock_inv, tmp_path):
        """--device with missing name exits with code 1."""
        mock_inv.return_value = (
            {},
            [_mock_device("rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        inv = _write_inventory(tmp_path)
        cfg = tmp_path / "snippet.txt"
        cfg.write_text("ntp server 1.1.1.1\n")

        result = runner.invoke(
            app,
            [
                "remediate",
                "--inventory",
                str(inv),
                "--config",
                str(cfg),
                "--device",
                "sw99",
            ],
        )
        assert result.exit_code == 1
        assert "sw99" in result.output

    @patch("audnet.cli.load_inventory")
    def test_no_devices(self, mock_inv, tmp_path):
        """Empty device list exits with code 1."""
        mock_inv.return_value = ({}, [])
        inv = _write_inventory(tmp_path)
        cfg = tmp_path / "snippet.txt"
        cfg.write_text("ntp server 1.1.1.1\n")

        result = runner.invoke(
            app,
            [
                "remediate",
                "--inventory",
                str(inv),
                "--config",
                str(cfg),
            ],
        )
        assert result.exit_code == 1
        assert "No devices to remediate" in result.output

    @patch("audnet.cli.load_inventory")
    @patch("audnet.remediate.apply_config")
    def test_result_table_output(self, mock_apply, mock_inv, tmp_path):
        """Successful remediation prints result table with device name and status."""
        from audnet.models import Device

        mock_inv.return_value = (
            {},
            [Device(name="rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_apply.return_value = MagicMock(
            device_name="rtr01",
            status=MagicMock(value="dry_run"),
            diff=MagicMock(added_lines=["ntp server 1.1.1.1"], removed_lines=[]),
            rolled_back=False,
            error=None,
            duration_seconds=0.1,
        )

        inv = _write_inventory(tmp_path)
        cfg = tmp_path / "snippet.txt"
        cfg.write_text("ntp server 1.1.1.1\n")

        result = runner.invoke(
            app,
            [
                "remediate",
                "--inventory",
                str(inv),
                "--config",
                str(cfg),
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "rtr01" in result.output

    @patch("audnet.cli.load_inventory")
    @patch("audnet.remediate.apply_config")
    def test_failure_exits_nonzero(self, mock_apply, mock_inv, tmp_path):
        """If any device fails the command exits with code 1."""
        from audnet.models import Device
        from audnet.remediate import RemediationStatus

        mock_inv.return_value = (
            {},
            [Device(name="rtr01", host="10.0.0.1", username="admin", password="x")],
        )
        mock_apply.return_value = MagicMock(
            device_name="rtr01",
            status=RemediationStatus.FAILED,
            diff=MagicMock(added_lines=[], removed_lines=[]),
            rolled_back=False,
            error="connection refused",
            duration_seconds=0.1,
        )

        inv = _write_inventory(tmp_path)
        cfg = tmp_path / "snippet.txt"
        cfg.write_text("ntp server 1.1.1.1\n")

        result = runner.invoke(
            app,
            [
                "remediate",
                "--inventory",
                str(inv),
                "--config",
                str(cfg),
            ],
        )
        assert result.exit_code == 1, f"Output: {result.output}"

    def test_help_output(self):
        """``remediate --help`` exits 0 and shows expected options."""
        import re

        result = runner.invoke(app, ["remediate", "--help"])
        assert result.exit_code == 0
        _ansi = re.compile(r"\x1b\[[0-9;]*m")
        clean = _ansi.sub("", result.output)
        assert "--config" in clean
        assert "--inventory" in clean
        assert "--dry-run" in clean
        assert "--no-dry-run" in clean

    def _block_git_history_import(self) -> None:
        """Block audnet.git_history from being imported (simulates missing GitPython)."""
        import builtins as _builtins

        self._real_import = _builtins.__import__

        def _blocked(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "audnet.git_history":
                raise ImportError("No module named 'git'")
            return self._real_import(name, *args, **kwargs)

        _builtins.__import__ = _blocked

    def _restore_import(self) -> None:
        import builtins as _builtins

        _builtins.__import__ = self._real_import

    def test_history_diff_gitpython_missing(self):
        """history-diff shows friendly error when GitPython is not installed."""
        self._block_git_history_import()
        try:
            result = runner.invoke(
                app,
                ["history-diff", "--device", "sandbox-c9k"],
            )
            assert result.exit_code == 1, f"Output: {result.output}"
            assert "GitPython is not installed" in result.output
        finally:
            self._restore_import()

    def test_history_show_gitpython_missing(self):
        """history-show shows friendly error when GitPython is not installed."""
        self._block_git_history_import()
        try:
            result = runner.invoke(
                app,
                ["history-show", "--device", "sandbox-c9k"],
            )
            assert result.exit_code == 1, f"Output: {result.output}"
            assert "GitPython is not installed" in result.output
        finally:
            self._restore_import()

    def test_history_log_gitpython_missing(self):
        """history-log shows friendly error when GitPython is not installed."""
        self._block_git_history_import()
        try:
            result = runner.invoke(
                app,
                ["history-log", "--device", "sandbox-c9k"],
            )
            assert result.exit_code == 1, f"Output: {result.output}"
            assert "GitPython is not installed" in result.output
        finally:
            self._restore_import()

    def test_rollback_gitpython_missing(self):
        """git-rollback shows friendly error when GitPython is not installed."""
        self._block_git_history_import()
        try:
            result = runner.invoke(
                app,
                ["git-rollback", "--device", "sandbox-c9k"],
            )
            assert result.exit_code == 1, f"Output: {result.output}"
            assert "GitPython is not installed" in result.output
        finally:
            self._restore_import()

    def test_history_diff_git_history_error(self):
        """history-diff shows friendly error when GitHistoryError is raised."""
        from audnet.exceptions import GitHistoryError

        with patch("audnet.git_history.diff_configs", side_effect=GitHistoryError("test error")):
            result = runner.invoke(
                app,
                ["history-diff", "--device", "sandbox-c9k"],
            )
        assert result.exit_code == 1, f"Output: {result.output}"
        assert "test error" in result.output

    def test_history_show_git_history_error(self):
        """history-show shows friendly error when GitHistoryError is raised."""
        from audnet.exceptions import GitHistoryError

        with patch("audnet.git_history.get_config_at", side_effect=GitHistoryError("repo gone")):
            result = runner.invoke(
                app,
                ["history-show", "--device", "sandbox-c9k"],
            )
        assert result.exit_code == 1, f"Output: {result.output}"
        assert "repo gone" in result.output

    def test_history_log_git_history_error(self):
        """history-log shows friendly error when GitHistoryError is raised."""
        from audnet.exceptions import GitHistoryError

        with patch("audnet.git_history.get_config_history", side_effect=GitHistoryError("no repo")):
            result = runner.invoke(
                app,
                ["history-log", "--device", "sandbox-c9k"],
            )
        assert result.exit_code == 1, f"Output: {result.output}"
        assert "no repo" in result.output

    def test_rollback_git_history_error(self):
        """git-rollback shows friendly error when GitHistoryError is raised."""
        from audnet.exceptions import GitHistoryError

        with patch("audnet.git_history.rollback_config", side_effect=GitHistoryError("bad ref")):
            result = runner.invoke(
                app,
                ["git-rollback", "--device", "sandbox-c9k"],
            )
        assert result.exit_code == 1, f"Output: {result.output}"
        assert "bad ref" in result.output
