from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

from typer.testing import CliRunner

from net_audit.cli import app
from net_audit.models import DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig


runner = CliRunner()


def _mock_snapshot(name: str, config_lines: list[str]) -> DeviceSnapshot:
    return DeviceSnapshot(
        device_name=name,
        interfaces=ParsedInterfaces(interfaces=[]),
        version=ParsedVersion(),
        config=ParsedConfig(lines=config_lines),
    )


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
        assert "net-audit" in result.output


class TestCliAudit:
    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_pass(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_fail(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "FAIL" in result.output

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_collection_error(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "ERROR" in result.output
        assert "Connection timed out" in result.output

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_html_only(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_multiple_devices(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [
                MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x"),
                MagicMock(name="sw01", host="10.0.0.2", username="admin", password="x"),
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
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "rtr01" in result.output
        assert "sw01" in result.output

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_verbose_flag(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_device_filter(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--device filters to a single device by name."""
        mock_inv.return_value = (
            {},
            [
                MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x"),
                MagicMock(name="sw01", host="10.0.0.2", username="admin", password="x"),
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_device_filter_not_found(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--device with nonexistent name prints error and exits."""
        mock_inv.return_value = (
            {},
            [
                MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x"),
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_check_filter(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--check filters results to specified check names."""
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_json_output(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--json outputs a JSON summary to stdout."""
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_check_filter_invalid(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--check with unknown check name prints a warning."""
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "Warning" in result.output
        assert "nonexistent_check" in result.output
        assert "unknown check" in result.output

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_check_filter_comma_separated(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--check with comma-separated values works correctly."""
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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


class TestCliDryRun:
    """Tests for --dry-run mode."""

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_dry_run_no_ssh_connections(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--dry-run does not call collect_all (no SSH connections)."""
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_dry_run_shows_devices_and_checks(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--dry-run lists devices and checks that would be audited."""
        mock_inv.return_value = (
            {},
            [
                MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x"),
                MagicMock(name="sw01", host="10.0.0.2", username="admin", password="x"),
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_dry_run_with_check_filter(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--dry-run with --check shows filtered checks."""
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_dry_run_short_flag(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """-n is a valid short flag for --dry-run."""
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_dry_run_validates_config(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--dry-run validates inventory and baseline loading."""
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_strict_flag_passed_to_load_inventory(self, mock_inv, mock_bl, mock_collect, tmp_path):
        """--strict is forwarded to load_inventory."""
        mock_inv.return_value = (
            {},
            [MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x")],
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
