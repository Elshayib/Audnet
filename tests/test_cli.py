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
        devices = [{"name": "rtr01", "host": "10.0.0.1", "username": "admin", "password": "x"}]
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
    bl.write_text("checks:\n  ssh_version:\n    severity: critical\n    rule: ssh_v2_only\n")
    return bl


class TestCliAudit:
    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_pass(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = ({}, [MagicMock(name="rtr01", host="10.0.0.1",
                                                 username="admin", password="x")])
        mock_bl.return_value = {"checks": {"ssh_version": {"severity": "critical", "rule": "ssh_v2_only"}}}
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(app, ["--inventory", str(inv), "--baseline", str(bl), "--output", str(out)])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "PASS" in result.output
        assert Path(f"{out}.md").exists()

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_fail(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = ({}, [MagicMock(name="rtr01", host="10.0.0.1",
                                                 username="admin", password="x")])
        mock_bl.return_value = {"checks": {"ssh_version": {"severity": "critical", "rule": "ssh_v2_only"}}}
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 1"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(app, ["--inventory", str(inv), "--baseline", str(bl), "--output", str(out)])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "FAIL" in result.output

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_collection_error(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = ({}, [MagicMock(name="rtr01", host="10.0.0.1",
                                                 username="admin", password="x")])
        mock_bl.return_value = {"checks": {"ssh_version": {"severity": "critical", "rule": "ssh_v2_only"}}}
        snap = DeviceSnapshot(device_name="rtr01", interfaces=ParsedInterfaces(),
                              version=ParsedVersion(), config=ParsedConfig(),
                              collection_error="Connection timed out")
        mock_collect.return_value = [snap]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(app, ["--inventory", str(inv), "--baseline", str(bl), "--output", str(out)])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "ERROR" in result.output
        assert "Connection timed out" in result.output

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_html_only(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = ({}, [MagicMock(name="rtr01", host="10.0.0.1",
                                                 username="admin", password="x")])
        mock_bl.return_value = {"checks": {"ssh_version": {"severity": "critical", "rule": "ssh_v2_only"}}}
        mock_collect.return_value = [_mock_snapshot("rtr01", ["ip ssh version 2"])]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(app, ["--inventory", str(inv), "--baseline", str(bl),
                                     "--output", str(out), "--format", "html"])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert Path(f"{out}.html").exists()
        assert not Path(f"{out}.md").exists()

    @patch("net_audit.cli.collect_all")
    @patch("net_audit.cli.load_baseline")
    @patch("net_audit.cli.load_inventory")
    def test_audit_multiple_devices(self, mock_inv, mock_bl, mock_collect, tmp_path):
        mock_inv.return_value = ({}, [
            MagicMock(name="rtr01", host="10.0.0.1", username="admin", password="x"),
            MagicMock(name="sw01", host="10.0.0.2", username="admin", password="x"),
        ])
        mock_bl.return_value = {"checks": {"ssh_version": {"severity": "critical", "rule": "ssh_v2_only"}}}
        mock_collect.return_value = [
            _mock_snapshot("rtr01", ["ip ssh version 2"]),
            _mock_snapshot("sw01", ["ip ssh version 1"]),
        ]
        inv = _write_inventory(tmp_path)
        bl = _write_baseline(tmp_path)
        out = tmp_path / "report"
        result = runner.invoke(app, ["--inventory", str(inv), "--baseline", str(bl), "--output", str(out)])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "rtr01" in result.output
        assert "sw01" in result.output
