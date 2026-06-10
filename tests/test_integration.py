from __future__ import annotations

from unittest.mock import patch, MagicMock

from net_audit.collector import collect_all
from net_audit.compliance import run_checks
from net_audit.config import load_inventory, load_baseline
from net_audit.models import AuditReport, DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig
from net_audit.parser import parse_interfaces, parse_version, parse_config
from net_audit.reporter import render_markdown, render_html


def _make_snapshot(name: str, interfaces_raw: str, version_raw: str, config_raw: str):
    """Build a DeviceSnapshot with parsed data, mimicking what the full pipeline does."""
    return DeviceSnapshot(
        device_name=name,
        interfaces=ParsedInterfaces(interfaces=parse_interfaces(interfaces_raw)),
        version=ParsedVersion(**parse_version(version_raw)),
        config=ParsedConfig(lines=parse_config(config_raw)),
    )


class TestFullPipeline:
    @patch("net_audit.collector.ConnectHandler")
    def test_end_to_end_compliant_device(self, mock_cls, tmp_path):
        """Full pipeline: SSH collect -> parse -> audit -> report for a compliant device."""
        mock_conn = MagicMock()
        mock_conn.send_command.side_effect = [
            ("Interface              IP-Address      OK? Method Status                Protocol\n"
             "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up\n"
             "GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down"),
            ("Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
             "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
             "router uptime is 5 days, 3 hours, 22 minutes"),
            ("hostname core-rtr-01\n"
             "ip ssh version 2\n"
             "ntp server 10.0.0.50\n"
             "ntp server 10.0.0.51\n"
             "logging host 10.0.0.60\n"
             "interface GigabitEthernet0/0\n"
             " switchport access vlan 10\n"),
        ]
        mock_conn.is_alive.return_value = True
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_cls.return_value = mock_conn

        inv = tmp_path / "devices.yaml"
        inv.write_text("devices:\n  - name: core-rtr-01\n    host: 10.0.0.1\n"
                       "    username: admin\n    password: secret\n")

        bl = tmp_path / "baseline.yaml"
        bl.write_text(
            "checks:\n"
            "  ssh_v2_only:\n    severity: critical\n    rule: ssh_v2_only\n"
            "  inactive_ports:\n    severity: high\n    rule: no_open_ports\n"
            "    allowed_vlans: [10, 20, 30]\n"
            "  ntp_config:\n    severity: medium\n    rule: ntp_approved\n"
            "    approved_servers: [10.0.0.50, 10.0.0.51]\n"
            "  syslog_config:\n    severity: medium\n    rule: syslog_approved\n"
            "    approved_servers: [10.0.0.60]\n"
        )

        _, devices = load_inventory(str(inv))
        baseline_data = load_baseline(str(bl))
        snapshots = collect_all(devices, max_workers=1)

        assert len(snapshots) == 1
        snap = snapshots[0]
        assert snap.collection_error is None
        assert len(snap.interfaces.interfaces) == 2
        assert snap.version.raw != ""
        assert snap.config.raw != ""

        parsed_snap = _make_snapshot(
            name=snap.device_name,
            interfaces_raw=mock_conn.send_command.side_effect[0] if False else
                ("Interface              IP-Address      OK? Method Status                Protocol\n"
                 "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up\n"
                 "GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down"),
            version_raw=snap.version.raw,
            config_raw=snap.config.raw,
        )

        results = run_checks(parsed_snap, baseline_data)
        report = AuditReport(
            device_name=parsed_snap.device_name,
            overall_pass=all(r.passed for r in results),
            checks=results,
        )

        assert report.overall_pass is True
        assert report.pass_count == 4
        assert report.fail_count == 0

        md = render_markdown([report])
        html = render_html([report])
        assert "core-rtr-01" in md
        assert "PASS" in md
        assert "core-rtr-01" in html
        assert "<html" in html

    @patch("net_audit.collector.ConnectHandler")
    def test_end_to_end_noncompliant_device(self, mock_cls, tmp_path):
        """Full pipeline: device with SSHv1, bad VLAN, rogue NTP -- all checks fail."""
        mock_conn = MagicMock()
        mock_conn.send_command.side_effect = [
            ("Interface              IP-Address      OK? Method Status                Protocol\n"
             "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"),
            ("Cisco IOS Software, Version 12.4\n\nrouter uptime is 1 day"),
            ("hostname dist-sw-01\n"
             "ip ssh version 1\n"
             "ntp server 8.8.8.8\n"
             "logging host 192.168.99.99\n"
             "interface GigabitEthernet0/1\n"
             " switchport access vlan 999\n"),
        ]
        mock_conn.is_alive.return_value = True
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_cls.return_value = mock_conn

        inv = tmp_path / "devices.yaml"
        inv.write_text("devices:\n  - name: dist-sw-01\n    host: 10.0.0.2\n"
                       "    username: admin\n    password: secret\n")
        bl = tmp_path / "baseline.yaml"
        bl.write_text(
            "checks:\n"
            "  ssh_v2_only:\n    severity: critical\n    rule: ssh_v2_only\n"
            "  inactive_ports:\n    severity: high\n    rule: no_open_ports\n"
            "    allowed_vlans: [10, 20]\n"
            "  ntp_config:\n    severity: medium\n    rule: ntp_approved\n"
            "    approved_servers: [10.0.0.50]\n"
            "  syslog_config:\n    severity: medium\n    rule: syslog_approved\n"
            "    approved_servers: [10.0.0.60]\n"
        )

        _, devices = load_inventory(str(inv))
        baseline_data = load_baseline(str(bl))
        snapshots = collect_all(devices, max_workers=1)

        snap = snapshots[0]
        assert snap.collection_error is None

        parsed_snap = _make_snapshot(
            name=snap.device_name,
            interfaces_raw=("Interface              IP-Address      OK? Method Status                Protocol\n"
                            "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"),
            version_raw=snap.version.raw,
            config_raw=snap.config.raw,
        )

        results = run_checks(parsed_snap, baseline_data)
        report = AuditReport(
            device_name=parsed_snap.device_name,
            overall_pass=all(r.passed for r in results),
            checks=results,
        )

        assert report.overall_pass is False
        assert report.fail_count == 4

        fail_details = " ".join(r.detail for r in report.checks if not r.passed)
        assert "SSHv1" in fail_details
        assert "VLAN 999" in fail_details
        assert "8.8.8.8" in fail_details
        assert "192.168.99.99" in fail_details

    @patch("net_audit.collector.ConnectHandler")
    def test_end_to_end_partial_compliance(self, mock_cls, tmp_path):
        """Device passes SSH and VLAN but fails NTP."""
        mock_conn = MagicMock()
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 3 days",
            ("hostname rtr02\n"
             "ip ssh version 2\n"
             "ntp server 10.0.0.50\n"
             "ntp server 8.8.8.8\n"
             "interface Gi0/1\n"
             " switchport access vlan 20\n"),
        ]
        mock_conn.is_alive.return_value = True
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_cls.return_value = mock_conn

        inv = tmp_path / "devices.yaml"
        inv.write_text("devices:\n  - name: rtr02\n    host: 10.0.0.3\n"
                       "    username: admin\n    password: secret\n")
        bl = tmp_path / "baseline.yaml"
        bl.write_text(
            "checks:\n"
            "  ssh_v2_only:\n    severity: critical\n    rule: ssh_v2_only\n"
            "  inactive_ports:\n    severity: high\n    rule: no_open_ports\n"
            "    allowed_vlans: [10, 20]\n"
            "  ntp_config:\n    severity: medium\n    rule: ntp_approved\n"
            "    approved_servers: [10.0.0.50]\n"
        )

        _, devices = load_inventory(str(inv))
        baseline_data = load_baseline(str(bl))
        snapshots = collect_all(devices, max_workers=1)

        snap = snapshots[0]
        assert snap.collection_error is None

        parsed_snap = _make_snapshot(
            name=snap.device_name,
            interfaces_raw="Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            version_raw=snap.version.raw,
            config_raw=snap.config.raw,
        )

        results = run_checks(parsed_snap, baseline_data)
        report = AuditReport(
            device_name="rtr02",
            overall_pass=all(r.passed for r in results),
            checks=results,
        )

        assert report.overall_pass is False
        assert report.pass_count == 2
        assert report.fail_count == 1

        passed_names = [r.check_name for r in report.checks if r.passed]
        failed_names = [r.check_name for r in report.checks if not r.passed]
        assert "ssh_v2_only" in passed_names
        assert "inactive_ports" in passed_names
        assert "ntp_config" in failed_names
