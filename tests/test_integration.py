"""Full-pipeline integration through the shared collection interface (#207).

Collects through ``collect_all`` with a fake raw-transport adapter — no
test reaches past the shared interface into adapter internals. The fake
only moves bytes (per-slot raw CLI output); retry, parsing, audit, and
reporting all run for real.
"""

from __future__ import annotations

from typing import Any

from audnet.collector import collect_all
from audnet.compliance import run_checks
from audnet.config import load_baseline, load_inventory
from audnet.models import (
    AuditReport,
    Device,
    DeviceSnapshot,
    ParsedConfig,
    ParsedInterfaces,
    ParsedVersion,
)
from audnet.parser import parse_config, parse_interfaces, parse_version
from audnet.vendor_registry import Slot


class FakeAdapter:
    """Fake raw-transport adapter: connect/run/close, only moves bytes."""

    def __init__(self, raw: dict[Slot, str]) -> None:
        self._raw = raw

    def connect(self, device: Device) -> Any:
        return object()

    def run(self, connection: Any, command: str) -> str:
        cmd = command.lower()
        if "interface" in cmd or "terse" in cmd or "system interface" in cmd:
            return self._raw[Slot.INTERFACES]
        if "version" in cmd or "system status" in cmd or "system info" in cmd:
            return self._raw[Slot.VERSION]
        return self._raw[Slot.RUNNING_CONFIG]

    def close(self, connection: Any) -> None:
        return None


def _make_snapshot(name: str, interfaces_raw: str, version_raw: str, config_raw: str):
    """Build a DeviceSnapshot with parsed data, mimicking what the full pipeline does."""
    return DeviceSnapshot(
        device_name=name,
        interfaces=ParsedInterfaces(interfaces=parse_interfaces(interfaces_raw)),
        version=ParsedVersion(**parse_version(version_raw)),
        config=ParsedConfig(lines=parse_config(config_raw)),
    )


_COMPLIANT_RAW = {
    Slot.INTERFACES: (
        "Interface              IP-Address      OK? Method Status                Protocol\n"
        "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up\n"
        "GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down"
    ),
    Slot.VERSION: (
        "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
        "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
        "router uptime is 5 days, 3 hours, 22 minutes"
    ),
    Slot.RUNNING_CONFIG: (
        "hostname core-rtr-01\n"
        "ip ssh version 2\n"
        "ntp server 10.0.0.50\n"
        "ntp server 10.0.0.51\n"
        "logging host 10.0.0.60\n"
        "interface GigabitEthernet0/0\n"
        " switchport access vlan 10\n"
    ),
}

_NONCOMPLIANT_RAW = {
    Slot.INTERFACES: (
        "Interface              IP-Address      OK? Method Status                Protocol\n"
        "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"
    ),
    Slot.VERSION: "Cisco IOS Software, Version 12.4\n\nrouter uptime is 1 day",
    Slot.RUNNING_CONFIG: (
        "hostname dist-sw-01\n"
        "ip ssh version 1\n"
        "ntp server 8.8.8.8\n"
        "logging host 192.168.99.99\n"
        "interface GigabitEthernet0/1\n"
        " switchport access vlan 999\n"
    ),
}

_PARTIAL_RAW = {
    Slot.INTERFACES: "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
    Slot.VERSION: "Cisco IOS Software, Version 15.2\nuptime is 3 days",
    Slot.RUNNING_CONFIG: (
        "hostname rtr02\n"
        "ip ssh version 2\n"
        "ntp server 10.0.0.50\n"
        "ntp server 8.8.8.8\n"
        "interface Gi0/1\n"
        " switchport access vlan 20\n"
    ),
}


class TestFullPipeline:
    def test_end_to_end_compliant_device(self, tmp_path):
        """Full pipeline: SSH collect -> parse -> audit -> report for a compliant device."""
        inv = tmp_path / "devices.yaml"
        inv.write_text(
            "devices:\n  - name: core-rtr-01\n    host: 10.0.0.1\n"
            "    username: admin\n    password: secret\n"
        )

        bl = tmp_path / "baseline.yaml"
        bl.write_text(
            "checks:\n"
            '  ssh_v2_only:\n    description: "SSHv2 must be enabled"\n    severity: critical\n    rule: ssh_v2_only\n'
            '  inactive_ports:\n    description: "Secure VLANs only"\n    severity: high\n    rule: no_open_ports\n'
            "    allowed_vlans: [10, 20, 30]\n"
            '  ntp_config:\n    description: "Approved NTP servers"\n    severity: medium\n    rule: ntp_approved\n'
            "    approved_servers: [10.0.0.50, 10.0.0.51]\n"
            '  syslog_config:\n    description: "Approved syslog servers"\n    severity: medium\n    rule: syslog_approved\n'
            "    approved_servers: [10.0.0.60]\n"
        )

        _, devices = load_inventory(str(inv))
        baseline_data = load_baseline(str(bl))
        snapshots = collect_all(devices, max_workers=1, adapter=FakeAdapter(_COMPLIANT_RAW))

        assert len(snapshots) == 1
        snap = snapshots[0]
        assert snap.collection_error is None
        assert len(snap.interfaces.interfaces) == 2
        assert snap.version.raw != ""
        assert snap.config.raw != ""

        parsed_snap = _make_snapshot(
            name=snap.device_name,
            interfaces_raw=_COMPLIANT_RAW[Slot.INTERFACES],
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

        from audnet.reporter import render_html, render_markdown

        md = render_markdown([report])
        html = render_html([report])
        assert "core-rtr-01" in md
        assert "PASS" in md
        assert "core-rtr-01" in html
        assert "<html" in html

    def test_end_to_end_noncompliant_device(self, tmp_path):
        """Full pipeline: device with SSHv1, bad VLAN, rogue NTP -- all checks fail."""
        inv = tmp_path / "devices.yaml"
        inv.write_text(
            "devices:\n  - name: dist-sw-01\n    host: 10.0.0.2\n"
            "    username: admin\n    password: secret\n"
        )
        bl = tmp_path / "baseline.yaml"
        bl.write_text(
            "checks:\n"
            '  ssh_v2_only:\n    description: "SSHv2 must be enabled"\n    severity: critical\n    rule: ssh_v2_only\n'
            '  inactive_ports:\n    description: "Secure VLANs only"\n    severity: high\n    rule: no_open_ports\n'
            "    allowed_vlans: [10, 20]\n"
            '  ntp_config:\n    description: "Approved NTP servers"\n    severity: medium\n    rule: ntp_approved\n'
            "    approved_servers: [10.0.0.50]\n"
            '  syslog_config:\n    description: "Approved syslog servers"\n    severity: medium\n    rule: syslog_approved\n'
            "    approved_servers: [10.0.0.60]\n"
        )

        _, devices = load_inventory(str(inv))
        baseline_data = load_baseline(str(bl))
        snapshots = collect_all(devices, max_workers=1, adapter=FakeAdapter(_NONCOMPLIANT_RAW))

        snap = snapshots[0]
        assert snap.collection_error is None

        parsed_snap = _make_snapshot(
            name=snap.device_name,
            interfaces_raw=_NONCOMPLIANT_RAW[Slot.INTERFACES],
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

    def test_end_to_end_partial_compliance(self, tmp_path):
        """Device passes SSH and VLAN but fails NTP."""
        inv = tmp_path / "devices.yaml"
        inv.write_text(
            "devices:\n  - name: rtr02\n    host: 10.0.0.3\n"
            "    username: admin\n    password: secret\n"
        )
        bl = tmp_path / "baseline.yaml"
        bl.write_text(
            "checks:\n"
            '  ssh_v2_only:\n    description: "SSHv2 must be enabled"\n    severity: critical\n    rule: ssh_v2_only\n'
            '  inactive_ports:\n    description: "Secure VLANs only"\n    severity: high\n    rule: no_open_ports\n'
            "    allowed_vlans: [10, 20]\n"
            '  ntp_config:\n    description: "Approved NTP servers"\n    severity: medium\n    rule: ntp_approved\n'
            "    approved_servers: [10.0.0.50]\n"
        )

        _, devices = load_inventory(str(inv))
        baseline_data = load_baseline(str(bl))
        snapshots = collect_all(devices, max_workers=1, adapter=FakeAdapter(_PARTIAL_RAW))

        snap = snapshots[0]
        assert snap.collection_error is None

        parsed_snap = _make_snapshot(
            name=snap.device_name,
            interfaces_raw=_PARTIAL_RAW[Slot.INTERFACES],
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
