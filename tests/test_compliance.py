from net_audit.compliance import run_checks
from net_audit.models import (DeviceSnapshot, ParsedInterfaces,
                               ParsedVersion, ParsedConfig)


def _snap(name, config_lines):
    return DeviceSnapshot(
        device_name=name,
        interfaces=ParsedInterfaces(interfaces=[]),
        version=ParsedVersion(),
        config=ParsedConfig(lines=config_lines),
    )


class TestSshVersion:
    def test_pass(self):
        snap = _snap("rtr01", ["ip ssh version 2"])
        bl = {"checks": {"ssh_version": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_version"][0]
        assert r.passed is True

    def test_fail_v1(self):
        snap = _snap("rtr01", ["ip ssh version 1"])
        bl = {"checks": {"ssh_version": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_version"][0]
        assert r.passed is False

    def test_fail_missing(self):
        snap = _snap("rtr01", ["hostname rtr01"])
        bl = {"checks": {"ssh_version": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_version"][0]
        assert r.passed is False


class TestInactivePorts:
    def test_pass(self):
        snap = _snap("sw01", ["interface Gi0/1", " switchport access vlan 10"])
        bl = {"checks": {"inactive_ports": {"severity": "high", "rule": "no_open_ports",
                                            "allowed_vlans": [10, 20], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is True

    def test_fail_bad_vlan(self):
        snap = _snap("sw01", ["interface Gi0/1", " switchport access vlan 1"])
        bl = {"checks": {"inactive_ports": {"severity": "high", "rule": "no_open_ports",
                                            "allowed_vlans": [10, 20], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False


class TestNtpConfig:
    def test_pass(self):
        snap = _snap("rtr01", ["ntp server 10.0.0.50"])
        bl = {"checks": {"ntp_config": {"severity": "medium", "rule": "ntp_approved",
                                        "approved_servers": ["10.0.0.50"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is True

    def test_fail(self):
        snap = _snap("rtr01", ["ntp server 8.8.8.8"])
        bl = {"checks": {"ntp_config": {"severity": "medium", "rule": "ntp_approved",
                                        "approved_servers": ["10.0.0.50"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False


class TestSyslogConfig:
    def test_pass(self):
        snap = _snap("rtr01", ["logging host 10.0.0.60"])
        bl = {"checks": {"syslog_config": {"severity": "medium", "rule": "syslog_approved",
                                           "approved_servers": ["10.0.0.60"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is True

    def test_fail(self):
        snap = _snap("rtr01", ["logging host 192.168.99.99"])
        bl = {"checks": {"syslog_config": {"severity": "medium", "rule": "syslog_approved",
                                           "approved_servers": ["10.0.0.60"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is False
