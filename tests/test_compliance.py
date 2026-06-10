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
        bl = {"checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True

    def test_fail_v1(self):
        snap = _snap("rtr01", ["ip ssh version 1"])
        bl = {"checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is False

    def test_fail_missing(self):
        snap = _snap("rtr01", ["hostname rtr01"])
        bl = {"checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
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


class TestUnknownRule:
    def test_unknown_rule_returns_fail(self):
        snap = _snap("rtr01", ["ip ssh version 2"])
        bl = {"checks": {"custom_check": {"severity": "low", "rule": "nonexistent_rule", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "custom_check"][0]
        assert r.passed is False
        assert "Unknown rule" in r.detail


class TestNoNtpConfigured:
    def test_no_servers_configured_fails(self):
        snap = _snap("rtr01", ["hostname rtr01"])
        bl = {"checks": {"ntp_config": {"severity": "medium", "rule": "ntp_approved",
                                        "approved_servers": ["10.0.0.50"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False
        assert "No NTP servers configured" in r.detail


class TestNoSyslogConfigured:
    def test_no_servers_configured_fails(self):
        snap = _snap("rtr01", ["hostname rtr01"])
        bl = {"checks": {"syslog_config": {"severity": "medium", "rule": "syslog_approved",
                                           "approved_servers": ["10.0.0.60"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is False
        assert "No syslog servers configured" in r.detail


class TestMultipleViolations:
    def test_multiple_bad_vlans(self):
        snap = _snap("sw01", [
            "interface Gi0/1", " switchport access vlan 1",
            "interface Gi0/2", " switchport access vlan 999",
        ])
        bl = {"checks": {"inactive_ports": {"severity": "high", "rule": "no_open_ports",
                                            "allowed_vlans": [10, 20], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "Gi0/1" in r.detail
        assert "Gi0/2" in r.detail

    def test_multiple_bad_ntp_servers(self):
        snap = _snap("rtr01", ["ntp server 8.8.8.8", "ntp server 1.1.1.1"])
        bl = {"checks": {"ntp_config": {"severity": "medium", "rule": "ntp_approved",
                                        "approved_servers": ["10.0.0.50"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False
        assert "8.8.8.8" in r.detail
        assert "1.1.1.1" in r.detail


class TestMixedResults:
    def test_some_pass_some_fail(self):
        snap = _snap("rtr01", [
            "ip ssh version 2",
            "ntp server 8.8.8.8",
        ])
        bl = {"checks": {
            "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""},
            "ntp_config": {"severity": "medium", "rule": "ntp_approved",
                           "approved_servers": ["10.0.0.50"], "description": ""},
        }}
        results = run_checks(snap, bl)
        ssh = [x for x in results if x.check_name == "ssh_v2_only"][0]
        ntp = [x for x in results if x.check_name == "ntp_config"][0]
        assert ssh.passed is True
        assert ntp.passed is False


class TestEmptyChecks:
    def test_empty_checks_returns_empty(self):
        snap = _snap("rtr01", ["ip ssh version 2"])
        bl = {"checks": {}}
        results = run_checks(snap, bl)
        assert results == []
