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


class TestSshVersionCaseInsensitive:
    """SSH version check handles mixed-case config lines."""

    def test_uppercase_ip_ssh(self):
        snap = _snap("rtr01", ["IP SSH VERSION 2"])
        bl = {"checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True

    def test_mixed_case(self):
        snap = _snap("rtr01", ["Ip Ssh Version 2"])
        bl = {"checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True

    def test_v1_mixed_case(self):
        snap = _snap("rtr01", ["Ip Ssh Version 1"])
        bl = {"checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is False


class TestOpenPortsRealWorldConfig:
    """VLAN check handles real-world config blocks with indentation."""

    def test_indented_interface_block(self):
        """Standard Cisco config with indented child lines."""
        snap = _snap("sw01", [
            "interface GigabitEthernet0/1",
            " switchport mode access",
            " switchport access vlan 10",
            "!",
            "interface GigabitEthernet0/2",
            " switchport mode access",
            " switchport access vlan 999",
        ])
        bl = {"checks": {"inactive_ports": {"severity": "high", "rule": "no_open_ports",
                                            "allowed_vlans": [10, 20], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "GigabitEthernet0/2" in r.detail
        assert "999" in r.detail

    def test_no_violation_with_indented_block(self):
        snap = _snap("sw01", [
            "interface GigabitEthernet0/1",
            " switchport access vlan 10",
            "interface GigabitEthernet0/2",
            " switchport access vlan 20",
        ])
        bl = {"checks": {"inactive_ports": {"severity": "high", "rule": "no_open_ports",
                                            "allowed_vlans": [10, 20], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is True

    def test_case_insensitive_vlan_check(self):
        snap = _snap("sw01", [
            "interface Gi0/1",
            " SWITCHPORT ACCESS VLAN 999",
        ])
        bl = {"checks": {"inactive_ports": {"severity": "high", "rule": "no_open_ports",
                                            "allowed_vlans": [10], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False

    def test_interface_with_description_and_other_lines(self):
        """Interface block with description, spanning-tree, etc. before VLAN."""
        snap = _snap("sw01", [
            "interface GigabitEthernet0/1",
            " description User Port",
            " spanning-tree portfast",
            " switchport access vlan 1",
        ])
        bl = {"checks": {"inactive_ports": {"severity": "high", "rule": "no_open_ports",
                                            "allowed_vlans": [10], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "GigabitEthernet0/1" in r.detail

    def test_multiple_interfaces_mixed(self):
        """Multiple interfaces, some passing some failing."""
        snap = _snap("sw01", [
            "interface Gi0/1",
            " switchport access vlan 10",
            "interface Gi0/2",
            " switchport access vlan 999",
            "interface Gi0/3",
            " switchport access vlan 20",
        ])
        bl = {"checks": {"inactive_ports": {"severity": "high", "rule": "no_open_ports",
                                            "allowed_vlans": [10, 20], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "Gi0/2" in r.detail
        assert "Gi0/1" not in r.detail
        assert "Gi0/3" not in r.detail


class TestNtpCaseInsensitive:
    """NTP check handles mixed-case config lines."""

    def test_uppercase_ntp(self):
        snap = _snap("rtr01", ["NTP SERVER 10.0.0.50"])
        bl = {"checks": {"ntp_config": {"severity": "medium", "rule": "ntp_approved",
                                        "approved_servers": ["10.0.0.50"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is True

    def test_mixed_case_ntp(self):
        snap = _snap("rtr01", ["Ntp Server 8.8.8.8"])
        bl = {"checks": {"ntp_config": {"severity": "medium", "rule": "ntp_approved",
                                        "approved_servers": ["10.0.0.50"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False


class TestSyslogCaseInsensitive:
    """Syslog check handles mixed-case config lines."""

    def test_uppercase_logging(self):
        snap = _snap("rtr01", ["LOGGING HOST 10.0.0.60"])
        bl = {"checks": {"syslog_config": {"severity": "medium", "rule": "syslog_approved",
                                           "approved_servers": ["10.0.0.60"], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is True


class TestEmptyAndCommentLines:
    """Checks handle configs with blank lines and comments gracefully."""

    def test_config_with_comments_and_blanks(self):
        snap = _snap("sw01", [
            "!",
            "interface Gi0/1",
            " switchport access vlan 10",
            "!",
            "",
            "interface Gi0/2",
            " switchport access vlan 20",
        ])
        bl = {"checks": {"inactive_ports": {"severity": "high", "rule": "no_open_ports",
                                            "allowed_vlans": [10, 20], "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is True

    def test_ssh_with_surrounding_noise(self):
        snap = _snap("rtr01", [
            "hostname rtr01",
            "!",
            "ip ssh version 2",
            "end",
        ])
        bl = {"checks": {"ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}}}
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True
