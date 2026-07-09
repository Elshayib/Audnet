from audnet.compliance import run_checks
from audnet.models import DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig


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
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True

    def test_fail_v1(self):
        snap = _snap("rtr01", ["ip ssh version 1"])
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is False

    def test_fail_missing(self):
        snap = _snap("rtr01", ["hostname rtr01"])
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is False


class TestInactivePorts:
    def test_pass(self):
        snap = _snap("sw01", ["interface Gi0/1", " switchport access vlan 10"])
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is True

    def test_fail_bad_vlan(self):
        snap = _snap("sw01", ["interface Gi0/1", " switchport access vlan 1"])
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False


class TestNtpConfig:
    def test_pass(self):
        snap = _snap("rtr01", ["ntp server 10.0.0.50"])
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "medium",
                    "rule": "ntp_approved",
                    "approved_servers": ["10.0.0.50"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is True

    def test_fail(self):
        snap = _snap("rtr01", ["ntp server 8.8.8.8"])
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "medium",
                    "rule": "ntp_approved",
                    "approved_servers": ["10.0.0.50"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False


class TestSyslogConfig:
    def test_pass(self):
        snap = _snap("rtr01", ["logging host 10.0.0.60"])
        bl = {
            "checks": {
                "syslog_config": {
                    "severity": "medium",
                    "rule": "syslog_approved",
                    "approved_servers": ["10.0.0.60"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is True

    def test_fail(self):
        snap = _snap("rtr01", ["logging host 192.168.99.99"])
        bl = {
            "checks": {
                "syslog_config": {
                    "severity": "medium",
                    "rule": "syslog_approved",
                    "approved_servers": ["10.0.0.60"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is False


class TestUnknownRule:
    def test_unknown_rule_returns_fail(self):
        snap = _snap("rtr01", ["ip ssh version 2"])
        bl = {
            "checks": {
                "custom_check": {"severity": "low", "rule": "nonexistent_rule", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "custom_check"][0]
        assert r.passed is False
        assert "Unknown rule" in r.detail


class TestNoNtpConfigured:
    def test_no_servers_configured_fails(self):
        snap = _snap("rtr01", ["hostname rtr01"])
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "medium",
                    "rule": "ntp_approved",
                    "approved_servers": ["10.0.0.50"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False
        assert "No NTP servers configured" in r.detail


class TestNoSyslogConfigured:
    def test_no_servers_configured_fails(self):
        snap = _snap("rtr01", ["hostname rtr01"])
        bl = {
            "checks": {
                "syslog_config": {
                    "severity": "medium",
                    "rule": "syslog_approved",
                    "approved_servers": ["10.0.0.60"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is False
        assert "No syslog servers configured" in r.detail


class TestMultipleViolations:
    def test_multiple_bad_vlans(self):
        snap = _snap(
            "sw01",
            [
                "interface Gi0/1",
                " switchport access vlan 1",
                "interface Gi0/2",
                " switchport access vlan 999",
            ],
        )
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "Gi0/1" in r.detail
        assert "Gi0/2" in r.detail

    def test_multiple_bad_ntp_servers(self):
        snap = _snap("rtr01", ["ntp server 8.8.8.8", "ntp server 1.1.1.1"])
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "medium",
                    "rule": "ntp_approved",
                    "approved_servers": ["10.0.0.50"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False
        assert "8.8.8.8" in r.detail
        assert "1.1.1.1" in r.detail


class TestMixedResults:
    def test_some_pass_some_fail(self):
        snap = _snap(
            "rtr01",
            [
                "ip ssh version 2",
                "ntp server 8.8.8.8",
            ],
        )
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""},
                "ntp_config": {
                    "severity": "medium",
                    "rule": "ntp_approved",
                    "approved_servers": ["10.0.0.50"],
                    "description": "",
                },
            }
        }
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
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True

    def test_mixed_case(self):
        snap = _snap("rtr01", ["Ip Ssh Version 2"])
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True

    def test_v1_mixed_case(self):
        snap = _snap("rtr01", ["Ip Ssh Version 1"])
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is False


class TestOpenPortsRealWorldConfig:
    """VLAN check handles real-world config blocks with indentation."""

    def test_indented_interface_block(self):
        """Standard Cisco config with indented child lines."""
        snap = _snap(
            "sw01",
            [
                "interface GigabitEthernet0/1",
                " switchport mode access",
                " switchport access vlan 10",
                "!",
                "interface GigabitEthernet0/2",
                " switchport mode access",
                " switchport access vlan 999",
            ],
        )
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "GigabitEthernet0/2" in r.detail
        assert "999" in r.detail

    def test_no_violation_with_indented_block(self):
        snap = _snap(
            "sw01",
            [
                "interface GigabitEthernet0/1",
                " switchport access vlan 10",
                "interface GigabitEthernet0/2",
                " switchport access vlan 20",
            ],
        )
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is True

    def test_case_insensitive_vlan_check(self):
        snap = _snap(
            "sw01",
            [
                "interface Gi0/1",
                " SWITCHPORT ACCESS VLAN 999",
            ],
        )
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False

    def test_interface_with_description_and_other_lines(self):
        """Interface block with description, spanning-tree, etc. before VLAN."""
        snap = _snap(
            "sw01",
            [
                "interface GigabitEthernet0/1",
                " description User Port",
                " spanning-tree portfast",
                " switchport access vlan 1",
            ],
        )
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "GigabitEthernet0/1" in r.detail

    def test_multiple_interfaces_mixed(self):
        """Multiple interfaces, some passing some failing."""
        snap = _snap(
            "sw01",
            [
                "interface Gi0/1",
                " switchport access vlan 10",
                "interface Gi0/2",
                " switchport access vlan 999",
                "interface Gi0/3",
                " switchport access vlan 20",
            ],
        )
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "Gi0/2" in r.detail
        assert "Gi0/1" not in r.detail
        assert "Gi0/3" not in r.detail

    def test_long_interface_block_over_10_lines(self):
        """Interface block with >10 lines before switchport access vlan still attributed correctly."""
        snap = _snap(
            "sw01",
            [
                "interface GigabitEthernet0/1",
                " description User Access Port",
                " ip access-group ACL_USER_IN in",
                " ip access-group ACL_USER_OUT out",
                " ip helper-address 10.0.0.1",
                " ip helper-address 10.0.0.2",
                " spanning-tree portfast",
                " spanning-tree bpduguard enable",
                " storm-control broadcast level 20.00",
                " storm-control multicast level 20.00",
                " switchport access vlan 999",
                " switchport mode access",
            ],
        )
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "GigabitEthernet0/1" in r.detail
        assert "999" in r.detail

    def test_no_interface_line_before_vlan(self):
        """VLAN line with no preceding interface line reports 'unknown'."""
        snap = _snap(
            "sw01",
            [
                "hostname sw01",
                " switchport access vlan 999",
            ],
        )
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "unknown" in r.detail


class TestNtpCaseInsensitive:
    """NTP check handles mixed-case config lines."""

    def test_uppercase_ntp(self):
        snap = _snap("rtr01", ["NTP SERVER 10.0.0.50"])
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "medium",
                    "rule": "ntp_approved",
                    "approved_servers": ["10.0.0.50"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is True

    def test_mixed_case_ntp(self):
        snap = _snap("rtr01", ["Ntp Server 8.8.8.8"])
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "medium",
                    "rule": "ntp_approved",
                    "approved_servers": ["10.0.0.50"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False


class TestSyslogCaseInsensitive:
    """Syslog check handles mixed-case config lines."""

    def test_uppercase_logging(self):
        snap = _snap("rtr01", ["LOGGING HOST 10.0.0.60"])
        bl = {
            "checks": {
                "syslog_config": {
                    "severity": "medium",
                    "rule": "syslog_approved",
                    "approved_servers": ["10.0.0.60"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is True


class TestEmptyAndCommentLines:
    """Checks handle configs with blank lines and comments gracefully."""

    def test_config_with_comments_and_blanks(self):
        snap = _snap(
            "sw01",
            [
                "!",
                "interface Gi0/1",
                " switchport access vlan 10",
                "!",
                "",
                "interface Gi0/2",
                " switchport access vlan 20",
            ],
        )
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is True

    def test_ssh_with_surrounding_noise(self):
        """SSH check works when surrounded by unrelated config lines."""
        snap = _snap(
            "rtr01",
            [
                "hostname rtr01",
                "!",
                "ip ssh version 2",
                "end",
            ],
        )
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True


class TestComplianceEdgeCases:
    """Edge-case tests for compliance checks covering missed branches."""

    def test_ssh_unexpected_line_fails(self):
        """SSH line that matches neither ok_value nor fail_value fails."""
        snap = _snap("rtr01", ["ip ssh version 3"])
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is False
        assert "unexpected" in r.detail.lower() or "version 3" in r.detail

    def test_vendor_patterns_default_override(self):
        """vendor_patterns with 'default' key overrides base patterns."""
        snap = _snap("rtr01", ["custom-ssh directive"])
        bl = {
            "checks": {
                "ssh_v2_only": {
                    "severity": "critical",
                    "rule": "ssh_v2_only",
                    "description": "",
                    "vendor_patterns": {
                        "default": {
                            "match": "custom-ssh",
                            "ok_value": "directive",
                            "fail_value": "bad",
                            "ok_detail": "ok",
                            "fail_detail_v1": "v1",
                            "fail_detail_missing": "missing",
                            "fail_detail_unexpected": "unexpected",
                        }
                    },
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True

    def test_vendor_patterns_non_dict_ignored(self):
        """vendor_patterns that is not a dict is safely ignored."""
        snap = _snap("rtr01", ["ip ssh version 2"])
        bl = {
            "checks": {
                "ssh_v2_only": {
                    "severity": "critical",
                    "rule": "ssh_v2_only",
                    "description": "",
                    "vendor_patterns": "not-a-dict",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True

    def test_vendor_patterns_default_non_dict_ignored(self):
        """vendor_patterns default that is not a dict is safely ignored."""
        snap = _snap("rtr01", ["ip ssh version 2"])
        bl = {
            "checks": {
                "ssh_v2_only": {
                    "severity": "critical",
                    "rule": "ssh_v2_only",
                    "description": "",
                    "vendor_patterns": {"default": "not-a-dict"},
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is True

    def test_open_ports_short_interface_line_skipped(self):
        """Interface line with fewer than 4 parts is skipped."""
        snap = _snap("rtr01", ["interface GigabitEthernet0/1", " switchport"])
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "description": "",
                    "allowed_vlans": [10, 20],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is True

    def test_open_ports_interface_name_not_found(self):
        """When no interface prefix line is found before a VLAN line, iface is 'unknown'."""
        snap = _snap("rtr01", [" switchport access vlan 99"])
        bl = {
            "checks": {
                "inactive_ports": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "description": "",
                    "allowed_vlans": [10, 20],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "inactive_ports"][0]
        assert r.passed is False
        assert "unknown" in r.detail

    def test_ntp_short_line_no_valid_servers(self):
        """Incomplete NTP lines are configuration defects and must fail."""
        snap = _snap("rtr01", ["ntp server"])
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "high",
                    "rule": "ntp_approved",
                    "description": "",
                    "approved_servers": ["10.0.0.1"],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False
        assert "incomplete" in r.detail.lower()

    def test_ntp_vrf_syntax_server_approved(self):
        """IOS-XE 'ntp server vrf <name> <ip>' with approved IP passes."""
        snap = _snap(
            "rtr01",
            ["ntp server 10.0.0.1", "ntp server vrf Mgmt-vrf 10.0.0.1"],
        )
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "high",
                    "rule": "ntp_approved",
                    "description": "",
                    "approved_servers": ["10.0.0.1"],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is True

    def test_ntp_vrf_syntax_server_unapproved(self):
        """IOS-XE 'ntp server vrf <name> <ip>' with unapproved IP fails."""
        snap = _snap(
            "rtr01",
            ["ntp server vrf Mgmt-vrf 8.8.8.8"],
        )
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "high",
                    "rule": "ntp_approved",
                    "description": "",
                    "approved_servers": ["10.0.0.1"],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False
        assert "8.8.8.8" in r.detail
        assert "vrf" not in r.detail

    def test_ntp_vrf_mixed_with_plain(self):
        """Mix of plain and VRF NTP lines: only unapproved IPs reported."""
        snap = _snap(
            "rtr01",
            [
                "ntp server 10.0.0.1",
                "ntp server vrf Mgmt-vrf 10.0.0.1",
                "ntp server vrf Mgmt-vrf 8.8.8.8",
            ],
        )
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "high",
                    "rule": "ntp_approved",
                    "description": "",
                    "approved_servers": ["10.0.0.1"],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False
        assert "8.8.8.8" in r.detail
        assert "vrf" not in r.detail
        assert "Mgmt-vrf" not in r.detail

    def test_ntp_vrf_case_insensitive(self):
        """VRF keyword is case-insensitive (VRF, vrf, Vrf all work)."""
        snap = _snap(
            "rtr01",
            ["ntp server VRF Mgmt-vrf 8.8.8.8"],
        )
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "high",
                    "rule": "ntp_approved",
                    "description": "",
                    "approved_servers": ["10.0.0.1"],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is False
        assert "8.8.8.8" in r.detail
        assert "VRF" not in r.detail

    def test_ntp_vrf_too_short(self):
        """'ntp server vrf <name>' without IP is skipped (len < 5)."""
        snap = _snap(
            "rtr01",
            ["ntp server vrf Mgmt-vrf"],
        )
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "high",
                    "rule": "ntp_approved",
                    "description": "",
                    "approved_servers": ["10.0.0.1"],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        # Incomplete VRF line is a violation (fail closed)
        assert r.passed is False

    def test_syslog_short_line_no_valid_servers(self):
        """Incomplete syslog lines are configuration defects and must fail."""
        snap = _snap("rtr01", ["logging host"])
        bl = {
            "checks": {
                "syslog_config": {
                    "severity": "high",
                    "rule": "syslog_approved",
                    "description": "",
                    "approved_servers": ["10.0.0.1"],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is False
        assert "incomplete" in r.detail.lower()

    def test_ntp_all_servers_approved(self):
        """All NTP servers in approved list passes."""
        snap = _snap(
            "rtr01",
            ["ntp server 10.0.0.1", "ntp server 10.0.0.2"],
        )
        bl = {
            "checks": {
                "ntp_config": {
                    "severity": "high",
                    "rule": "ntp_approved",
                    "description": "",
                    "approved_servers": ["10.0.0.1", "10.0.0.2"],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ntp_config"][0]
        assert r.passed is True

    def test_syslog_all_servers_approved(self):
        """All syslog servers in approved list passes."""
        snap = _snap(
            "rtr01",
            ["logging host 10.0.0.1", "logging host 10.0.0.2"],
        )
        bl = {
            "checks": {
                "syslog_config": {
                    "severity": "high",
                    "rule": "syslog_approved",
                    "description": "",
                    "approved_servers": ["10.0.0.1", "10.0.0.2"],
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "syslog_config"][0]
        assert r.passed is True

    def test_multiple_ssh_lines_v1_anywhere_fails(self):
        """SSHv1 anywhere fails even if SSHv2 also appears (evaluate all lines)."""
        snap = _snap("rtr01", ["ip ssh version 2", "ip ssh version 1"])
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        assert r.passed is False


class TestRenamedCheckPropagation:
    """Baseline key name should propagate to ComplianceResult.check_name."""

    def test_renamed_ssh_check(self):
        snap = _snap("rtr01", ["ip ssh version 2"])
        bl = {
            "checks": {
                "my_ssh_check": {
                    "severity": "critical",
                    "rule": "ssh_v2_only",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "my_ssh_check"][0]
        assert r.passed is True

    def test_renamed_vlan_check(self):
        snap = _snap("sw01", ["interface Gi0/1", " switchport access vlan 999"])
        bl = {
            "checks": {
                "vlan_policy": {
                    "severity": "high",
                    "rule": "no_open_ports",
                    "allowed_vlans": [10],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "vlan_policy"][0]
        assert r.passed is False
        assert "999" in r.detail

    def test_renamed_ntp_check(self):
        snap = _snap("rtr01", ["ntp server 8.8.8.8"])
        bl = {
            "checks": {
                "time_servers": {
                    "severity": "medium",
                    "rule": "ntp_approved",
                    "approved_servers": ["10.0.0.50"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "time_servers"][0]
        assert r.passed is False
        assert "8.8.8.8" in r.detail

    def test_renamed_syslog_check(self):
        snap = _snap("rtr01", ["logging host 192.168.99.99"])
        bl = {
            "checks": {
                "log_servers": {
                    "severity": "medium",
                    "rule": "syslog_approved",
                    "approved_servers": ["10.0.0.60"],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "log_servers"][0]
        assert r.passed is False
        assert "192.168.99.99" in r.detail


class TestSnmpV3Only:
    """Tests for the snmp_v3_only compliance check (CIS 3.1)."""

    def test_fail_when_community_string_present(self):
        """Fails when any snmp-server community line is found."""
        snap = _snap("rtr01", ["snmp-server community public RO"])
        bl = {
            "checks": {
                "snmp_v3_only": {
                    "severity": "critical",
                    "rule": "snmp_v3_only",
                    "description": "SNMPv1/v2c community strings must not be configured",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "snmp_v3_only"][0]
        assert r.passed is False
        # Community values are redacted in details
        assert "snmp-server community" in r.detail
        assert "public" not in r.detail
        assert "***" in r.detail

    def test_fail_multiple_community_strings(self):
        """Fails and reports all community string lines."""
        snap = _snap(
            "rtr01",
            [
                "snmp-server community public RO",
                "snmp-server community private RW",
            ],
        )
        bl = {
            "checks": {
                "snmp_v3_only": {
                    "severity": "critical",
                    "rule": "snmp_v3_only",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "snmp_v3_only"][0]
        assert r.passed is False
        # Community names redacted; both lines still reported
        assert r.detail.count("***") >= 2
        assert "public" not in r.detail
        assert "private" not in r.detail

    def test_pass_when_no_community_strings(self):
        """Passes when no snmp-server community lines exist."""
        snap = _snap("rtr01", ["hostname rtr01", "ip ssh version 2"])
        bl = {
            "checks": {
                "snmp_v3_only": {
                    "severity": "critical",
                    "rule": "snmp_v3_only",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "snmp_v3_only"][0]
        assert r.passed is True
        assert "No SNMPv1/v2c" in r.detail

    def test_pass_with_snmp_v3_group_only(self):
        """Passes when SNMPv3 group is configured but no community strings."""
        snap = _snap(
            "rtr01",
            [
                "snmp-server group mygroup v3 priv",
                "snmp-server user admin mygroup v3",
            ],
        )
        bl = {
            "checks": {
                "snmp_v3_only": {
                    "severity": "critical",
                    "rule": "snmp_v3_only",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "snmp_v3_only"][0]
        assert r.passed is True

    def test_case_insensitive(self):
        """Check is case-insensitive for community string matching."""
        snap = _snap("rtr01", ["SNMP-SERVER COMMUNITY Public RO"])
        bl = {
            "checks": {
                "snmp_v3_only": {
                    "severity": "critical",
                    "rule": "snmp_v3_only",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "snmp_v3_only"][0]
        assert r.passed is False

    def test_fail_with_community_and_v3_present(self):
        """Fails if community strings exist even when v3 is also configured."""
        snap = _snap(
            "rtr01",
            [
                "snmp-server group mygroup v3 priv",
                "snmp-server community public RO",
            ],
        )
        bl = {
            "checks": {
                "snmp_v3_only": {
                    "severity": "critical",
                    "rule": "snmp_v3_only",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "snmp_v3_only"][0]
        assert r.passed is False
        assert "***" in r.detail
        assert "public" not in r.detail


class TestUnusedIfaceShutdown:
    """Tests for the unused_iface_shutdown compliance check (NIST CM-6)."""

    def _snap_with_interfaces(self, name, config_lines, interfaces=None):
        return DeviceSnapshot(
            device_name=name,
            interfaces=ParsedInterfaces(interfaces=interfaces or []),
            version=ParsedVersion(),
            config=ParsedConfig(lines=config_lines),
        )

    def test_fail_unused_interface_no_shutdown(self):
        """Fails when an interface without IP and not in allowed VLAN is not shut down."""
        snap = self._snap_with_interfaces(
            "sw01",
            [
                "interface GigabitEthernet0/1",
                " switchport access vlan 999",
                "!",
                "interface GigabitEthernet0/2",
                " shutdown",
            ],
        )
        bl = {
            "checks": {
                "unused_iface_shutdown": {
                    "severity": "medium",
                    "rule": "unused_iface_shutdown",
                    "allowed_vlans": [10, 20, 30],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "unused_iface_shutdown"][0]
        assert r.passed is False
        assert "GigabitEthernet0/1" in r.detail

    def test_pass_all_unused_interfaces_shutdown(self):
        """Passes when all unused interfaces are administratively shut down."""
        snap = self._snap_with_interfaces(
            "sw01",
            [
                "interface GigabitEthernet0/1",
                " switchport access vlan 999",
                " shutdown",
                "!",
                "interface GigabitEthernet0/2",
                " switchport access vlan 888",
                " shutdown",
            ],
        )
        bl = {
            "checks": {
                "unused_iface_shutdown": {
                    "severity": "medium",
                    "rule": "unused_iface_shutdown",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "unused_iface_shutdown"][0]
        assert r.passed is True

    def test_pass_interface_in_allowed_vlan(self):
        """Passes when interface is in allowed VLAN even without shutdown."""
        snap = self._snap_with_interfaces(
            "sw01",
            [
                "interface GigabitEthernet0/1",
                " switchport access vlan 10",
            ],
        )
        bl = {
            "checks": {
                "unused_iface_shutdown": {
                    "severity": "medium",
                    "rule": "unused_iface_shutdown",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "unused_iface_shutdown"][0]
        assert r.passed is True

    def test_pass_interface_with_ip_address(self):
        """Passes when interface has an IP address (routed port) even without shutdown."""
        snap = self._snap_with_interfaces(
            "rtr01",
            [
                "interface GigabitEthernet0/0",
                " ip address 10.0.0.1 255.255.255.0",
                "!",
                "interface GigabitEthernet0/1",
                " shutdown",
            ],
            interfaces=[
                {"interface": "GigabitEthernet0/0", "ip_address": "10.0.0.1"},
            ],
        )
        bl = {
            "checks": {
                "unused_iface_shutdown": {
                    "severity": "medium",
                    "rule": "unused_iface_shutdown",
                    "allowed_vlans": [10],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "unused_iface_shutdown"][0]
        assert r.passed is True

    def test_fail_mixed_active_and_unused(self):
        """Fails listing only the non-compliant interfaces when some are active."""
        snap = self._snap_with_interfaces(
            "sw01",
            [
                "interface GigabitEthernet0/0",
                " ip address 10.0.0.1 255.255.255.0",
                "!",
                "interface GigabitEthernet0/1",
                " switchport access vlan 10",
                "!",
                "interface GigabitEthernet0/2",
                " switchport access vlan 999",
                "!",
                "interface GigabitEthernet0/3",
                " shutdown",
            ],
            interfaces=[
                {"interface": "GigabitEthernet0/0", "ip_address": "10.0.0.1"},
            ],
        )
        bl = {
            "checks": {
                "unused_iface_shutdown": {
                    "severity": "medium",
                    "rule": "unused_iface_shutdown",
                    "allowed_vlans": [10, 20],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "unused_iface_shutdown"][0]
        assert r.passed is False
        assert "GigabitEthernet0/2" in r.detail
        assert "GigabitEthernet0/0" not in r.detail
        assert "GigabitEthernet0/1" not in r.detail
        assert "GigabitEthernet0/3" not in r.detail

    def test_fail_multiple_violations(self):
        """Fails with all non-compliant interface names listed."""
        snap = self._snap_with_interfaces(
            "sw01",
            [
                "interface GigabitEthernet0/1",
                " switchport access vlan 999",
                "!",
                "interface GigabitEthernet0/2",
                " switchport access vlan 888",
                "!",
                "interface GigabitEthernet0/3",
                " switchport access vlan 777",
            ],
        )
        bl = {
            "checks": {
                "unused_iface_shutdown": {
                    "severity": "medium",
                    "rule": "unused_iface_shutdown",
                    "allowed_vlans": [10],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "unused_iface_shutdown"][0]
        assert r.passed is False
        assert "GigabitEthernet0/1" in r.detail
        assert "GigabitEthernet0/2" in r.detail
        assert "GigabitEthernet0/3" in r.detail

    def test_pass_no_interfaces(self):
        """Passes when there are no interface blocks in config."""
        snap = self._snap_with_interfaces(
            "rtr01",
            ["hostname rtr01", "ip ssh version 2"],
        )
        bl = {
            "checks": {
                "unused_iface_shutdown": {
                    "severity": "medium",
                    "rule": "unused_iface_shutdown",
                    "allowed_vlans": [10],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "unused_iface_shutdown"][0]
        assert r.passed is True

    def test_interface_with_unassigned_ip_not_active(self):
        """Interface with 'unassigned' IP is not considered active."""
        snap = self._snap_with_interfaces(
            "rtr01",
            [
                "interface GigabitEthernet0/1",
                " ip address unassigned",
            ],
            interfaces=[
                {"interface": "GigabitEthernet0/1", "ip_address": "unassigned"},
            ],
        )
        bl = {
            "checks": {
                "unused_iface_shutdown": {
                    "severity": "medium",
                    "rule": "unused_iface_shutdown",
                    "allowed_vlans": [10],
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "unused_iface_shutdown"][0]
        assert r.passed is False
        assert "GigabitEthernet0/1" in r.detail


class TestVtyTimeout:
    """Tests for the vty_timeout compliance check (CIS 2.1)."""

    def _snap(self, name, config_lines):
        return DeviceSnapshot(
            device_name=name,
            interfaces=ParsedInterfaces(interfaces=[]),
            version=ParsedVersion(),
            config=ParsedConfig(lines=config_lines),
        )

    def test_pass_within_limit(self):
        """Passes when exec-timeout is within the allowed limit."""
        snap = self._snap(
            "rtr01",
            [
                "line vty 0 4",
                " exec-timeout 5 0",
                " login local",
            ],
        )
        bl = {
            "checks": {
                "vty_timeout": {
                    "severity": "high",
                    "rule": "vty_timeout",
                    "max_timeout_minutes": 10,
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "vty_timeout"][0]
        assert r.passed is True

    def test_pass_at_boundary(self):
        """Passes when exec-timeout equals the max."""
        snap = self._snap(
            "rtr01",
            [
                "line vty 0 4",
                " exec-timeout 10 0",
            ],
        )
        bl = {
            "checks": {
                "vty_timeout": {
                    "severity": "high",
                    "rule": "vty_timeout",
                    "max_timeout_minutes": 10,
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "vty_timeout"][0]
        assert r.passed is True

    def test_fail_exceeds_limit(self):
        """Fails when exec-timeout exceeds the max."""
        snap = self._snap(
            "rtr01",
            [
                "line vty 0 4",
                " exec-timeout 15 0",
            ],
        )
        bl = {
            "checks": {
                "vty_timeout": {
                    "severity": "high",
                    "rule": "vty_timeout",
                    "max_timeout_minutes": 10,
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "vty_timeout"][0]
        assert r.passed is False
        assert "15min" in r.detail

    def test_fail_missing_timeout(self):
        """Fails when exec-timeout is missing from VTY block."""
        snap = self._snap(
            "rtr01",
            [
                "line vty 0 4",
                " login local",
            ],
        )
        bl = {
            "checks": {
                "vty_timeout": {
                    "severity": "high",
                    "rule": "vty_timeout",
                    "max_timeout_minutes": 10,
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "vty_timeout"][0]
        assert r.passed is False
        assert "missing" in r.detail.lower()

    def test_multiple_vty_ranges(self):
        """Checks multiple VTY line ranges."""
        snap = self._snap(
            "rtr01",
            [
                "line vty 0 4",
                " exec-timeout 5 0",
                "line vty 5 15",
                " exec-timeout 15 0",
            ],
        )
        bl = {
            "checks": {
                "vty_timeout": {
                    "severity": "high",
                    "rule": "vty_timeout",
                    "max_timeout_minutes": 10,
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "vty_timeout"][0]
        assert r.passed is False
        assert "vty 5 15" in r.detail

    def test_default_max_timeout(self):
        """Uses default max_timeout_minutes of 10 when not specified."""
        snap = self._snap(
            "rtr01",
            [
                "line vty 0 4",
                " exec-timeout 11 0",
            ],
        )
        bl = {
            "checks": {
                "vty_timeout": {"severity": "high", "rule": "vty_timeout", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "vty_timeout"][0]
        assert r.passed is False


class TestAaaAuth:
    """Tests for the aaa_auth compliance check (NIST AC-2)."""

    def _snap(self, name, config_lines):
        return DeviceSnapshot(
            device_name=name,
            interfaces=ParsedInterfaces(interfaces=[]),
            version=ParsedVersion(),
            config=ParsedConfig(lines=config_lines),
        )

    def test_pass_both_present(self):
        """Passes when both aaa new-model and aaa authentication login default are present."""
        snap = self._snap(
            "rtr01",
            [
                "aaa new-model",
                "aaa authentication login default group tacacs+ local",
            ],
        )
        bl = {
            "checks": {"aaa_auth": {"severity": "critical", "rule": "aaa_auth", "description": ""}}
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "aaa_auth"][0]
        assert r.passed is True

    def test_fail_missing_new_model(self):
        """Fails when aaa new-model is absent."""
        snap = self._snap(
            "rtr01",
            [
                "aaa authentication login default group tacacs+ local",
            ],
        )
        bl = {
            "checks": {"aaa_auth": {"severity": "critical", "rule": "aaa_auth", "description": ""}}
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "aaa_auth"][0]
        assert r.passed is False
        assert "aaa new-model" in r.detail

    def test_fail_missing_auth_login(self):
        """Fails when aaa authentication login default is absent."""
        snap = self._snap(
            "rtr01",
            [
                "aaa new-model",
            ],
        )
        bl = {
            "checks": {"aaa_auth": {"severity": "critical", "rule": "aaa_auth", "description": ""}}
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "aaa_auth"][0]
        assert r.passed is False
        assert "aaa authentication login default" in r.detail

    def test_fail_both_missing(self):
        """Fails when both are absent (reports new-model missing first)."""
        snap = self._snap("rtr01", ["hostname rtr01"])
        bl = {
            "checks": {"aaa_auth": {"severity": "critical", "rule": "aaa_auth", "description": ""}}
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "aaa_auth"][0]
        assert r.passed is False
        assert "aaa new-model" in r.detail

    def test_case_insensitive(self):
        """Check is case-insensitive."""
        snap = self._snap(
            "rtr01",
            [
                "AAA NEW-MODEL",
                "AAA AUTHENTICATION LOGIN DEFAULT group tacacs+ local",
            ],
        )
        bl = {
            "checks": {"aaa_auth": {"severity": "critical", "rule": "aaa_auth", "description": ""}}
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "aaa_auth"][0]
        assert r.passed is True


class TestPasswordEncryption:
    """Tests for the password_encryption compliance check (CIS 1.2)."""

    def _snap(self, name, config_lines):
        return DeviceSnapshot(
            device_name=name,
            interfaces=ParsedInterfaces(interfaces=[]),
            version=ParsedVersion(),
            config=ParsedConfig(lines=config_lines),
        )

    def test_pass_when_present(self):
        """Passes when service password-encryption is present."""
        snap = self._snap("rtr01", ["service password-encryption"])
        bl = {
            "checks": {
                "password_encryption": {
                    "severity": "high",
                    "rule": "password_encryption",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "password_encryption"][0]
        assert r.passed is True

    def test_fail_when_absent(self):
        """Fails when service password-encryption is absent."""
        snap = self._snap("rtr01", ["hostname rtr01"])
        bl = {
            "checks": {
                "password_encryption": {
                    "severity": "high",
                    "rule": "password_encryption",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "password_encryption"][0]
        assert r.passed is False

    def test_case_insensitive(self):
        """Check is case-insensitive."""
        snap = self._snap("rtr01", ["SERVICE PASSWORD-ENCRYPTION"])
        bl = {
            "checks": {
                "password_encryption": {
                    "severity": "high",
                    "rule": "password_encryption",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "password_encryption"][0]
        assert r.passed is True


class TestCdpDisabled:
    """Tests for the cdp_disabled compliance check (CIS 4.5)."""

    def _snap(self, name, config_lines, interfaces=None):
        return DeviceSnapshot(
            device_name=name,
            interfaces=ParsedInterfaces(interfaces=interfaces or []),
            version=ParsedVersion(),
            config=ParsedConfig(lines=config_lines),
        )

    def test_pass_global_disable(self):
        """Passes when no cdp run is globally configured."""
        snap = self._snap(
            "rtr01",
            [
                "no cdp run",
                "interface GigabitEthernet0/0",
            ],
        )
        bl = {
            "checks": {
                "cdp_disabled": {"severity": "medium", "rule": "cdp_disabled", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "cdp_disabled"][0]
        assert r.passed is True

    def test_pass_per_interface_disable(self):
        """Passes when all interfaces have no cdp enable."""
        snap = self._snap(
            "rtr01",
            [
                "interface GigabitEthernet0/0",
                " no cdp enable",
                "interface GigabitEthernet0/1",
                " no cdp enable",
            ],
            interfaces=[
                {"interface": "GigabitEthernet0/0", "ip_address": "10.0.0.1"},
                {"interface": "GigabitEthernet0/1", "ip_address": "10.0.0.2"},
            ],
        )
        bl = {
            "checks": {
                "cdp_disabled": {"severity": "medium", "rule": "cdp_disabled", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "cdp_disabled"][0]
        assert r.passed is True

    def test_fail_cdp_active_on_interface(self):
        """Fails when CDP is active on an interface without no cdp enable."""
        snap = self._snap(
            "rtr01",
            [
                "interface GigabitEthernet0/0",
                " ip address 10.0.0.1 255.255.255.0",
            ],
            interfaces=[
                {"interface": "GigabitEthernet0/0", "ip_address": "10.0.0.1"},
            ],
        )
        bl = {
            "checks": {
                "cdp_disabled": {"severity": "medium", "rule": "cdp_disabled", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "cdp_disabled"][0]
        assert r.passed is False
        assert "gigabitethernet0/0" in r.detail

    def test_fail_mixed_interfaces(self):
        """Fails listing only interfaces without CDP disabled."""
        snap = self._snap(
            "rtr01",
            [
                "interface GigabitEthernet0/0",
                " no cdp enable",
                "interface GigabitEthernet0/1",
                " ip address 10.0.0.2 255.255.255.0",
            ],
            interfaces=[
                {"interface": "GigabitEthernet0/0", "ip_address": "10.0.0.1"},
                {"interface": "GigabitEthernet0/1", "ip_address": "10.0.0.2"},
            ],
        )
        bl = {
            "checks": {
                "cdp_disabled": {"severity": "medium", "rule": "cdp_disabled", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "cdp_disabled"][0]
        assert r.passed is False
        assert "gigabitethernet0/1" in r.detail
        assert "gigabitethernet0/0" not in r.detail


class TestLoginBanner:
    """Tests for the login_banner compliance check (CIS 1.3)."""

    def _snap(self, name, config_lines):
        return DeviceSnapshot(
            device_name=name,
            interfaces=ParsedInterfaces(interfaces=[]),
            version=ParsedVersion(),
            config=ParsedConfig(lines=config_lines),
        )

    def test_pass_banner_present(self):
        """Passes when banner login is configured."""
        snap = self._snap(
            "rtr01",
            [
                "banner login ^",
                "Authorized access only",
                "^",
            ],
        )
        bl = {
            "checks": {
                "login_banner": {"severity": "medium", "rule": "login_banner", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "login_banner"][0]
        assert r.passed is True

    def test_fail_banner_missing(self):
        """Fails when banner login is absent."""
        snap = self._snap("rtr01", ["hostname rtr01"])
        bl = {
            "checks": {
                "login_banner": {"severity": "medium", "rule": "login_banner", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "login_banner"][0]
        assert r.passed is False

    def test_pass_with_required_pattern(self):
        """Passes when banner contains the required pattern."""
        snap = self._snap(
            "rtr01",
            [
                "banner login ^",
                "Unauthorized access prohibited",
                "^",
            ],
        )
        bl = {
            "checks": {
                "login_banner": {
                    "severity": "medium",
                    "rule": "login_banner",
                    "required_pattern": "Unauthorized access prohibited",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "login_banner"][0]
        assert r.passed is True

    def test_fail_pattern_mismatch(self):
        """Fails when banner does not contain the required pattern."""
        snap = self._snap(
            "rtr01",
            [
                "banner login ^",
                "Welcome to this device",
                "^",
            ],
        )
        bl = {
            "checks": {
                "login_banner": {
                    "severity": "medium",
                    "rule": "login_banner",
                    "required_pattern": "Unauthorized access prohibited",
                    "description": "",
                }
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "login_banner"][0]
        assert r.passed is False
        assert "Unauthorized access prohibited" in r.detail

    def test_no_pattern_check_when_not_configured(self):
        """Does not check pattern when required_pattern is not in config."""
        snap = self._snap(
            "rtr01",
            [
                "banner login ^",
                "Welcome!",
                "^",
            ],
        )
        bl = {
            "checks": {
                "login_banner": {"severity": "medium", "rule": "login_banner", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "login_banner"][0]
        assert r.passed is True
