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
        """NTP line with fewer than 3 parts is skipped, no valid servers found."""
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
        # Short line skipped, no valid servers -> violations empty -> passes
        assert r.passed is True

    def test_syslog_short_line_no_valid_servers(self):
        """Syslog line with fewer than 3 parts is skipped, no valid servers found."""
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
        assert r.passed is True

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

    def test_multiple_ssh_lines_first_wins(self):
        """When multiple SSH version lines exist, first match wins."""
        snap = _snap("rtr01", ["ip ssh version 1", "ip ssh version 2"])
        bl = {
            "checks": {
                "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""}
            }
        }
        r = [x for x in run_checks(snap, bl) if x.check_name == "ssh_v2_only"][0]
        # fail_value "version 1" is checked before ok_value "version 2"
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
        assert "snmp-server community" in r.detail

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
        assert "public" in r.detail

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
        assert "public" in r.detail


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
