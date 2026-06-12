import pytest
from net_audit.parser import parse_interfaces, parse_version, parse_config
from net_audit.exceptions import ParseError


class TestParseInterfaces:
    def test_basic_table(self):
        raw = (
            "Interface              IP-Address      OK? Method Status                Protocol\n"
            "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up\n"
            "GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down"
        )
        result = parse_interfaces(raw)
        assert len(result) == 2
        assert result[0]["interface"] == "GigabitEthernet0/0"
        assert result[0]["status"] == "up"

    def test_empty_input(self):
        assert parse_interfaces("") == []


class TestParseVersion:
    def test_parses_version(self):
        raw = (
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
            "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
            "router uptime is 5 days, 3 hours, 22 minutes"
        )
        result = parse_version(raw)
        assert "15.2" in result.get("version", "")
        assert "5 days" in result.get("uptime", "")

    def test_parses_serial(self):
        raw = (
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
            "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
            "router uptime is 5 days, 3 hours, 22 minutes\n\n"
            "System Serial Number               : 98DVJUONW1X\n"
        )
        result = parse_version(raw)
        assert result.get("serial") == "98DVJUONW1X"

    def test_serial_missing(self):
        """Output without serial number produces empty string."""
        raw = (
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
            "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
            "router uptime is 5 days, 3 hours, 22 minutes"
        )
        result = parse_version(raw)
        assert result.get("serial", "") == ""

    def test_unknown(self):
        assert parse_version("") == {}


class TestParseConfig:
    def test_splits_lines(self):
        raw = "hostname rtr01\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0"
        result = parse_config(raw)
        assert "hostname rtr01" in result
        assert len(result) == 3

    def test_empty(self):
        assert parse_config("") == []


class TestParserErrorPaths:
    def test_missing_template_returns_empty(self, tmp_path, monkeypatch):
        """When template file doesn't exist, parse_interfaces returns []."""
        import net_audit.parser as parser_mod

        monkeypatch.setattr(parser_mod, "TEMPLATE_DIR", tmp_path / "nonexistent")
        result = parse_interfaces("some raw output")
        assert result == []

    def test_malformed_output_returns_empty(self):
        """When raw output doesn't match template, returns empty list."""
        raw = "this is garbage that won't match any template"
        result = parse_interfaces(raw)
        assert result == []

    def test_whitespace_only_input(self):
        """Whitespace-only input returns empty."""
        assert parse_interfaces("   \n  \n  ") == []
        assert parse_version("   \n  ") == {}
        assert parse_config("   \n  ") == []

    def test_version_no_match(self):
        """Version output that doesn't match template returns empty dict."""
        raw = "some random text without version info"
        result = parse_version(raw)
        assert result == {}

    def test_corrupt_template_raises_parse_error(self, tmp_path, monkeypatch):
        """A corrupt TextFSM template raises ParseError."""
        import net_audit.parser as parser_mod

        bad_template_dir = tmp_path / "templates"
        bad_template_dir.mkdir()
        bad_template = bad_template_dir / "cisco_ios_show_ip_interface_brief.textfsm"
        bad_template.write_text("This is not a valid TextFSM template {{{")
        monkeypatch.setattr(parser_mod, "TEMPLATE_DIR", bad_template_dir)
        with pytest.raises(ParseError, match="Template error"):
            parse_interfaces("some raw output")


class TestParserVendorDispatch:
    """Tests for vendor-aware template selection in parser functions."""

    def test_parse_interfaces_uses_cisco_ios_by_default(self):
        """Default device_type='cisco_ios' uses cisco_ios templates."""
        raw = (
            "Interface              IP-Address      OK? Method Status                Protocol\n"
            "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"
        )
        result = parse_interfaces(raw)
        assert len(result) == 1
        assert result[0]["interface"] == "GigabitEthernet0/0"

    def test_parse_interfaces_with_explicit_cisco_ios(self):
        """Explicitly passing cisco_ios works the same as default."""
        raw = (
            "Interface              IP-Address      OK? Method Status                Protocol\n"
            "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"
        )
        result = parse_interfaces(raw, device_type="cisco_ios")
        assert len(result) == 1

    def test_parse_interfaces_unknown_vendor_falls_back(self):
        """Unknown device_type falls back to cisco_ios templates."""
        raw = (
            "Interface              IP-Address      OK? Method Status                Protocol\n"
            "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"
        )
        result = parse_interfaces(raw, device_type="juniper_junos")
        assert len(result) == 1

    def test_parse_version_uses_cisco_ios_by_default(self):
        raw = (
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
            "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
            "router uptime is 5 days, 3 hours, 22 minutes"
        )
        result = parse_version(raw)
        assert "15.2" in result.get("version", "")

    def test_parse_version_with_explicit_vendor(self):
        raw = (
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
            "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
            "router uptime is 5 days, 3 hours, 22 minutes"
        )
        result = parse_version(raw, device_type="cisco_ios")
        assert "15.2" in result.get("version", "")

    def test_parse_config_ignores_device_type(self):
        """parse_config is vendor-agnostic; device_type is accepted but doesn't change behavior."""
        raw = "hostname rtr01\ninterface Gi0/0"
        result_default = parse_config(raw)
        result_vendor = parse_config(raw, device_type="arista_eos")
        assert result_default == result_vendor
        assert len(result_default) == 2

    def test_parse_interfaces_empty_with_vendor(self):
        assert parse_interfaces("", device_type="cisco_ios") == []
        assert parse_interfaces("   ", device_type="arista_eos") == []

    def test_parse_version_empty_with_vendor(self):
        assert parse_version("", device_type="cisco_ios") == {}
        assert parse_version("   ", device_type="cisco_nxos") == {}
