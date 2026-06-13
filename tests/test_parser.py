import pytest
from audnet.parser import parse_interfaces, parse_version, parse_config
from audnet.exceptions import ParseError


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
        assert result.get("hostname") == "router"

    def test_parses_hostname(self):
        raw = (
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
            "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
            "Test1 uptime is 2 minutes\n"
        )
        result = parse_version(raw)
        assert result.get("hostname") == "Test1"

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
    def test_missing_template_raises_parse_error(self, tmp_path, monkeypatch):
        """When template file doesn't exist, parse_interfaces raises ParseError."""
        import audnet.parser as parser_mod

        monkeypatch.setattr(parser_mod, "TEMPLATE_DIR", tmp_path / "nonexistent")
        with pytest.raises(ParseError, match="TextFSM template not found"):
            parse_interfaces("some raw output")

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
        import audnet.parser as parser_mod

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


class TestParserNxosTemplates:
    """Tests for cisco_nxos TextFSM template parsing."""

    def test_parse_interfaces_nxos(self):
        """parse_interfaces correctly parses NX-OS show ip interface brief output."""
        raw = (
            'IP Interface Status for VRF "default"(1)\n'
            "Interface            IP Address         Interface Status\n"
            "Vlan10                10.0.0.1          protocol-up/link-up/admin-up\n"
            "Ethernet1/1           192.168.1.1       protocol-up/link-up/admin-up\n"
        )
        result = parse_interfaces(raw, device_type="cisco_nxos")
        assert len(result) == 2
        iface_names = [r["interface"] for r in result]
        assert "Vlan10" in iface_names
        assert "Ethernet1/1" in iface_names

    def test_parse_interfaces_nxos_ip_addresses(self):
        """NX-OS parse produces ip_address field."""
        raw = (
            'IP Interface Status for VRF "default"(1)\n'
            "Interface            IP Address         Interface Status\n"
            "Loopback0             10.255.0.1        protocol-up/link-up/admin-up\n"
        )
        result = parse_interfaces(raw, device_type="cisco_nxos")
        assert len(result) == 1
        assert result[0]["ip_address"] == "10.255.0.1"

    def test_parse_interfaces_nxos_empty(self):
        assert parse_interfaces("", device_type="cisco_nxos") == []

    def test_parse_version_nxos(self):
        """parse_version correctly parses NX-OS show version output."""
        raw = (
            "Cisco Nexus Operating System (NX-OS) Software\n"
            "\n"
            "  BIOS: version 2.12.0\n"
            "  NXOS: version 9.3(7)\n"
            "  cisco Nexus9000 C9372PX chassis\n"
            "  Device name: nxos-switch\n"
            "  Processor Board ID SAL2015ABCD\n"
            "\n"
            "Kernel uptime is 1 day(s), 2 hour(s), 3 minute(s), 4 second(s)\n"
        )
        result = parse_version(raw, device_type="cisco_nxos")
        assert result != {}
        assert "9.3" in result.get("os", "")

    def test_parse_version_nxos_hostname(self):
        raw = (
            "Cisco Nexus Operating System (NX-OS) Software\n"
            "\n"
            "  BIOS: version 2.12.0\n"
            "  NXOS: version 9.3(7)\n"
            "  cisco Nexus9000 C9372PX chassis\n"
            "  Device name: core-switch-01\n"
            "  Processor Board ID SAL2015ABCD\n"
            "\n"
            "Kernel uptime is 0 day(s), 6 hour(s), 0 minute(s), 0 second(s)\n"
        )
        result = parse_version(raw, device_type="cisco_nxos")
        assert result.get("hostname") == "core-switch-01"

    def test_parse_version_nxos_empty(self):
        assert parse_version("", device_type="cisco_nxos") == {}

    def test_parse_config_nxos(self):
        """parse_config for NX-OS splits config lines identically to IOS."""
        raw = "hostname nxos-switch\nfeature ssh\nip ssh version 2"
        result = parse_config(raw, device_type="cisco_nxos")
        assert "hostname nxos-switch" in result
        assert "ip ssh version 2" in result
        assert len(result) == 3


class TestParserAristaTemplates:
    """Tests for arista_eos TextFSM template parsing."""

    def test_parse_interfaces_arista(self):
        """parse_interfaces correctly parses Arista EOS show ip interface brief output."""
        raw = (
            "                                                                        Address\n"
            "Interface        IP Address         Status      Protocol          MTU   Owner\n"
            "---------------- ------------------ ----------- ----------------- ----- -------\n"
            "Ethernet1        10.0.0.1           up          up                1500\n"
            "Management1      192.168.1.2        up          up                1500\n"
        )
        result = parse_interfaces(raw, device_type="arista_eos")
        assert len(result) == 2
        iface_names = [r["interface"] for r in result]
        assert "Ethernet1" in iface_names
        assert "Management1" in iface_names

    def test_parse_interfaces_arista_ip(self):
        raw = (
            "Interface        IP Address         Status      Protocol          MTU\n"
            "Loopback0        10.255.0.1         up          up                65535\n"
        )
        result = parse_interfaces(raw, device_type="arista_eos")
        assert len(result) == 1
        assert result[0]["ip_address"] == "10.255.0.1"

    def test_parse_interfaces_arista_empty(self):
        assert parse_interfaces("", device_type="arista_eos") == []

    def test_parse_version_arista(self):
        """parse_version correctly parses Arista EOS show version output."""
        raw = (
            "Arista DCS-7050TX-64\n"
            "Hardware version:    01.07\n"
            "Serial number:       ZZZ9999999\n"
            "System MAC address:  1234.5678.90ab\n"
            "Software image version: 4.26.2F\n"
            "Architecture:        i686\n"
            "Uptime: 5 days, 3 hours and 24 minutes\n"
            "Total memory: 1893608 kB\n"
            "Free memory: 641372 kB\n"
        )
        result = parse_version(raw, device_type="arista_eos")
        assert result != {}
        assert result.get("model") == "DCS-7050TX-64"

    def test_parse_version_arista_serial(self):
        raw = (
            "Arista DCS-7050TX-64\n"
            "Serial number:       ZZZ9999999\n"
            "Software image version: 4.26.2F\n"
            "Uptime: 5 days, 3 hours and 24 minutes\n"
            "Free memory: 641372 kB\n"
        )
        result = parse_version(raw, device_type="arista_eos")
        assert result.get("serial") == "ZZZ9999999"

    def test_parse_version_arista_image(self):
        raw = (
            "Arista DCS-7280CR3-96\n"
            "Serial number:       ABC1234567\n"
            "Software image version: 4.28.3M\n"
            "Uptime: 10 days, 1 hours and 5 minutes\n"
            "Free memory: 500000 kB\n"
        )
        result = parse_version(raw, device_type="arista_eos")
        assert result.get("image") == "4.28.3M"

    def test_parse_version_arista_empty(self):
        assert parse_version("", device_type="arista_eos") == {}

    def test_parse_config_arista(self):
        """parse_config for Arista EOS splits config lines identically to IOS."""
        raw = "hostname arista-sw\nip ssh version 2\nmanagement api http-commands"
        result = parse_config(raw, device_type="arista_eos")
        assert "hostname arista-sw" in result
        assert "ip ssh version 2" in result
        assert len(result) == 3


class TestParserTemplateExistence:
    """Verify all 3 expected templates exist for each vendor."""

    @pytest.mark.parametrize(
        "device_type",
        ["cisco_ios", "cisco_nxos", "arista_eos"],
    )
    def test_interfaces_template_exists(self, device_type):
        """parse_interfaces with each vendor does not raise ParseError for empty input."""
        result = parse_interfaces("", device_type=device_type)
        assert result == []

    @pytest.mark.parametrize(
        "device_type",
        ["cisco_ios", "cisco_nxos", "arista_eos"],
    )
    def test_version_template_exists(self, device_type):
        """parse_version with each vendor does not raise ParseError for empty input."""
        result = parse_version("", device_type=device_type)
        assert result == {}
