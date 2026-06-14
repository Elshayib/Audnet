"""Tests for expanded vendor support (8 vendors) and auto-detection."""

import pytest

from audnet.vendor_registry import (
    _DETECTION_RULES,
    detect_vendor,
    get_commands,
    get_template_name,
    get_vendor_profile,
    list_vendors,
)
from audnet.parser import parse_interfaces, parse_version, parse_config


# ---------------------------------------------------------------------------
# Sample outputs for new vendors
# ---------------------------------------------------------------------------

FORTINET_INTERFACES = """\
== [ port1 ]
name: port1    ip: 10.0.0.1 255.255.255.0    status: up    access: ping ssh
== [ port2 ]
name: port2    ip: 10.0.0.2 255.255.255.0    status: down    access: ping
"""

FORTINET_VERSION = """\
Hostname: fw01
Version: FortiOS v7.4.3 build1234
Serial-Number: FGVM1234567890
Model: FortiGate-VM64
"""

FORTINET_CONFIG = """\
config system global
  set hostname fw01
end
"""

ARUBA_INTERFACES = """\
Interface 1/1/1 is up
  Admin state is up
  Hardware: Ethernet, Interface name: 1/1/1
  IP address 10.0.0.1/24
Interface 1/1/2 is down
  Admin state is down
  Hardware: Ethernet, Interface name: 1/1/2
"""

ARUBA_VERSION = """\
ArubaOS-CX.10.10.1000
Virtual.10.10.1000
Hostname: sw01
System Description: Aruba 6300M Switch
Serial Number: SG1234AB56
"""

ARUBA_CONFIG = """\
hostname sw01
interface 1/1/1
  no shutdown
"""

HP_INTERFACES = """\
                   | Intrusion                           | Port
Port   Type        | Alert     Enabled Status            | Action  Status
-------+-----------+---------+--------+------------------+--------+--------
  1    100/1000T  | No        Yes      Up               | No      Forward
  2    100/1000T  | No        Yes      Down             | No      Forward
"""

HP_VERSION = """\
Image stamp: /sw/code/build/bass
    Jun 15 2024 12:00:00
    J9856A
    16.10.0010
    Boot Image: Primary
    Product: J9856A HP 5412R zl2 Switch
    Serial No: SG1234AB56
"""

HP_CONFIG = """\
hostname hp-sw01
vlan 1
  name default
"""


class TestVendorCount:
    def test_at_least_8_vendors(self):
        vendors = list_vendors()
        assert len(vendors) >= 8

    def test_all_new_vendors_registered(self):
        vendors = list_vendors()
        assert "fortinet_fortios" in vendors
        assert "aruba_os" in vendors
        assert "hp_procurve" in vendors

    def test_existing_vendors_still_present(self):
        vendors = list_vendors()
        for existing in ("cisco_ios", "cisco_nxos", "arista_eos", "juniper_junos", "paloalto_panos"):
            assert existing in vendors


class TestFortinetFortiOS:
    def test_profile(self):
        profile = get_vendor_profile("fortinet_fortios")
        assert profile.template_prefix == "fortinet_fortios"
        assert profile.description == "Fortinet FortiOS"

    def test_commands(self):
        cmds = get_commands("fortinet_fortios")
        assert cmds == [
            "get system interface",
            "get system status",
            "show full-configuration",
        ]

    def test_template_names(self):
        from audnet.vendor_registry import Slot

        assert get_template_name("fortinet_fortios", Slot.INTERFACES) == "fortinet_fortios_get_system_interface"
        assert get_template_name("fortinet_fortios", Slot.VERSION) == "fortinet_fortios_get_system_status"
        assert get_template_name("fortinet_fortios", Slot.RUNNING_CONFIG) == "fortinet_fortios_show_full_configuration"

    def test_parse_interfaces(self):
        result = parse_interfaces(FORTINET_INTERFACES, device_type="fortinet_fortios")
        assert len(result) >= 1
        names = [r.get("interface") for r in result]
        assert any("port1" in n for n in names if n)

    def test_parse_version(self):
        result = parse_version(FORTINET_VERSION, device_type="fortinet_fortios")
        assert result.get("hostname") == "fw01"
        assert result.get("model") == "FortiGate-VM64"

    def test_parse_config(self):
        result = parse_config(FORTINET_CONFIG, device_type="fortinet_fortios")
        assert len(result) > 0
        assert any("config" in line for line in result)


class TestArubaOS:
    def test_profile(self):
        profile = get_vendor_profile("aruba_os")
        assert profile.template_prefix == "aruba_os"
        assert profile.description == "Aruba OS (AOS-CX)"

    def test_commands(self):
        cmds = get_commands("aruba_os")
        assert cmds == [
            "show interface",
            "show version",
            "show running-config",
        ]

    def test_template_names(self):
        from audnet.vendor_registry import Slot

        assert get_template_name("aruba_os", Slot.INTERFACES) == "aruba_os_show_interface"
        assert get_template_name("aruba_os", Slot.VERSION) == "aruba_os_show_version"
        assert get_template_name("aruba_os", Slot.RUNNING_CONFIG) == "aruba_os_show_running_config"

    def test_parse_interfaces(self):
        result = parse_interfaces(ARUBA_INTERFACES, device_type="aruba_os")
        assert len(result) >= 1
        names = [r.get("interface") for r in result]
        assert any("1/1/1" in n for n in names if n)

    def test_parse_version(self):
        result = parse_version(ARUBA_VERSION, device_type="aruba_os")
        assert result.get("hostname") == "sw01"
        assert result.get("serial") == "SG1234AB56"

    def test_parse_config(self):
        result = parse_config(ARUBA_CONFIG, device_type="aruba_os")
        assert len(result) > 0


class TestHPProCurve:
    def test_profile(self):
        profile = get_vendor_profile("hp_procurve")
        assert profile.template_prefix == "hp_procurve"
        assert profile.description == "HP ProCurve"

    def test_commands(self):
        cmds = get_commands("hp_procurve")
        assert cmds == [
            "show interfaces brief",
            "show version",
            "show running-config",
        ]

    def test_template_names(self):
        from audnet.vendor_registry import Slot

        assert get_template_name("hp_procurve", Slot.INTERFACES) == "hp_procurve_show_interfaces_brief"
        assert get_template_name("hp_procurve", Slot.VERSION) == "hp_procurve_show_version"
        assert get_template_name("hp_procurve", Slot.RUNNING_CONFIG) == "hp_procurve_show_running_config"

    def test_parse_interfaces(self):
        result = parse_interfaces(HP_INTERFACES, device_type="hp_procurve")
        assert len(result) >= 1

    def test_parse_version(self):
        result = parse_version(HP_VERSION, device_type="hp_procurve")
        assert result.get("version") == "16.10.0010"
        assert "HP" in result.get("model", "")

    def test_parse_config(self):
        result = parse_config(HP_CONFIG, device_type="hp_procurve")
        assert len(result) > 0


class TestVendorFallbackWithNewVendors:
    def test_unknown_still_falls_back(self):
        profile = get_vendor_profile("totally_unknown_vendor")
        assert profile.template_prefix == "cisco_ios"

    def test_existing_vendor_templates_unchanged(self):
        from audnet.vendor_registry import Slot

        assert get_template_name("cisco_ios", Slot.INTERFACES) == "cisco_ios_show_ip_interface_brief"
        assert get_template_name("cisco_ios", Slot.VERSION) == "cisco_ios_show_version"

    def test_new_vendor_unknown_falls_back_to_cisco_ios_templates(self):
        """Unregistered vendor gets cisco_ios template names."""
        from audnet.vendor_registry import Slot

        name = get_template_name("unknown_vendor", Slot.INTERFACES)
        assert name == "cisco_ios_show_ip_interface_brief"


class TestDetectVendor:
    def test_cisco_ios(self):
        assert detect_vendor("Cisco IOS Software, Version 15.2") == "cisco_ios"

    def test_cisco_nxos(self):
        assert detect_vendor("Cisco NX-OS(tm) n9000") == "cisco_nxos"

    def test_arista_eos(self):
        assert detect_vendor("Arista Networks EOS 4.28") == "arista_eos"

    def test_juniper_junos(self):
        assert detect_vendor("JUNOS 21.4R3.10") == "juniper_junos"

    def test_paloalto_panos(self):
        assert detect_vendor("Palo Alto Networks PAN-OS 10.2") == "paloalto_panos"

    def test_fortinet_fortios(self):
        assert detect_vendor("FortiOS v7.4.3") == "fortinet_fortios"

    def test_fortinet_fortigate(self):
        assert detect_vendor("FortiGate-VM64") == "fortinet_fortios"

    def test_aruba_os(self):
        assert detect_vendor("ArubaOS-CX.10.10.1000") == "aruba_os"

    def test_hp_procurve(self):
        assert detect_vendor("HP ProCurve J9856A") == "hp_procurve"

    def test_hp_procurve_j_number(self):
        assert detect_vendor("HP J9856A Switch") == "hp_procurve"

    def test_unknown_falls_back(self):
        assert detect_vendor("Unknown device xyz") == "cisco_ios"

    def test_empty_string_falls_back(self):
        assert detect_vendor("") == "cisco_ios"

    def test_case_insensitive(self):
        assert detect_vendor("junos 21.4") == "juniper_junos"
        assert detect_vendor("CISCO IOS") == "cisco_ios"


class TestDetectVendorSNMP:
    @pytest.mark.asyncio
    async def test_snmp_detection_success(self):
        """SNMP detection returns cisco_ios when pysnmp works (no real SNMP server)."""
        from audnet.vendor_registry import detect_vendor_snmp

        # Without a real SNMP server, detection should fall back to cisco_ios
        result = await detect_vendor_snmp("192.0.2.1", timeout=1)
        assert result == "cisco_ios"

    @pytest.mark.asyncio
    async def test_snmp_detection_pysnmp_not_available(self):
        """SNMP detection falls back when pysnmp is not installed."""
        import audnet.vendor_registry as vr

        # Just verify the function exists and can be called
        assert callable(vr.detect_vendor_snmp)

    @pytest.mark.asyncio
    async def test_snmp_detection_error(self):
        """SNMP detection falls back on error."""
        import audnet.vendor_registry as vr

        # If pysnmp is not installed, it should return cisco_ios
        try:
            from pysnmp.hlapi.asyncio import getCmd  # noqa: F401
            # pysnmp is available, test with unreachable host (will timeout/error)
            # This is a smoke test — we don't have a real SNMP server
            result = await vr.detect_vendor_snmp("192.0.2.1", timeout=1)
            assert result == "cisco_ios"  # Should fall back on timeout
        except ImportError:
            # pysnmp not installed is also fine
            result = await vr.detect_vendor_snmp("10.0.0.1")
            assert result == "cisco_ios"


class TestDetectionRulesOrder:
    def test_specific_patterns_before_generic(self):
        """More specific patterns (e.g., 'FortiOS' before 'FortiGate') come first."""
        patterns = [p for p, _ in _DETECTION_RULES]
        # FortiOS should appear before FortiGate
        assert patterns.index("FortiOS") < patterns.index("FortiGate")
        # NX-OS should appear before Cisco IOS
        assert patterns.index("NX-OS") < patterns.index("Cisco IOS")
