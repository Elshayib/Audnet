"""Tests for Juniper JunOS and Palo Alto PAN-OS vendor support."""

from audnet.parser import parse_interfaces, parse_version, parse_config
from audnet.vendor_registry import (
    Slot,
    get_commands,
    get_template_name,
    get_vendor_profile,
    list_vendors,
)


# ---------------------------------------------------------------------------
# Juniper JunOS sample outputs
# ---------------------------------------------------------------------------

JUNOS_INTERFACES_TERSE = """\
Interface                 Admin Link Proto    Local                 Remote
ge-0/0/0                 up    up   inet     10.0.0.1/24
ge-0/0/1                 up    down inet     10.0.0.2/24
ge-0/0/2                 up    up   inet     10.0.0.3/24
lo0                      up    up   inet     127.0.0.1           --> 0/0
"""

JUNOS_VERSION = """\
Hostname: router1
Model: mx240
Junos: 21.4R3.10
System serial number: JN1234AB5678
 router1 up 14 days, 3 hours, 22 minutes, 15 seconds
"""

JUNOS_CONFIG = """\
version 21.4R3.10;
system {
    host-name router1;
    domain-name example.com;
    time-zone UTC;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
"""


# ---------------------------------------------------------------------------
# Palo Alto PAN-OS sample outputs
# ---------------------------------------------------------------------------

PANOS_INTERFACE_ALL = """\
total configured hardware interfaces: 5
name    id    speed/duplex/state/fec    mac address
--------------------------------------------------------------------------------
ethernet1/1    1    1000/full/up    00:1b:17:00:01:01
ethernet1/2    2    1000/full/down    00:1b:17:00:01:02

total configured logical interfaces: 3
name    id    vsys    zone    forwarding    tag    address
--------------------------------------------------------------------------------
ethernet1/1    1    1    trust    vr:default    10    10.0.0.1/24
ethernet1/2    2    1    untrust    vr:default    20    10.0.0.2/24
loopback.1    6    1    mgmt    vr:default    0    127.0.0.1/32
"""

PANOS_SYSTEM_INFO = """\
hostname: pa-vm-01
ip-address: 10.0.0.10
netmask: 255.255.255.0
default-gateway: 10.0.0.1
mac-address: 00:1b:17:aa:bb:cc
uptime: 30 days, 4:15:22
family: vm
model: PA-VM
serial: 001234567890
vm-license: none
vm-mode: bundled
sw-version: 10.2.3
platform-family: vm
vpn-disable-mode: off
multi-vsys: off
operational-mode: normal
"""

PANOS_CONFIG_RUNNING = """{
    "config": {
        "devices": {
            "localhost.localdomain": {
                "vsys": {
                    "vsys1": {
                        "zone": [
                            {"name": "trust"},
                            {"name": "untrust"}
                        ]
                    }
                }
            }
        }
    }
}
set deviceconfig system hostname pa-vm-01
set deviceconfig system ip-address 10.0.0.10
set deviceconfig system netmask 255.255.255.0
set deviceconfig system default-gateway 10.0.0.1
"""


class TestJuniperJunosVendor:
    """Tests for Juniper JunOS vendor support."""

    def test_junos_in_vendors_list(self):
        vendors = list_vendors()
        assert "juniper_junos" in vendors

    def test_junos_profile(self):
        profile = get_vendor_profile("juniper_junos")
        assert profile.template_prefix == "juniper_junos"
        assert profile.description == "Juniper JunOS"

    def test_junos_commands(self):
        cmds = get_commands("juniper_junos")
        assert cmds == [
            "show interfaces terse",
            "show version",
            "show configuration",
        ]

    def test_junos_template_names(self):
        assert (
            get_template_name("juniper_junos", Slot.INTERFACES)
            == "juniper_junos_show_ip_interface_brief"
        )
        assert get_template_name("juniper_junos", Slot.VERSION) == "juniper_junos_show_version"
        assert (
            get_template_name("juniper_junos", Slot.RUNNING_CONFIG)
            == "juniper_junos_show_running_config"
        )

    def test_junos_parse_interfaces(self):
        result = parse_interfaces(JUNOS_INTERFACES_TERSE, device_type="juniper_junos")
        assert len(result) >= 1
        # Check that interfaces were parsed
        names = [r.get("interface") for r in result]
        assert any("ge-0/0/0" in n for n in names if n)

    def test_junos_parse_version(self):
        result = parse_version(JUNOS_VERSION, device_type="juniper_junos")
        assert result.get("hostname") == "router1"
        assert result.get("model") == "mx240"
        assert "junos_version" in result or "version" in result

    def test_junos_parse_config(self):
        result = parse_config(JUNOS_CONFIG, device_type="juniper_junos")
        assert len(result) > 0
        assert any("version" in line for line in result)


class TestPaloAltoPanosVendor:
    """Tests for Palo Alto PAN-OS vendor support."""

    def test_panos_in_vendors_list(self):
        vendors = list_vendors()
        assert "paloalto_panos" in vendors

    def test_panos_profile(self):
        profile = get_vendor_profile("paloalto_panos")
        assert profile.template_prefix == "paloalto_panos"
        assert profile.description == "Palo Alto PAN-OS"

    def test_panos_commands(self):
        cmds = get_commands("paloalto_panos")
        assert cmds == [
            "show interface all",
            "show system info",
            "show config running",
        ]

    def test_panos_template_names(self):
        assert (
            get_template_name("paloalto_panos", Slot.INTERFACES)
            == "paloalto_panos_show_interface_all"
        )
        assert (
            get_template_name("paloalto_panos", Slot.VERSION) == "paloalto_panos_show_system_info"
        )
        assert (
            get_template_name("paloalto_panos", Slot.RUNNING_CONFIG)
            == "paloalto_panos_show_config_running"
        )

    def test_panos_parse_interfaces(self):
        result = parse_interfaces(PANOS_INTERFACE_ALL, device_type="paloalto_panos")
        assert len(result) >= 1
        names = [r.get("interface") for r in result]
        assert any("ethernet1/1" in n for n in names if n)

    def test_panos_parse_version(self):
        result = parse_version(PANOS_SYSTEM_INFO, device_type="paloalto_panos")
        assert result.get("hostname") == "pa-vm-01"
        assert result.get("model") == "PA-VM"
        assert result.get("serial") == "001234567890"

    def test_panos_parse_config(self):
        result = parse_config(PANOS_CONFIG_RUNNING, device_type="paloalto_panos")
        assert len(result) > 0


class TestVendorFallback:
    """Ensure new vendors don't break fallback behavior."""

    def test_unknown_still_falls_back(self):
        profile = get_vendor_profile("unknown_vendor")
        assert profile.template_prefix == "cisco_ios"

    def test_existing_vendors_still_work(self):
        assert "cisco_ios" in list_vendors()
        assert "cisco_nxos" in list_vendors()
        assert "arista_eos" in list_vendors()

    def test_cisco_ios_templates_unchanged(self):
        assert (
            get_template_name("cisco_ios", Slot.INTERFACES) == "cisco_ios_show_ip_interface_brief"
        )
        assert get_template_name("cisco_ios", Slot.VERSION) == "cisco_ios_show_version"
