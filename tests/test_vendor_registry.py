"""Tests for the vendor registry and multi-vendor dispatch system."""

import pytest
from audnet.vendor_registry import (
    Slot,
    get_commands,
    get_template_name,
    get_vendor_profile,
    list_vendors,
    register_vendor,
)


class TestVendorProfile:
    def test_cisco_ios_profile(self):
        profile = get_vendor_profile("cisco_ios")
        assert profile.template_prefix == "cisco_ios"
        assert "show ip interface brief" in profile.commands
        assert "show version" in profile.commands
        assert "show running-config" in profile.commands

    def test_cisco_nxos_profile(self):
        profile = get_vendor_profile("cisco_nxos")
        assert profile.template_prefix == "cisco_nxos"
        assert "show version" in profile.commands

    def test_arista_eos_profile(self):
        profile = get_vendor_profile("arista_eos")
        assert profile.template_prefix == "arista_eos"
        assert "show version" in profile.commands


class TestGetVendorProfileFallback:
    def test_unknown_device_type_falls_back_to_cisco_ios(self):
        profile = get_vendor_profile("totally_unknown_vendor")
        assert profile.template_prefix == "cisco_ios"

    def test_empty_string_falls_back_to_cisco_ios(self):
        profile = get_vendor_profile("")
        assert profile.template_prefix == "cisco_ios"


class TestGetCommands:
    def test_cisco_ios_commands(self):
        cmds = get_commands("cisco_ios")
        assert cmds == [
            "show ip interface brief",
            "show version",
            "show running-config",
        ]

    def test_unknown_type_returns_cisco_ios_commands(self):
        cmds = get_commands("nonexistent_vendor")
        assert cmds == get_commands("cisco_ios")

    def test_commands_are_list(self):
        cmds = get_commands("cisco_ios")
        assert isinstance(cmds, list)


class TestGetTemplateName:
    def test_cisco_ios_interface_template(self):
        name = get_template_name("cisco_ios", slot=Slot.INTERFACES)
        assert name == "cisco_ios_show_ip_interface_brief"

    def test_cisco_ios_version_template(self):
        name = get_template_name("cisco_ios", slot=Slot.VERSION)
        assert name == "cisco_ios_show_version"

    def test_cisco_ios_config_template(self):
        name = get_template_name("cisco_ios", slot=Slot.RUNNING_CONFIG)
        assert name == "cisco_ios_show_running_config"

    def test_arista_eos_template(self):
        name = get_template_name("arista_eos", slot=Slot.INTERFACES)
        assert name == "arista_eos_show_ip_interface_brief"

    def test_cisco_nxos_template(self):
        name = get_template_name("cisco_nxos", slot=Slot.VERSION)
        assert name == "cisco_nxos_show_version"

    def test_unknown_type_uses_cisco_ios_templates(self):
        name = get_template_name("unknown_vendor", slot=Slot.INTERFACES)
        assert name == "cisco_ios_show_ip_interface_brief"


class TestRegisterVendor:
    def test_register_new_vendor(self):
        register_vendor(
            device_type="test_juniper_junos",
            commands=[
                "show interfaces terse",
                "show version",
                "show configuration",
            ],
            template_prefix="juniper_junos",
            description="Juniper JunOS",
        )
        profile = get_vendor_profile("test_juniper_junos")
        assert profile.template_prefix == "juniper_junos"
        assert "show interfaces terse" in profile.commands

    def test_register_vendor_with_custom_suffixes(self):
        register_vendor(
            device_type="test_paloalto_panos",
            commands=[
                "show interface all",
                "show system info",
                "show config running",
            ],
            template_prefix="paloalto_panos",
            template_suffixes={
                Slot.INTERFACES: "show_interface_all",
                Slot.VERSION: "show_system_info",
                Slot.RUNNING_CONFIG: "show_config_running",
            },
        )
        name = get_template_name("test_paloalto_panos", slot=Slot.INTERFACES)
        assert name == "paloalto_panos_show_interface_all"

    def test_register_vendor_without_suffixes_uses_defaults(self):
        register_vendor(
            device_type="test_vendor",
            commands=["cmd1", "cmd2", "cmd3"],
            template_prefix="test_vendor",
        )
        name = get_template_name("test_vendor", slot=Slot.INTERFACES)
        assert name == "test_vendor_show_ip_interface_brief"


class TestListVendors:
    def test_includes_cisco_ios(self):
        vendors = list_vendors()
        assert "cisco_ios" in vendors

    def test_includes_cisco_nxos(self):
        vendors = list_vendors()
        assert "cisco_nxos" in vendors

    def test_includes_arista_eos(self):
        vendors = list_vendors()
        assert "arista_eos" in vendors

    def test_returns_sorted_list(self):
        vendors = list_vendors()
        assert vendors == sorted(vendors)


class TestVendorProfileImmutable:
    def test_frozen_dataclass(self):
        profile = get_vendor_profile("cisco_ios")
        with pytest.raises(AttributeError):
            profile.template_prefix = "something_else"
