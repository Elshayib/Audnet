"""Vendor registry — dispatch system for multi-vendor command and template resolution.

Adding a new vendor requires only:
1. TextFSM template files following the naming convention:
   ``<vendor_prefix>_<slot_suffix>.textfsm``
2. An entry in ``VENDOR_PROFILES`` with the CLI commands for that vendor.

The registry falls back to cisco_ios for unknown device types, preserving
backward compatibility.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class Slot(Enum):
    """Named slots mapping command output to parser input.

    Each slot corresponds to one CLI command and one TextFSM template.
    Using an enum instead of magic indices prevents silent data corruption
    when adding new commands or reordering existing ones.
    """

    INTERFACES = "interfaces"
    VERSION = "version"
    RUNNING_CONFIG = "running_config"


_SLOT_SUFFIX_MAP: dict[Slot, str] = {
    Slot.INTERFACES: "show_ip_interface_brief",
    Slot.VERSION: "show_version",
    Slot.RUNNING_CONFIG: "show_running_config",
}


@dataclass(frozen=True)
class VendorProfile:
    """Immutable profile describing a vendor's CLI commands and template prefix."""

    commands: tuple[str, ...]
    template_prefix: str
    description: str = ""


def _profile(commands: list[str], prefix: str, description: str = "") -> VendorProfile:
    return VendorProfile(commands=tuple(commands), template_prefix=prefix, description=description)


# ---------------------------------------------------------------------------
# Built-in vendor profiles
# ---------------------------------------------------------------------------
VENDOR_PROFILES: dict[str, VendorProfile] = {
    "cisco_ios": _profile(
        commands=[
            "show ip interface brief",
            "show version",
            "show running-config",
        ],
        prefix="cisco_ios",
        description="Cisco IOS / IOS-XE",
    ),
    "cisco_nxos": _profile(
        commands=[
            "show ip interface brief",
            "show version",
            "show running-config",
        ],
        prefix="cisco_nxos",
        description="Cisco NX-OS",
    ),
    "arista_eos": _profile(
        commands=[
            "show ip interface brief",
            "show version",
            "show running-config",
        ],
        prefix="arista_eos",
        description="Arista EOS",
    ),
    "juniper_junos": _profile(
        commands=[
            "show interfaces terse",
            "show version",
            "show configuration",
        ],
        prefix="juniper_junos",
        description="Juniper JunOS",
    ),
    "paloalto_panos": _profile(
        commands=[
            "show interface all",
            "show system info",
            "show config running",
        ],
        prefix="paloalto_panos",
        description="Palo Alto PAN-OS",
    ),
    "fortinet_fortios": _profile(
        commands=[
            "get system interface",
            "get system status",
            "show full-configuration",
        ],
        prefix="fortinet_fortios",
        description="Fortinet FortiOS",
    ),
    "aruba_os": _profile(
        commands=[
            "show interface",
            "show version",
            "show running-config",
        ],
        prefix="aruba_os",
        description="Aruba OS (AOS-CX)",
    ),
    "hp_procurve": _profile(
        commands=[
            "show interfaces brief",
            "show version",
            "show running-config",
        ],
        prefix="hp_procurve",
        description="HP ProCurve",
    ),
}

_DEFAULT_VENDOR = "cisco_ios"

# ---------------------------------------------------------------------------
# Command -> template name mapping
# ---------------------------------------------------------------------------

# Per-vendor overrides for template slot suffixes.  Keys are vendor names,
# values are dicts mapping Slot -> suffix string.
VENDOR_TEMPLATE_SUFFIXES: dict[str, dict[Slot, str]] = {
    "cisco_ios": {
        Slot.INTERFACES: "show_ip_interface_brief",
        Slot.VERSION: "show_version",
        Slot.RUNNING_CONFIG: "show_running_config",
    },
    "cisco_nxos": {
        Slot.INTERFACES: "show_ip_interface_brief",
        Slot.VERSION: "show_version",
        Slot.RUNNING_CONFIG: "show_running_config",
    },
    "arista_eos": {
        Slot.INTERFACES: "show_ip_interface_brief",
        Slot.VERSION: "show_version",
        Slot.RUNNING_CONFIG: "show_running_config",
    },
    "juniper_junos": {
        Slot.INTERFACES: "show_ip_interface_brief",
        Slot.VERSION: "show_version",
        Slot.RUNNING_CONFIG: "show_running_config",
    },
    "paloalto_panos": {
        Slot.INTERFACES: "show_interface_all",
        Slot.VERSION: "show_system_info",
        Slot.RUNNING_CONFIG: "show_config_running",
    },
    "fortinet_fortios": {
        Slot.INTERFACES: "get_system_interface",
        Slot.VERSION: "get_system_status",
        Slot.RUNNING_CONFIG: "show_full_configuration",
    },
    "aruba_os": {
        Slot.INTERFACES: "show_interface",
        Slot.VERSION: "show_version",
        Slot.RUNNING_CONFIG: "show_running_config",
    },
    "hp_procurve": {
        Slot.INTERFACES: "show_interfaces_brief",
        Slot.VERSION: "show_version",
        Slot.RUNNING_CONFIG: "show_running_config",
    },
}


def get_vendor_profile(device_type: str) -> VendorProfile:
    """Return the VendorProfile for *device_type*, falling back to cisco_ios."""
    if device_type in VENDOR_PROFILES:
        return VENDOR_PROFILES[device_type]
    logger.warning("Unknown device_type '%s' — falling back to '%s'", device_type, _DEFAULT_VENDOR)
    return VENDOR_PROFILES[_DEFAULT_VENDOR]


def get_commands(device_type: str) -> list[str]:
    """Return the CLI command list for *device_type*."""
    return list(get_vendor_profile(device_type).commands)


def get_template_name(device_type: str, slot: Slot) -> str:
    """Return the TextFSM template filename (without extension) for the given
    vendor and slot."""
    profile = get_vendor_profile(device_type)
    suffixes = VENDOR_TEMPLATE_SUFFIXES.get(
        device_type, VENDOR_TEMPLATE_SUFFIXES.get(_DEFAULT_VENDOR, {})
    )
    suffix = suffixes.get(slot, _SLOT_SUFFIX_MAP[slot])
    return f"{profile.template_prefix}_{suffix}"


def register_vendor(
    device_type: str,
    commands: list[str],
    template_prefix: str,
    template_suffixes: dict[Slot, str] | None = None,
    description: str = "",
) -> None:
    """Register a new vendor at runtime.

    Args:
        device_type: Netmiko device type string (e.g. ``juniper_junos``).
        commands: List of CLI commands in slot order
                  (interfaces, version, running-config).
        template_prefix: Prefix used in TextFSM template filenames.
        template_suffixes: Optional dict mapping Slot -> suffix string.
        description: Human-readable vendor description.
    """
    VENDOR_PROFILES[device_type] = _profile(
        commands=commands, prefix=template_prefix, description=description
    )
    if template_suffixes is not None:
        VENDOR_TEMPLATE_SUFFIXES[device_type] = template_suffixes
    logger.info("Registered vendor '%s' with prefix '%s'", device_type, template_prefix)


def list_vendors() -> list[str]:
    """Return all registered vendor device types."""
    return sorted(VENDOR_PROFILES.keys())


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

# SNMP sysDesCR OID
_SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"

# Mapping of vendor identifiers (case-insensitive) to device types.
# Ordered by specificity — more specific patterns first.
_DETECTION_RULES: list[tuple[str, str]] = [
    # (substring to match in sysDescr/banner, device_type)
    ("FortiOS", "fortinet_fortios"),
    ("FortiGate", "fortinet_fortios"),
    ("ArubaOS-CX", "aruba_os"),
    ("Aruba", "aruba_os"),
    ("ProCurve", "hp_procurve"),
    ("HP J", "hp_procurve"),
    ("JUNOS", "juniper_junos"),
    ("Juniper", "juniper_junos"),
    ("NX-OS", "cisco_nxos"),
    ("cisco_nxos", "cisco_nxos"),
    ("Arista", "arista_eos"),
    ("EOS", "arista_eos"),
    ("PAN-OS", "paloalto_panos"),
    ("Palo Alto", "paloalto_panos"),
    ("Cisco IOS", "cisco_ios"),
    ("Cisco Internetwork Operating System", "cisco_ios"),
]


def detect_vendor(sys_descr: str) -> str:
    """Detect vendor device_type from SNMP sysDescr or SSH banner string.

    Args:
        sys_descr: The SNMP sysDescr value or SSH banner text.

    Returns:
        Device type string. Falls back to 'cisco_ios' if no match.
    """
    text = sys_descr.strip()
    for pattern, device_type in _DETECTION_RULES:
        if pattern.lower() in text.lower():
            logger.info(
                "Detected vendor '%s' from sysDescr match: '%s'", device_type, pattern
            )
            return device_type
    logger.warning(
        "Could not detect vendor from sysDescr, falling back to '%s'", _DEFAULT_VENDOR
    )
    return _DEFAULT_VENDOR


async def detect_vendor_snmp(
    host: str,
    community: str = "public",
    port: int = 161,
    timeout: int = 5,
) -> str:
    """Detect vendor via SNMP sysDescr query.

    Args:
        host: Target device IP/hostname.
        community: SNMP community string.
        port: SNMP port.
        timeout: Query timeout in seconds.

    Returns:
        Device type string. Falls back to 'cisco_ios' on failure.
    """
    try:
        from pysnmp.hlapi.asyncio import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            getCmd,
        )
    except ImportError:
        logger.warning(
            "pysnmp not available for SNMP detection, falling back to '%s'",
            _DEFAULT_VENDOR,
        )
        return _DEFAULT_VENDOR

    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((host, port), timeout=timeout, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(_SYS_DESCR_OID)),
        )
        error_indication, error_status, error_index, var_binds = await iterator

        if error_indication or error_status:
            logger.warning(
                "SNMP detection failed for %s: %s",
                host,
                error_indication or error_status,
            )
            return _DEFAULT_VENDOR

        for var_bind in var_binds:
            sys_descr = str(var_bind[1])
            return detect_vendor(sys_descr)
    except Exception as exc:  # noqa: BLE001
        logger.warning("SNMP detection error for %s: %s", host, exc)
        return _DEFAULT_VENDOR

    return _DEFAULT_VENDOR
