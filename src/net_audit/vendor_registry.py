"""Vendor registry — dispatch system for multi-vendor command and template resolution.

Adding a new vendor requires only:
1. TextFSM template files following the naming convention:
   ``<vendor_prefix>_<sanitized_command_name>.textfsm``
2. An entry in ``VENDOR_PROFILES`` with the CLI commands for that vendor.

The registry falls back to cisco_ios for unknown device types, preserving
backward compatibility.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


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
}

_DEFAULT_VENDOR = "cisco_ios"

# ---------------------------------------------------------------------------
# Command -> template name mapping
# ---------------------------------------------------------------------------

# Maps the logical slot index (0=interfaces, 1=version, 2=config) to the
# template file suffix.  Vendors that use different command phrasing can
# override per-slot via VENDOR_TEMPLATE_SUFFIXES.
_TEMPLATE_SLOT_SUFFIXES = ("show_ip_interface_brief", "show_version", "show_running_config")

# Per-vendor overrides for template slot suffixes.  Keys are vendor names,
# values are tuples of 3 suffixes matching the slot order.
VENDOR_TEMPLATE_SUFFIXES: dict[str, tuple[str, str, str]] = {
    "cisco_ios": _TEMPLATE_SLOT_SUFFIXES,
    "cisco_nxos": ("show_ip_interface_brief", "show_version", "show_running_config"),
    "arista_eos": ("show_ip_interface_brief", "show_version", "show_running_config"),
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


def get_template_name(device_type: str, slot: int) -> str:
    """Return the TextFSM template filename (without extension) for the given
    vendor and logical slot (0=interfaces, 1=version, 2=config)."""
    profile = get_vendor_profile(device_type)
    suffixes = VENDOR_TEMPLATE_SUFFIXES.get(
        device_type, VENDOR_TEMPLATE_SUFFIXES.get(_DEFAULT_VENDOR, _TEMPLATE_SLOT_SUFFIXES)
    )
    suffix = suffixes[slot]
    return f"{profile.template_prefix}_{suffix}"


def register_vendor(
    device_type: str,
    commands: list[str],
    template_prefix: str,
    template_suffixes: tuple[str, str, str] | None = None,
    description: str = "",
) -> None:
    """Register a new vendor at runtime.

    Args:
        device_type: Netmiko device type string (e.g. ``juniper_junos``).
        commands: List of CLI commands in slot order
                  (interfaces, version, running-config).
        template_prefix: Prefix used in TextFSM template filenames.
        template_suffixes: Optional 3-tuple overriding the default slot suffixes.
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
