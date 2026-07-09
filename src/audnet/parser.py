"""TextFSM parser — converts raw CLI output to structured JSON.

Supports multi-vendor template resolution via the vendor registry.
Each parse function accepts an optional ``device_type`` parameter that
selects the correct TextFSM template.  Falls back to cisco_ios templates
for unknown device types.
"""

from __future__ import annotations

import logging
from importlib.resources import files

import textfsm

from audnet.exceptions import ParseError
from audnet.vendor_registry import Slot, get_template_name

logger = logging.getLogger(__name__)

TEMPLATE_DIR = files("audnet.textfsm_templates")


def _apply_template(template_name: str, raw: str) -> list[dict[str, str]]:
    template_path = TEMPLATE_DIR / template_name
    if not template_path.is_file():
        raise ParseError(
            f"TextFSM template not found: {template_name!r}. Expected file: {template_path}"
        )
    try:
        with template_path.open() as f:
            template = textfsm.TextFSM(f)
        rows = template.ParseText(raw)
        return [dict(zip(template.header, row)) for row in rows]
    except textfsm.TextFSMTemplateError as exc:
        logger.error("TextFSM template error in %s: %s", template_name, exc)
        raise ParseError(f"Template error in {template_name}: {exc}") from exc


# Map vendor-specific TextFSM field names onto the canonical schema used by
# ParsedVersion / compliance (interface, ip_address, version, …).
_VERSION_ALIASES = ("os", "image", "junos_version", "software_version", "sw_version")
_IFACE_NAME_ALIASES = ("port", "ifname", "name", "intf")
_IP_ALIASES = ("local", "address", "ip", "ipaddr")
_STATUS_ALIASES = ("admin_status", "oper_status", "link", "link_status", "proto")


def _normalize_row(row: dict[str, str]) -> dict[str, str]:
    return {k.lower().replace(" ", "_"): v.strip() for k, v in row.items()}


def _canonicalize_interface(row: dict[str, str]) -> dict[str, str]:
    """Normalize interface record keys across vendors."""
    out = dict(row)
    if not out.get("interface"):
        for alias in _IFACE_NAME_ALIASES:
            if out.get(alias):
                out["interface"] = out[alias]
                break
    if not out.get("ip_address"):
        for alias in _IP_ALIASES:
            if out.get(alias):
                out["ip_address"] = out[alias]
                break
    # Junos: admin_status / link_status → status
    if not out.get("status"):
        if out.get("link_status"):
            out["status"] = out["link_status"]
        elif out.get("admin_status"):
            out["status"] = out["admin_status"]
    # PAN speed/duplex/state like "1000/full/up" → extract oper state
    speed = out.get("speed_duplex", "")
    if speed and "/" in speed and not out.get("link_status"):
        parts = speed.split("/")
        if parts:
            out["link_status"] = parts[-1]
            if not out.get("status"):
                out["status"] = parts[-1]
    return out


def _canonicalize_version(row: dict[str, str]) -> dict[str, str]:
    """Ensure software version lands in the ``version`` field for ParsedVersion."""
    out = dict(row)
    if not out.get("version"):
        for alias in _VERSION_ALIASES:
            if out.get(alias):
                out["version"] = out[alias]
                break
    return out


def parse_interfaces(raw: str, device_type: str = "cisco_ios") -> list[dict[str, str]]:
    if not raw.strip():
        return []
    template_name = get_template_name(device_type, slot=Slot.INTERFACES) + ".textfsm"
    records = _apply_template(template_name, raw)
    result = [_canonicalize_interface(_normalize_row(r)) for r in records]
    if not result:
        logger.warning(
            "Interface parse produced 0 records for device_type=%s (raw length=%d)",
            device_type,
            len(raw),
        )
    return result


def parse_version(raw: str, device_type: str = "cisco_ios") -> dict[str, str]:
    if not raw.strip():
        return {}
    template_name = get_template_name(device_type, slot=Slot.VERSION) + ".textfsm"
    rows = _apply_template(template_name, raw)
    if rows:
        return _canonicalize_version(_normalize_row(rows[0]))
    logger.warning(
        "Version parse produced 0 records for device_type=%s (raw length=%d)",
        device_type,
        len(raw),
    )
    return {}


def parse_config(raw: str, device_type: str = "cisco_ios") -> list[str]:
    # Config parsing is vendor-agnostic (line-by-line), but we keep the
    # device_type parameter for forward compatibility.
    if not raw.strip():
        return []
    return [line.strip() for line in raw.splitlines() if line.strip()]
