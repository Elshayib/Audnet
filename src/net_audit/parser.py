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

from net_audit.exceptions import ParseError
from net_audit.vendor_registry import get_template_name

logger = logging.getLogger(__name__)

TEMPLATE_DIR = files("net_audit.textfsm_templates")


def _apply_template(template_name: str, raw: str) -> list[dict[str, str]]:
    template_path = TEMPLATE_DIR / template_name
    if not template_path.is_file():
        logger.warning("TextFSM template not found: %s", template_name)
        return []
    try:
        with template_path.open() as f:
            template = textfsm.TextFSM(f)
        rows = template.ParseText(raw)
        return [dict(zip(template.header, row)) for row in rows]
    except textfsm.TextFSMTemplateError as exc:
        logger.error("TextFSM template error in %s: %s", template_name, exc)
        raise ParseError(f"Template error in {template_name}: {exc}") from exc


def _normalize_row(row: dict[str, str]) -> dict[str, str]:
    return {k.lower().replace(" ", "_"): v.strip() for k, v in row.items()}


def parse_interfaces(raw: str, device_type: str = "cisco_ios") -> list[dict[str, str]]:
    if not raw.strip():
        return []
    template_name = get_template_name(device_type, slot=0) + ".textfsm"
    records = _apply_template(template_name, raw)
    return [_normalize_row(r) for r in records]


def parse_version(raw: str, device_type: str = "cisco_ios") -> dict[str, str]:
    if not raw.strip():
        return {}
    template_name = get_template_name(device_type, slot=1) + ".textfsm"
    rows = _apply_template(template_name, raw)
    if rows:
        return _normalize_row(rows[0])
    return {}


def parse_config(raw: str, device_type: str = "cisco_ios") -> list[str]:
    # Config parsing is vendor-agnostic (line-by-line), but we keep the
    # device_type parameter for forward compatibility.
    if not raw.strip():
        return []
    return [line.strip() for line in raw.splitlines() if line.strip()]
