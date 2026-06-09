"""TextFSM parser — converts raw CLI output to structured JSON."""

from __future__ import annotations

import logging
from pathlib import Path

import textfsm

from net_audit.exceptions import ParseError

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent / "textfsm_templates"


def _apply_template(template_name: str, raw: str) -> list[dict[str, str]]:
    template_path = TEMPLATE_DIR / template_name
    if not template_path.exists():
        logger.warning("TextFSM template not found: %s", template_path)
        return []
    try:
        with open(template_path) as f:
            template = textfsm.TextFSM(f)
        rows = template.ParseText(raw)
        return [dict(zip(template.header, row)) for row in rows]
    except textfsm.TextFSMTemplateError as exc:
        logger.error("TextFSM template error in %s: %s", template_name, exc)
        raise ParseError(f"Template error in {template_name}: {exc}") from exc


def _normalize_row(row: dict[str, str]) -> dict[str, str]:
    return {k.lower().replace(" ", "_"): v.strip() for k, v in row.items()}


def parse_interfaces(raw: str) -> list[dict[str, str]]:
    if not raw.strip():
        return []
    records = _apply_template("cisco_ios_show_ip_interface_brief.textfsm", raw)
    return [_normalize_row(r) for r in records]


def parse_version(raw: str) -> dict[str, str]:
    if not raw.strip():
        return {}
    rows = _apply_template("cisco_ios_show_version.textfsm", raw)
    if rows:
        return _normalize_row(rows[0])
    return {}


def parse_config(raw: str) -> list[str]:
    if not raw.strip():
        return []
    return [line.strip() for line in raw.splitlines() if line.strip()]
