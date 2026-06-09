"""TextFSM parser — converts raw CLI output to structured JSON."""

from __future__ import annotations

from pathlib import Path

import textfsm


TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent / "textfsm_templates"


def _apply_template(template_name: str, raw: str) -> list[dict]:
    template_path = TEMPLATE_DIR / template_name
    if not template_path.exists():
        return []
    try:
        with open(template_path) as f:
            template = textfsm.TextFSM(f)
        rows = template.ParseText(raw)
        return [dict(zip(template.header, row)) for row in rows]
    except textfsm.TextFSMTemplateError:
        return []


def parse_interfaces(raw: str) -> list[dict]:
    if not raw.strip():
        return []
    records = _apply_template("cisco_ios_show_ip_interface_brief.textfsm", raw)
    return [{k.lower().replace(" ", "_"): v.strip() for k, v in r.items()} for r in records]


def parse_version(raw: str) -> dict:
    if not raw.strip():
        return {}
    rows = _apply_template("cisco_ios_show_version.textfsm", raw)
    if rows:
        return {k.lower().replace(" ", "_"): v.strip() for k, v in rows[0].items()}
    return {}


def parse_config(raw: str) -> list[str]:
    if not raw.strip():
        return []
    return [line.strip() for line in raw.splitlines() if line.strip()]
