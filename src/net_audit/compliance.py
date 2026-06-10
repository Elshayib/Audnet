"""Compliance engine — runs security baseline checks against device snapshots."""

from __future__ import annotations

import logging
import re
from typing import Any

from net_audit.models import ComplianceResult, DeviceSnapshot

logger = logging.getLogger(__name__)

# Pre-compiled patterns for config extraction
_RE_SSH_VERSION = re.compile(r"^ip\s+ssh\s+version\s+(\d+)", re.IGNORECASE)
_RE_SWITCHPORT_ACCESS_VLAN = re.compile(
    r"^switchport\s+access\s+vlan\s+(\d+)", re.IGNORECASE
)
_RE_INTERFACE = re.compile(r"^interface\s+(.+)", re.IGNORECASE)
_RE_NTP_SERVER = re.compile(r"^ntp\s+server\s+(\S+)", re.IGNORECASE)
_RE_LOGGING_HOST = re.compile(r"^logging\s+host\s+(\S+)", re.IGNORECASE)


def _extract_interfaces(lines: list[str]) -> dict[str, list[str]]:
    """Build a mapping of interface name -> child config lines.

    Parses Cisco-style config blocks. Since parse_config strips whitespace,
    we detect interface boundaries by 'interface X' lines and collect all
    subsequent non-interface lines until the next interface or a top-level
    marker (hostname, end, !).
    """
    interfaces: dict[str, list[str]] = {}
    current_iface: str | None = None
    _TOPLEVEL_RE = re.compile(r"^(hostname|end|banner|no\s)", re.IGNORECASE)

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            current_iface = None
            continue

        m = _RE_INTERFACE.match(stripped)
        if m:
            current_iface = m.group(1).strip()
            interfaces[current_iface] = []
            continue

        if current_iface is not None:
            if _TOPLEVEL_RE.match(stripped):
                current_iface = None
            else:
                interfaces[current_iface].append(stripped)

    return interfaces


def _check_ssh_v2_only(snapshot: DeviceSnapshot, config: dict[str, Any]) -> ComplianceResult:
    sev = config["severity"]

    matches = [m for m in (_RE_SSH_VERSION.match(line) for line in snapshot.config.lines) if m]
    if not matches:
        logger.warning("%s: no 'ip ssh version' directive found", snapshot.device_name)
        return ComplianceResult(
            check_name="ssh_v2_only", passed=False, severity=sev,
            detail="No SSH version configuration found — must explicitly set 'ip ssh version 2'")

    for m in matches:
        version = m.group(1)
        if version == "1":
            logger.info("%s: SSHv1 detected", snapshot.device_name)
            return ComplianceResult(
                check_name="ssh_v2_only", passed=False, severity=sev,
                detail="SSHv1 is configured — prohibited. Use 'ip ssh version 2'")
        if version == "2":
            logger.info("%s: SSHv2 confirmed", snapshot.device_name)
            return ComplianceResult(
                check_name="ssh_v2_only", passed=True, severity=sev,
                detail="SSHv2 is explicitly enabled")

    return ComplianceResult(
        check_name="ssh_v2_only", passed=False, severity=sev,
        detail=f"Unexpected SSH version config: {'; '.join(m.string for m in matches)}")


def _check_no_open_ports(snapshot: DeviceSnapshot, config: dict[str, Any]) -> ComplianceResult:
    allowed = set(str(v) for v in config.get("allowed_vlans", []))
    sev = config["severity"]

    interfaces = _extract_interfaces(snapshot.config.lines)
    violations: list[str] = []

    for iface, child_lines in interfaces.items():
        for line in child_lines:
            m = _RE_SWITCHPORT_ACCESS_VLAN.match(line)
            if m:
                vlan = m.group(1)
                if vlan not in allowed:
                    violations.append(f"{iface} in VLAN {vlan}")

    if violations:
        logger.info("%s: unauthorized VLANs: %s", snapshot.device_name, violations)
        return ComplianceResult(
            check_name="inactive_ports", passed=False, severity=sev,
            detail=f"Unauthorized VLAN assignments: {'; '.join(violations)}")
    return ComplianceResult(
        check_name="inactive_ports", passed=True, severity=sev,
        detail="All VLAN assignments are within the allowed set")


def _check_ntp_approved(snapshot: DeviceSnapshot, config: dict[str, Any]) -> ComplianceResult:
    approved = set(str(s) for s in config.get("approved_servers", []))
    sev = config["severity"]

    servers = [m.group(1) for line in snapshot.config.lines
               if (m := _RE_NTP_SERVER.match(line.strip()))]

    if not servers:
        logger.warning("%s: no NTP servers configured", snapshot.device_name)
        return ComplianceResult(
            check_name="ntp_config", passed=False, severity=sev,
            detail="No NTP servers configured — at least one required")

    violations = [s for s in servers if s not in approved]
    if violations:
        logger.info("%s: unapproved NTP servers: %s", snapshot.device_name, violations)
        return ComplianceResult(
            check_name="ntp_config", passed=False, severity=sev,
            detail=f"Unapproved NTP servers: {', '.join(violations)}")
    return ComplianceResult(
        check_name="ntp_config", passed=True, severity=sev,
        detail="All NTP servers are approved")


def _check_syslog_approved(snapshot: DeviceSnapshot, config: dict[str, Any]) -> ComplianceResult:
    approved = set(str(s) for s in config.get("approved_servers", []))
    sev = config["severity"]

    servers = [m.group(1) for line in snapshot.config.lines
               if (m := _RE_LOGGING_HOST.match(line.strip()))]

    if not servers:
        logger.warning("%s: no syslog servers configured", snapshot.device_name)
        return ComplianceResult(
            check_name="syslog_config", passed=False, severity=sev,
            detail="No syslog servers configured — at least one required")

    violations = [s for s in servers if s not in approved]
    if violations:
        logger.info("%s: unapproved syslog servers: %s", snapshot.device_name, violations)
        return ComplianceResult(
            check_name="syslog_config", passed=False, severity=sev,
            detail=f"Unapproved syslog servers: {', '.join(violations)}")
    return ComplianceResult(
        check_name="syslog_config", passed=True, severity=sev,
        detail="All syslog servers are approved")


_RULE_DISPATCH: dict[str, Any] = {
    "ssh_v2_only": _check_ssh_v2_only,
    "no_open_ports": _check_no_open_ports,
    "ntp_approved": _check_ntp_approved,
    "syslog_approved": _check_syslog_approved,
}


def run_checks(snapshot: DeviceSnapshot, baseline: dict[str, Any]) -> list[ComplianceResult]:
    results = []
    for check_name, check_config in baseline.get("checks", {}).items():
        handler = _RULE_DISPATCH.get(check_config.get("rule"))
        if handler is None:
            logger.warning("Unknown rule '%s' for check '%s'", check_config.get("rule"), check_name)
            results.append(ComplianceResult(
                check_name=check_name, passed=False,
                severity=check_config.get("severity", "medium"),
                detail=f"Unknown rule: {check_config.get('rule')}"))
        else:
            results.append(handler(snapshot, check_config))
    return results
