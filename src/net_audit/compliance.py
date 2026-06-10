"""Compliance engine — runs security baseline checks against device snapshots."""

from __future__ import annotations

import logging
from typing import Any

from net_audit.models import ComplianceResult, DeviceSnapshot

logger = logging.getLogger(__name__)


def _check_ssh_v2_only(snapshot: DeviceSnapshot, config: dict[str, Any]) -> ComplianceResult:
    lines = snapshot.config.lines
    sev = config["severity"]

    ssh_version_lines = [line for line in lines if "ip ssh version" in line]
    if not ssh_version_lines:
        logger.warning("%s: no 'ip ssh version' directive found", snapshot.device_name)
        return ComplianceResult(
            check_name="ssh_v2_only", passed=False, severity=sev,
            detail="No SSH version configuration found — must explicitly set 'ip ssh version 2'")

    for line in ssh_version_lines:
        if "ip ssh version 1" in line:
            logger.info("%s: SSHv1 detected", snapshot.device_name)
            return ComplianceResult(
                check_name="ssh_v2_only", passed=False, severity=sev,
                detail="SSHv1 is configured — prohibited. Use 'ip ssh version 2'")
        if "ip ssh version 2" in line:
            logger.info("%s: SSHv2 confirmed", snapshot.device_name)
            return ComplianceResult(
                check_name="ssh_v2_only", passed=True, severity=sev,
                detail="SSHv2 is explicitly enabled")

    return ComplianceResult(
        check_name="ssh_v2_only", passed=False, severity=sev,
        detail=f"Unexpected SSH version config: {'; '.join(ssh_version_lines)}")


def _check_no_open_ports(snapshot: DeviceSnapshot, config: dict[str, Any]) -> ComplianceResult:
    allowed = set(str(v) for v in config.get("allowed_vlans", []))
    lines = snapshot.config.lines
    violations: list[str] = []

    for i, line in enumerate(lines):
        if "switchport access vlan" not in line:
            continue
        parts = line.strip().split()
        if len(parts) < 4:
            continue
        vlan = parts[-1]
        if vlan in allowed:
            continue

        # Walk backwards to find the interface name
        iface = "unknown"
        for j in range(i - 1, max(i - 10, -1), -1):
            stripped = lines[j].strip()
            if stripped.startswith("interface "):
                iface = stripped.split(" ", 1)[1]
                break
        violations.append(f"{iface} in VLAN {vlan}")

    sev = config["severity"]
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
    ntp_lines = [line.strip() for line in snapshot.config.lines if "ntp server" in line]
    sev = config["severity"]

    if not ntp_lines:
        logger.warning("%s: no NTP servers configured", snapshot.device_name)
        return ComplianceResult(
            check_name="ntp_config", passed=False, severity=sev,
            detail="No NTP servers configured — at least one required")

    violations = []
    for line in ntp_lines:
        parts = line.split()
        if len(parts) >= 3:
            server = parts[2]
            if server not in approved:
                violations.append(server)

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
    syslog_lines = [line.strip() for line in snapshot.config.lines if "logging host" in line]
    sev = config["severity"]

    if not syslog_lines:
        logger.warning("%s: no syslog servers configured", snapshot.device_name)
        return ComplianceResult(
            check_name="syslog_config", passed=False, severity=sev,
            detail="No syslog servers configured — at least one required")

    violations = []
    for line in syslog_lines:
        parts = line.split()
        if len(parts) >= 3:
            server = parts[2]
            if server not in approved:
                violations.append(server)

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
