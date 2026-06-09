"""Compliance engine — runs security baseline checks against device snapshots."""

from __future__ import annotations

import re

from net_audit.models import DeviceSnapshot, ComplianceResult


def _check_ssh_v2_only(snapshot: DeviceSnapshot, config: dict) -> ComplianceResult:
    lines = snapshot.config.lines
    has_v2 = any(re.search(r"ip ssh version\s+2", line) for line in lines)
    has_v1 = any(re.search(r"ip ssh version\s+1", line) for line in lines)
    sev = config["severity"]

    if has_v1:
        return ComplianceResult(check_name="ssh_version", passed=False, severity=sev,
                                detail="SSHv1 is configured — prohibited")
    if has_v2:
        return ComplianceResult(check_name="ssh_version", passed=True, severity=sev,
                                detail="SSHv2 is enabled")
    return ComplianceResult(check_name="ssh_version", passed=False, severity=sev,
                            detail="No SSH version configuration found")


def _check_no_open_ports(snapshot: DeviceSnapshot, config: dict) -> ComplianceResult:
    allowed = set(str(v) for v in config.get("allowed_vlans", []))
    lines = snapshot.config.lines
    violations = []

    for i, line in enumerate(lines):
        m = re.search(r"switchport access vlan (\d+)", line)
        if m and m.group(1) not in allowed:
            iface = "unknown"
            for j in range(i - 1, max(i - 5, -1), -1):
                im = re.match(r"^interface\s+(\S+)", lines[j])
                if im:
                    iface = im.group(1)
                    break
            violations.append(f"{iface} in VLAN {m.group(1)}")

    sev = config["severity"]
    if violations:
        return ComplianceResult(check_name="inactive_ports", passed=False, severity=sev,
                                detail=f"Unauthorized VLANs: {'; '.join(violations)}")
    return ComplianceResult(check_name="inactive_ports", passed=True, severity=sev,
                            detail="All VLAN assignments are within the allowed set")


def _check_ntp_approved(snapshot: DeviceSnapshot, config: dict) -> ComplianceResult:
    approved = set(str(s) for s in config.get("approved_servers", []))
    violations = [m.group(1) for line in snapshot.config.lines
                  if (m := re.search(r"ntp server\s+(\S+)", line)) and m.group(1) not in approved]
    sev = config["severity"]

    if violations:
        return ComplianceResult(check_name="ntp_config", passed=False, severity=sev,
                                detail=f"Unapproved NTP servers: {', '.join(violations)}")
    if not any("ntp server" in line for line in snapshot.config.lines):
        return ComplianceResult(check_name="ntp_config", passed=False, severity=sev,
                                detail="No NTP servers configured")
    return ComplianceResult(check_name="ntp_config", passed=True, severity=sev,
                            detail="All NTP servers are approved")


def _check_syslog_approved(snapshot: DeviceSnapshot, config: dict) -> ComplianceResult:
    approved = set(str(s) for s in config.get("approved_servers", []))
    violations = [m.group(1) for line in snapshot.config.lines
                  if (m := re.search(r"logging host\s+(\S+)", line)) and m.group(1) not in approved]
    sev = config["severity"]

    if violations:
        return ComplianceResult(check_name="syslog_config", passed=False, severity=sev,
                                detail=f"Unapproved syslog servers: {', '.join(violations)}")
    if not any("logging host" in line for line in snapshot.config.lines):
        return ComplianceResult(check_name="syslog_config", passed=False, severity=sev,
                                detail="No syslog servers configured")
    return ComplianceResult(check_name="syslog_config", passed=True, severity=sev,
                            detail="All syslog servers are approved")


_RULE_DISPATCH = {
    "ssh_v2_only": _check_ssh_v2_only,
    "no_open_ports": _check_no_open_ports,
    "ntp_approved": _check_ntp_approved,
    "syslog_approved": _check_syslog_approved,
}


def run_checks(snapshot: DeviceSnapshot, baseline: dict) -> list[ComplianceResult]:
    results = []
    for check_name, check_config in baseline.get("checks", {}).items():
        handler = _RULE_DISPATCH.get(check_config.get("rule"))
        if handler is None:
            results.append(ComplianceResult(
                check_name=check_name, passed=False,
                severity=check_config.get("severity", "medium"),
                detail=f"Unknown rule: {check_config.get('rule')}"))
        else:
            results.append(handler(snapshot, check_config))
    return results
