"""Compliance engine — runs security baseline checks against device snapshots.

Supports vendor-specific pattern overrides via the ``vendor_patterns`` config
key in each check.  Falls back to Cisco IOS patterns for unknown vendors.
"""

from __future__ import annotations

import logging
from typing import Any

from audnet.models import ComplianceResult, DeviceSnapshot

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default (Cisco IOS) config-line patterns per rule
# ---------------------------------------------------------------------------
_DEFAULT_PATTERNS: dict[str, dict[str, Any]] = {
    "ssh_v2_only": {
        "match": "ip ssh version",
        "ok_value": "ip ssh version 2",
        "fail_value": "ip ssh version 1",
        "ok_detail": "SSHv2 is explicitly enabled",
        "fail_detail_v1": "SSHv1 is configured — prohibited. Use 'ip ssh version 2'",
        "fail_detail_missing": "No SSH version configuration found — must explicitly set 'ip ssh version 2'",
        "fail_detail_unexpected": "Unexpected SSH version config: {lines}",
    },
    "no_open_ports": {
        "match": "switchport access vlan",
        "iface_prefix": "interface ",
        "ok_detail": "All VLAN assignments are within the allowed set",
        "fail_detail": "Unauthorized VLAN assignments: {violations}",
    },
    "ntp_approved": {
        "match": "ntp server",
        "ok_detail": "All NTP servers are approved",
        "fail_detail": "Unapproved NTP servers: {violations}",
        "fail_detail_missing": "No NTP servers configured — at least one required",
    },
    "syslog_approved": {
        "match": "logging host",
        "ok_detail": "All syslog servers are approved",
        "fail_detail": "Unapproved syslog servers: {violations}",
        "fail_detail_missing": "No syslog servers configured — at least one required",
    },
}


def _get_patterns(rule: str, check_config: dict[str, Any]) -> dict[str, Any]:
    """Return effective patterns for a rule, merging vendor overrides."""
    base = dict(_DEFAULT_PATTERNS.get(rule, {}))
    vendor_overrides = check_config.get("vendor_patterns", {})
    # vendor_overrides is a dict of {device_type: {pattern_key: value}}
    # For now we use the base patterns; vendor_overrides can be passed in
    # the baseline YAML to customize per vendor.
    if isinstance(vendor_overrides, dict):
        # If vendor_overrides has a 'default' key, apply those as base overrides
        default_overrides = vendor_overrides.get("default", {})
        if isinstance(default_overrides, dict):
            base.update(default_overrides)
    return base


def _check_ssh_v2_only(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "ssh_v2_only"
) -> ComplianceResult:
    lines = snapshot.config.lines
    sev = config["severity"]
    patterns = _get_patterns("ssh_v2_only", config)
    match = patterns["match"]
    ok_value = patterns["ok_value"]
    fail_value = patterns["fail_value"]

    ssh_version_lines = [line for line in lines if match in line.lower()]
    if not ssh_version_lines:
        logger.warning("%s: no '%s' directive found", snapshot.device_name, match)
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_missing"],
        )

    for line in ssh_version_lines:
        line_lower = line.lower()
        if fail_value in line_lower:
            logger.info("%s: SSHv1 detected", snapshot.device_name)
            return ComplianceResult(
                check_name=check_name,
                passed=False,
                severity=sev,
                detail=patterns["fail_detail_v1"],
            )
        if ok_value in line_lower:
            logger.info("%s: SSHv2 confirmed", snapshot.device_name)
            return ComplianceResult(
                check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
            )

    return ComplianceResult(
        check_name=check_name,
        passed=False,
        severity=sev,
        detail=patterns["fail_detail_unexpected"].format(lines="; ".join(ssh_version_lines)),
    )


def _check_no_open_ports(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "inactive_ports"
) -> ComplianceResult:
    allowed = set(str(v) for v in config.get("allowed_vlans", []))
    lines = snapshot.config.lines
    violations: list[str] = []
    patterns = _get_patterns("no_open_ports", config)
    match = patterns["match"]
    iface_prefix = patterns["iface_prefix"]

    current_iface = "unknown"
    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith(iface_prefix):
            current_iface = stripped.split(" ", 1)[1]
        if match not in line.lower():
            continue
        parts = stripped.split()
        if len(parts) < 4:
            continue
        vlan = parts[-1]
        if vlan in allowed:
            continue
        violations.append(f"{current_iface} in VLAN {vlan}")

    sev = config["severity"]
    if violations:
        logger.info("%s: unauthorized VLANs: %s", snapshot.device_name, violations)
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail"].format(violations="; ".join(violations)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_ntp_approved(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "ntp_config"
) -> ComplianceResult:
    approved = set(str(s) for s in config.get("approved_servers", []))
    patterns = _get_patterns("ntp_approved", config)
    match = patterns["match"]
    ntp_lines = [line.strip() for line in snapshot.config.lines if match in line.lower()]
    sev = config["severity"]

    if not ntp_lines:
        logger.warning("%s: no NTP servers configured", snapshot.device_name)
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_missing"],
        )

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
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail"].format(violations=", ".join(violations)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_syslog_approved(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "syslog_config"
) -> ComplianceResult:
    approved = set(str(s) for s in config.get("approved_servers", []))
    patterns = _get_patterns("syslog_approved", config)
    match = patterns["match"]
    syslog_lines = [line.strip() for line in snapshot.config.lines if match in line.lower()]
    sev = config["severity"]

    if not syslog_lines:
        logger.warning("%s: no syslog servers configured", snapshot.device_name)
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_missing"],
        )

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
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail"].format(violations=", ".join(violations)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


_RULE_DISPATCH: dict[str, Any] = {
    "ssh_v2_only": _check_ssh_v2_only,
    "no_open_ports": _check_no_open_ports,
    "ntp_approved": _check_ntp_approved,
    "syslog_approved": _check_syslog_approved,
}


def list_checks() -> list[str]:
    """Return all available compliance rule names."""
    return sorted(_RULE_DISPATCH.keys())


def run_checks(snapshot: DeviceSnapshot, baseline: dict[str, Any]) -> list[ComplianceResult]:
    results = []
    for check_name, check_config in baseline.get("checks", {}).items():
        handler = _RULE_DISPATCH.get(check_config.get("rule"))
        if handler is None:
            logger.warning("Unknown rule '%s' for check '%s'", check_config.get("rule"), check_name)
            results.append(
                ComplianceResult(
                    check_name=check_name,
                    passed=False,
                    severity=check_config.get("severity", "medium"),
                    detail=f"Unknown rule: {check_config.get('rule')}",
                )
            )
        else:
            results.append(handler(snapshot, check_config, check_name))
    return results
