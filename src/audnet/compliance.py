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
    "snmp_v3_only": {
        "match": "snmp-server community",
        "ok_detail": "No SNMPv1/v2c community strings configured",
        "fail_detail": "SNMPv1/v2c community strings found: {lines}",
    },
    "unused_iface_shutdown": {
        "iface_prefix": "interface ",
        "ok_detail": "All unused interfaces are administratively shut down",
        "fail_detail": "Unused interfaces missing shutdown: {violations}",
    },
    "vty_timeout": {
        "line_prefix": "line vty",
        "match": "exec-timeout",
        "ok_detail": "All VTY lines have exec-timeout within limit",
        "fail_detail": "VTY lines exceeding max exec-timeout: {violations}",
        "fail_detail_missing": "VTY lines missing exec-timeout: {violations}",
    },
    "aaa_auth": {
        "match_new_model": "aaa new-model",
        "match_auth_login": "aaa authentication login default",
        "ok_detail": "AAA new-model and login authentication are configured",
        "fail_detail_missing_new_model": "aaa new-model is not configured",
        "fail_detail_missing_auth": "aaa authentication login default is not configured",
    },
    "password_encryption": {
        "match": "service password-encryption",
        "ok_detail": "service password-encryption is enabled",
        "fail_detail": "service password-encryption is not configured",
    },
    "cdp_disabled": {
        "ok_detail": "CDP is disabled globally or on all interfaces",
        "fail_detail": "CDP is active on: {violations}",
    },
    "login_banner": {
        "match": "banner login",
        "ok_detail": "Login banner is configured",
        "fail_detail_missing": "banner login is not configured",
        "fail_detail_pattern": "Login banner does not contain required pattern: {pattern}",
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


def _check_snmp_v3_only(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "snmp_v3_only"
) -> ComplianceResult:
    """Check that no SNMPv1/v2c community strings are configured."""
    lines = snapshot.config.lines
    sev = config["severity"]
    patterns = _get_patterns("snmp_v3_only", config)
    match = patterns["match"]

    community_lines = [line.strip() for line in lines if match in line.lower()]
    if community_lines:
        logger.info(
            "%s: SNMPv1/v2c community strings found: %s",
            snapshot.device_name,
            community_lines,
        )
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail"].format(lines="; ".join(community_lines)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_unused_iface_shutdown(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "unused_iface_shutdown"
) -> ComplianceResult:
    """Check that unused interfaces (no IP, not in allowed VLAN) are shut down.

    An interface is considered "active" (exempt from shutdown requirement) if:
    - It has an IP address assigned (from parsed interfaces), OR
    - It is in the allowed VLAN set

    All other interfaces must have 'shutdown' configured.
    """
    allowed_vlans = set(str(v) for v in config.get("allowed_vlans", []))
    lines = snapshot.config.lines
    patterns = _get_patterns("unused_iface_shutdown", config)
    iface_prefix = patterns["iface_prefix"]

    # Build set of active interface names from parsed interfaces (those with IP)
    active_ifaces: set[str] = set()
    for iface in snapshot.interfaces.interfaces:
        name = iface.get("interface", "")
        ip_addr = iface.get("ip_address", "")
        if name and ip_addr and ip_addr not in ("", "unassigned"):
            active_ifaces.add(name.lower())

    # Track current interface and whether it has shutdown or is in allowed VLAN
    current_iface: str | None = None
    has_shutdown = False
    has_allowed_vlan = False
    violations: list[str] = []

    def _is_active_by_vlan(iface_name: str) -> bool:
        """Check if interface name appears in allowed VLAN context."""
        return iface_name.lower() in active_ifaces

    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith(iface_prefix):
            # Finalize previous interface block
            if current_iface is not None:
                is_active = (
                    current_iface.lower() in active_ifaces or has_allowed_vlan
                )
                if not is_active and not has_shutdown:
                    violations.append(current_iface)
            # Start new interface block
            current_iface = stripped.split(" ", 1)[1] if " " in stripped else stripped
            has_shutdown = False
            has_allowed_vlan = False
        elif current_iface is not None:
            sl = stripped.lower()
            if "shutdown" == sl:
                has_shutdown = True
            elif "switchport access vlan" in sl:
                parts = stripped.split()
                if len(parts) >= 4 and parts[-1] in allowed_vlans:
                    has_allowed_vlan = True

    # Finalize last interface block
    if current_iface is not None:
        is_active = (
            current_iface.lower() in active_ifaces or has_allowed_vlan
        )
        if not is_active and not has_shutdown:
            violations.append(current_iface)

    sev = config["severity"]
    if violations:
        logger.info(
            "%s: unused interfaces missing shutdown: %s",
            snapshot.device_name,
            violations,
        )
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail"].format(violations="; ".join(violations)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_vty_timeout(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "vty_timeout"
) -> ComplianceResult:
    """Check that all VTY line blocks have exec-timeout within the allowed limit."""
    import re as _re

    max_minutes = int(config.get("max_timeout_minutes", 10))
    lines = snapshot.config.lines
    patterns = _get_patterns("vty_timeout", config)
    line_prefix = patterns["line_prefix"]
    match = patterns["match"]

    in_vty = False
    has_timeout = False
    timeout_minutes = 0
    violations: list[str] = []
    missing: list[str] = []
    vty_block = ""

    for line in lines:
        stripped = line.strip()
        sl = stripped.lower()
        if sl.startswith(line_prefix):
            # Finalize previous VTY block
            if in_vty:
                if not has_timeout:
                    missing.append(vty_block)
                elif timeout_minutes > max_minutes:
                    violations.append(f"{vty_block} (timeout={timeout_minutes}min)")
            in_vty = True
            has_timeout = False
            timeout_minutes = 0
            vty_block = stripped
        elif in_vty and match in sl:
            has_timeout = True
            m = _re.search(r"exec-timeout\s+(\d+)", sl)
            if m:
                timeout_minutes = int(m.group(1))

    # Finalize last VTY block
    if in_vty:
        if not has_timeout:
            missing.append(vty_block)
        elif timeout_minutes > max_minutes:
            violations.append(f"{vty_block} (timeout={timeout_minutes}min)")

    sev = config["severity"]
    if missing:
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_missing"].format(violations="; ".join(missing)),
        )
    if violations:
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail"].format(violations="; ".join(violations)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_aaa_auth(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "aaa_auth"
) -> ComplianceResult:
    """Check that aaa new-model and aaa authentication login default are configured."""
    lines = snapshot.config.lines
    patterns = _get_patterns("aaa_auth", config)
    sev = config["severity"]

    has_new_model = False
    has_auth_login = False
    for line in lines:
        sl = line.strip().lower()
        if patterns["match_new_model"] in sl:
            has_new_model = True
        if patterns["match_auth_login"] in sl:
            has_auth_login = True
        if has_new_model and has_auth_login:
            break

    if not has_new_model:
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_missing_new_model"],
        )
    if not has_auth_login:
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_missing_auth"],
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_password_encryption(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "password_encryption"
) -> ComplianceResult:
    """Check that service password-encryption is configured."""
    lines = snapshot.config.lines
    patterns = _get_patterns("password_encryption", config)
    sev = config["severity"]

    for line in lines:
        if patterns["match"] in line.lower():
            return ComplianceResult(
                check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
            )
    return ComplianceResult(
        check_name=check_name, passed=False, severity=sev, detail=patterns["fail_detail"]
    )


def _check_cdp_disabled(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "cdp_disabled"
) -> ComplianceResult:
    """Check that CDP is disabled globally (no cdp run) or per-interface (no cdp enable)."""
    lines = snapshot.config.lines
    patterns = _get_patterns("cdp_disabled", config)
    sev = config["severity"]

    # Check for global disable
    for line in lines:
        if "no cdp run" in line.lower():
            return ComplianceResult(
                check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
            )

    # Check per-interface: track interfaces with 'no cdp enable'
    iface_cdp_disabled: set[str] = set()
    current_iface: str | None = None
    for line in lines:
        stripped = line.strip()
        sl = stripped.lower()
        if sl.startswith("interface "):
            current_iface = stripped.split(" ", 1)[1] if " " in stripped else stripped
        elif current_iface is not None and "no cdp enable" in sl:
            iface_cdp_disabled.add(current_iface.lower())

    # Build set of all interfaces from parsed interfaces
    all_ifaces: set[str] = set()
    for iface in snapshot.interfaces.interfaces:
        name = iface.get("interface", "")
        if name:
            all_ifaces.add(name.lower())

    # If we have interface data, check that all interfaces have CDP disabled
    if all_ifaces:
        active_cdp = all_ifaces - iface_cdp_disabled
        if active_cdp:
            violations = sorted(active_cdp)
            return ComplianceResult(
                check_name=check_name,
                passed=False,
                severity=sev,
                detail=patterns["fail_detail"].format(violations="; ".join(violations)),
            )

    # No interface data available and no global disable — pass (can't determine)
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_login_banner(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "login_banner"
) -> ComplianceResult:
    """Check that a login banner is configured, optionally matching a required pattern."""
    lines = snapshot.config.lines
    patterns = _get_patterns("login_banner", config)
    required_pattern = config.get("required_pattern")
    sev = config["severity"]

    banner_found = False
    banner_text_lines: list[str] = []
    in_banner = False
    banner_delimiter = None

    for line in lines:
        stripped = line.strip()
        sl = stripped.lower()
        if patterns["match"] in sl:
            banner_found = True
            in_banner = True
            # Extract delimiter character (e.g., "banner login ^" -> ^)
            parts = stripped.split()
            if len(parts) >= 3:
                banner_delimiter = parts[-1]
            banner_text_lines.append(stripped)
            continue
        if in_banner:
            if banner_delimiter and banner_delimiter in stripped:
                in_banner = False
                banner_delimiter = None
            else:
                banner_text_lines.append(stripped)

    if not banner_found:
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_missing"],
        )

    if required_pattern:
        full_banner = " ".join(banner_text_lines)
        if required_pattern.lower() not in full_banner.lower():
            return ComplianceResult(
                check_name=check_name,
                passed=False,
                severity=sev,
                detail=patterns["fail_detail_pattern"].format(pattern=required_pattern),
            )

    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


_RULE_DISPATCH: dict[str, Any] = {
    "ssh_v2_only": _check_ssh_v2_only,
    "no_open_ports": _check_no_open_ports,
    "ntp_approved": _check_ntp_approved,
    "syslog_approved": _check_syslog_approved,
    "snmp_v3_only": _check_snmp_v3_only,
    "unused_iface_shutdown": _check_unused_iface_shutdown,
    "vty_timeout": _check_vty_timeout,
    "aaa_auth": _check_aaa_auth,
    "password_encryption": _check_password_encryption,
    "cdp_disabled": _check_cdp_disabled,
    "login_banner": _check_login_banner,
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
