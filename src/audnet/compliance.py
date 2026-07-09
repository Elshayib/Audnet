"""Compliance engine — runs security baseline checks against device snapshots.

Supports vendor-specific pattern overrides via the ``vendor_patterns`` config
key in each check.  Falls back to Cisco IOS patterns for unknown vendors.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from audnet.models import ComplianceResult, DeviceSnapshot

logger = logging.getLogger(__name__)

# Pre-compiled regex for exec-timeout parsing (used by _check_vty_timeout)
_RE_EXEC_TIMEOUT = re.compile(r"exec-timeout\s+(\d+)")

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


def _get_patterns(
    rule: str,
    check_config: dict[str, Any],
    device_type: str | None = None,
) -> dict[str, Any]:
    """Return effective patterns for a rule, merging vendor overrides."""
    base = dict(_DEFAULT_PATTERNS.get(rule, {}))
    vendor_overrides = check_config.get("vendor_patterns", {})
    if isinstance(vendor_overrides, dict):
        default_overrides = vendor_overrides.get("default", {})
        if isinstance(default_overrides, dict):
            base.update(default_overrides)
        if device_type:
            vendor_specific = vendor_overrides.get(device_type, {})
            if isinstance(vendor_specific, dict):
                base.update(vendor_specific)
    return base


def _is_negated(line: str) -> bool:
    """Return True if a config line is a ``no …`` negation."""
    return line.strip().lower().startswith("no ")


def _check_ssh_v2_only(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "ssh_v2_only"
) -> ComplianceResult:
    sev = config["severity"]
    patterns = _get_patterns("ssh_v2_only", config, snapshot.device_type)
    match = patterns["match"]
    ok_value = patterns["ok_value"]
    fail_value = patterns["fail_value"]

    # Evaluate ALL matching lines — SSHv1 anywhere fails even if v2 appears first
    ssh_version_lines = [
        line for line in snapshot.config.lines if match in line.lower() and not _is_negated(line)
    ]
    if not ssh_version_lines:
        logger.warning("%s: no '%s' directive found", snapshot.device_name, match)
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_missing"],
        )

    has_v1 = False
    has_v2 = False
    unexpected: list[str] = []
    for line in ssh_version_lines:
        ll = line.lower()
        # Prefer exact-ish match: fail_value as whole token sequence
        if fail_value in ll:
            # Avoid matching "ip ssh version 12" as v1 via word boundary
            if re.search(rf"{re.escape(fail_value)}(?:\s|$)", ll):
                has_v1 = True
                continue
        if ok_value in ll:
            if re.search(rf"{re.escape(ok_value)}(?:\s|$)", ll):
                has_v2 = True
                continue
        unexpected.append(line.strip())

    if has_v1:
        logger.info("%s: SSHv1 detected", snapshot.device_name)
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_v1"],
        )
    if has_v2 and not unexpected:
        logger.info("%s: SSHv2 confirmed", snapshot.device_name)
        return ComplianceResult(
            check_name=check_name,
            passed=True,
            severity=sev,
            detail=patterns["ok_detail"],
        )
    if unexpected:
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail_unexpected"].format(
                lines="; ".join(unexpected)
            ),
        )
    return ComplianceResult(
        check_name=check_name,
        passed=False,
        severity=sev,
        detail=patterns["fail_detail_missing"],
    )


def _check_no_open_ports(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "inactive_ports"
) -> ComplianceResult:
    allowed = set(str(v) for v in config.get("allowed_vlans", []))
    patterns = _get_patterns("no_open_ports", config, snapshot.device_type)
    match = patterns["match"]
    iface_prefix = patterns["iface_prefix"]

    violations: list[str] = []
    current_iface = "unknown"

    for line in snapshot.config.lines:
        stripped = line.strip()
        sl = stripped.lower()
        if sl.startswith(iface_prefix):
            current_iface = stripped.split(" ", 1)[1]
            continue  # skip to next line after updating current_iface
        if match not in sl:
            continue
        parts = stripped.split()
        if len(parts) < 4:
            continue
        vlan = parts[-1]
        if vlan not in allowed:
            violations.append(f"{current_iface} in VLAN {vlan}")

    sev = config["severity"]
    if violations:
        logger.info("%s: unauthorized VLANs: %s", snapshot.device_name, violations)
        return ComplianceResult(
            check_name=check_name, passed=False, severity=sev,
            detail=patterns["fail_detail"].format(violations="; ".join(violations)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_ntp_approved(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "ntp_config"
) -> ComplianceResult:
    approved = set(str(s) for s in config.get("approved_servers", []))
    patterns = _get_patterns("ntp_approved", config, snapshot.device_type)
    match = patterns["match"]
    sev = config["severity"]

    violations: list[str] = []
    found_any = False

    for line in snapshot.config.lines:
        ll = line.lower()
        if match not in ll:
            continue
        found_any = True
        stripped = line.strip()
        parts = stripped.split()
        if len(parts) < 3:
            # Incomplete "ntp server" line is a configuration defect, not a pass
            violations.append(f"<incomplete: {stripped}>")
            continue
        # Handle IOS-XE VRF syntax: "ntp server vrf <name> <ip>"
        if parts[2].lower() == "vrf":
            if len(parts) >= 5:
                server = parts[4]
            else:
                violations.append(f"<incomplete vrf: {stripped}>")
                continue
        else:
            server = parts[2]
        if server not in approved:
            violations.append(server)

    if not found_any:
        logger.warning("%s: no NTP servers configured", snapshot.device_name)
        return ComplianceResult(
            check_name=check_name, passed=False, severity=sev,
            detail=patterns["fail_detail_missing"],
        )

    if violations:
        logger.info("%s: unapproved NTP servers: %s", snapshot.device_name, violations)
        return ComplianceResult(
            check_name=check_name, passed=False, severity=sev,
            detail=patterns["fail_detail"].format(violations=", ".join(violations)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_syslog_approved(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "syslog_config"
) -> ComplianceResult:
    approved = set(str(s) for s in config.get("approved_servers", []))
    patterns = _get_patterns("syslog_approved", config, snapshot.device_type)
    match = patterns["match"]
    sev = config["severity"]

    violations: list[str] = []
    found_any = False

    for line in snapshot.config.lines:
        ll = line.lower()
        if match not in ll:
            continue
        found_any = True
        stripped = line.strip()
        parts = stripped.split()
        if len(parts) < 3:
            violations.append(f"<incomplete: {stripped}>")
            continue
        # Handle VRF: "logging host vrf <name> <ip>"
        if parts[2].lower() == "vrf":
            if len(parts) >= 5:
                server = parts[4]
            else:
                violations.append(f"<incomplete vrf: {stripped}>")
                continue
        else:
            server = parts[2]
        if server not in approved:
            violations.append(server)

    if not found_any:
        logger.warning("%s: no syslog servers configured", snapshot.device_name)
        return ComplianceResult(
            check_name=check_name, passed=False, severity=sev,
            detail=patterns["fail_detail_missing"],
        )

    if violations:
        logger.info("%s: unapproved syslog servers: %s", snapshot.device_name, violations)
        return ComplianceResult(
            check_name=check_name, passed=False, severity=sev,
            detail=patterns["fail_detail"].format(violations=", ".join(violations)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_snmp_v3_only(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "snmp_v3_only"
) -> ComplianceResult:
    """Check that no SNMPv1/v2c community strings are configured."""
    patterns = _get_patterns("snmp_v3_only", config, snapshot.device_type)
    match = patterns["match"]
    sev = config["severity"]

    # Ignore "no snmp-server community …" negation lines; never log raw communities
    community_lines = [
        line.strip()
        for line in snapshot.config.lines
        if match in line.lower() and not _is_negated(line)
    ]
    if community_lines:
        # Redact community values in detail — reports/history must not store secrets
        redacted = []
        for line in community_lines:
            parts = line.split()
            # snmp-server community <name> …
            if len(parts) >= 3:
                parts[2] = "***"
            redacted.append(" ".join(parts))
        logger.info(
            "%s: SNMPv1/v2c community strings found (%d)",
            snapshot.device_name,
            len(community_lines),
        )
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=patterns["fail_detail"].format(lines="; ".join(redacted)),
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
    patterns = _get_patterns("unused_iface_shutdown", config, snapshot.device_type)
    iface_prefix = patterns["iface_prefix"]

    # Build set of active interface names from parsed interfaces (those with IP)
    # Store lowercased to avoid repeated .lower() in the hot loop
    active_ifaces: set[str] = set()
    for iface in snapshot.interfaces.interfaces:
        name = iface.get("interface", "")
        ip_addr = iface.get("ip_address", "")
        if name and ip_addr and ip_addr not in ("", "unassigned"):
            active_ifaces.add(name.lower())

    # Track current interface and whether it has shutdown or is in allowed VLAN
    current_iface: str | None = None
    current_iface_lower: str | None = None
    has_shutdown = False
    has_allowed_vlan = False
    violations: list[str] = []

    def _finalize_iface() -> None:
        nonlocal current_iface, current_iface_lower, has_shutdown, has_allowed_vlan
        if current_iface is not None:
            if not (current_iface_lower in active_ifaces or has_allowed_vlan) and not has_shutdown:
                violations.append(current_iface)
        current_iface = None
        current_iface_lower = None
        has_shutdown = False
        has_allowed_vlan = False

    for line in snapshot.config.lines:
        stripped = line.strip()
        sl = stripped.lower()
        if sl.startswith(iface_prefix):
            _finalize_iface()
            current_iface = stripped.split(" ", 1)[1] if " " in stripped else stripped
            current_iface_lower = current_iface.lower()
        elif current_iface is not None:
            if sl == "shutdown":
                has_shutdown = True
            elif "switchport access vlan" in sl:
                parts = stripped.split()
                if len(parts) >= 4 and parts[-1] in allowed_vlans:
                    has_allowed_vlan = True

    _finalize_iface()

    sev = config["severity"]
    if violations:
        logger.info("%s: unused interfaces missing shutdown: %s", snapshot.device_name, violations)
        return ComplianceResult(
            check_name=check_name, passed=False, severity=sev,
            detail=patterns["fail_detail"].format(violations="; ".join(violations)),
        )
    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_vty_timeout(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "vty_timeout"
) -> ComplianceResult:
    """Check that all VTY line blocks have exec-timeout within the allowed limit."""
    max_minutes = int(config.get("max_timeout_minutes", 10))
    patterns = _get_patterns("vty_timeout", config, snapshot.device_type)
    line_prefix = patterns["line_prefix"]
    match = patterns["match"]

    in_vty = False
    has_timeout = False
    timeout_minutes = 0
    violations: list[str] = []
    missing: list[str] = []
    vty_block = ""

    for line in snapshot.config.lines:
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
        elif in_vty and (
            sl.startswith("line ")
            or sl.startswith("interface ")
            or sl.startswith("router ")
            or sl.startswith("ip ")
            or sl.startswith("!")
        ):
            # End of VTY block — do not absorb console/aux/global exec-timeout
            if not has_timeout:
                missing.append(vty_block)
            elif timeout_minutes > max_minutes:
                violations.append(f"{vty_block} (timeout={timeout_minutes}min)")
            in_vty = False
            has_timeout = False
            timeout_minutes = 0
            vty_block = ""
        elif in_vty and match in sl:
            has_timeout = True
            m = _RE_EXEC_TIMEOUT.search(sl)
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
    patterns = _get_patterns("aaa_auth", config, snapshot.device_type)
    sev = config["severity"]

    has_new_model = False
    has_auth_login = False
    for line in lines:
        sl = line.strip().lower()
        if _is_negated(sl):
            # "no aaa new-model" is not compliance
            continue
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
    patterns = _get_patterns("password_encryption", config, snapshot.device_type)
    sev = config["severity"]

    for line in lines:
        sl = line.lower().strip()
        if _is_negated(sl):
            continue
        if patterns["match"] in sl:
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
    patterns = _get_patterns("cdp_disabled", config, snapshot.device_type)
    sev = config["severity"]

    # Single pass: check for global disable AND track per-interface disables
    iface_cdp_disabled: set[str] = set()
    current_iface: str | None = None
    has_global_disable = False

    for line in snapshot.config.lines:
        stripped = line.strip()
        sl = stripped.lower()
        if "no cdp run" in sl:
            has_global_disable = True
            return ComplianceResult(
                check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
            )
        if sl.startswith("interface "):
            current_iface = stripped.split(" ", 1)[1] if " " in stripped else stripped
        elif current_iface is not None and "no cdp enable" in sl:
            iface_cdp_disabled.add(current_iface.lower())

    # Build set of all interfaces from parsed interfaces
    all_ifaces: set[str] = set()
    for iface in snapshot.interfaces.interfaces:
        name = iface.get("interface", "") or iface.get("port", "")
        if name:
            all_ifaces.add(name.lower())

    # If we have interface data, check that all interfaces have CDP disabled
    if all_ifaces:
        active_cdp = all_ifaces - iface_cdp_disabled
        if active_cdp:
            violations = sorted(active_cdp)
            return ComplianceResult(
                check_name=check_name, passed=False, severity=sev,
                detail=patterns["fail_detail"].format(violations="; ".join(violations)),
            )
        return ComplianceResult(
            check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
        )

    # No interface data and no global disable — fail closed (cannot prove CDP off)
    if not has_global_disable:
        return ComplianceResult(
            check_name=check_name,
            passed=False,
            severity=sev,
            detail=(
                "Cannot verify CDP is disabled: no interface data collected "
                "and 'no cdp run' not found"
            ),
        )

    return ComplianceResult(
        check_name=check_name, passed=True, severity=sev, detail=patterns["ok_detail"]
    )


def _check_login_banner(
    snapshot: DeviceSnapshot, config: dict[str, Any], check_name: str = "login_banner"
) -> ComplianceResult:
    """Check that a login banner is configured, optionally matching a required pattern."""
    patterns = _get_patterns("login_banner", config, snapshot.device_type)
    required_pattern = config.get("required_pattern")
    sev = config["severity"]

    banner_found = False
    banner_parts: list[str] = []
    in_banner = False
    banner_delimiter: str | None = None

    for line in snapshot.config.lines:
        stripped = line.strip()
        sl = stripped.lower()
        if patterns["match"] in sl:
            banner_found = True
            in_banner = True
            # Extract delimiter character (e.g., "banner login ^" -> ^)
            parts = stripped.split()
            if len(parts) >= 3:
                banner_delimiter = parts[-1]
            banner_parts.append(sl)
            continue
        if in_banner:
            if banner_delimiter and banner_delimiter in stripped:
                in_banner = False
                banner_delimiter = None
            else:
                banner_parts.append(sl)

    if not banner_found:
        return ComplianceResult(
            check_name=check_name, passed=False, severity=sev,
            detail=patterns["fail_detail_missing"],
        )

    # Check required pattern against accumulated banner text (lowercased)
    if required_pattern:
        rp_lower = required_pattern.lower()
        if not any(rp_lower in part for part in banner_parts):
            return ComplianceResult(
                check_name=check_name, passed=False, severity=sev,
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
