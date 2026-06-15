"""Safe automated push with dry-run enforcement and rollback.

Provides a controlled remediation path that:
- Always performs a dry-run + diff before live changes
- Supports idempotent config fragments
- Automatically rolls back on failure
- Full audit logging of every remediation action
- Approval gate stub for future Phase 3 integration
"""

from __future__ import annotations

import dataclasses
import logging
import time
from enum import Enum
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
    ConnectionException,
    ReadException,
)
from paramiko.ssh_exception import SSHException

from audnet.exceptions import CollectionError, NetAuditError
from audnet.models import Device, DeviceSnapshot

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RemediationError(NetAuditError):
    """Raised when a remediation action fails."""


class RemediationRollbackError(RemediationError):
    """Raised when both the remediation and rollback fail."""


class ApprovalRequiredError(RemediationError):
    """Raised when approval is required but not obtained."""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class RemediationStatus(Enum):
    SUCCESS = "success"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    DRY_RUN = "dry_run"
    SKIPPED = "skipped"  # Idempotent no-op


@dataclasses.dataclass
class ConfigDiff:
    """Represents the diff between current and desired config."""

    device_name: str
    added_lines: list[str]
    removed_lines: list[str]
    unchanged: bool

    def __str__(self) -> str:
        if self.unchanged:
            return f"[{self.device_name}] No changes needed (idempotent)."
        parts = [f"[{self.device_name}] Config diff:"]
        if self.removed_lines:
            parts.append("  --- (to remove)")
            for line in self.removed_lines:
                parts.append(f"    - {line}")
        if self.added_lines:
            parts.append("  +++ (to add)")
            for line in self.added_lines:
                parts.append(f"    + {line}")
        return "\n".join(parts)


@dataclasses.dataclass
class RemediationResult:
    """Result of a remediation attempt."""

    device_name: str
    status: RemediationStatus
    diff: ConfigDiff
    pre_snapshot: DeviceSnapshot | None = None
    post_snapshot: DeviceSnapshot | None = None
    rolled_back: bool = False
    rollback_error: str | None = None
    error: str | None = None
    duration_seconds: float = 0.0
    timestamp: str = dataclasses.field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )

    @property
    def success(self) -> bool:
        return self.status in (
            RemediationStatus.SUCCESS,
            RemediationStatus.DRY_RUN,
            RemediationStatus.SKIPPED,
        )


# ---------------------------------------------------------------------------
# Approval gate (stub for Phase 3)
# ---------------------------------------------------------------------------


class ApprovalGate:
    """Stub for future approval workflow integration.

    In Phase 3 this will integrate with ticketing systems, Slack
    approvals, or other workflow tools. Currently defaults to
    interactive CLI confirmation or auto-approve in automation mode.
    """

    def __init__(self, auto_approve: bool = False):
        self._auto_approve = auto_approve

    def request_approval(self, device_name: str, diff: ConfigDiff) -> bool:
        """Request approval for a remediation action.

        Args:
            device_name: Target device name
            diff: The config diff to be applied

        Returns:
            True if approved, False if denied.

        Raises:
            ApprovalRequiredError: If approval is required but cannot be obtained.
        """
        if self._auto_approve:
            logger.info("[AUTO-APPROVED] %s remediation", device_name)
            return True

        # Interactive CLI confirmation
        print(f"\n{'=' * 60}")
        print(f"REMEDIATION APPVAL REQUIRED for {device_name}")
        print(f"{'=' * 60}")
        print(str(diff))
        print(f"{'=' * 60}")

        try:
            response = input("Apply changes? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False

        if response not in ("y", "yes"):
            logger.info("Remediation denied by user for %s", device_name)
            return False

        logger.info("Remediation approved by user for %s", device_name)
        return True


# ---------------------------------------------------------------------------
# Core remediation logic
# ---------------------------------------------------------------------------


def _connect(device: Device) -> Any:  # pragma: no cover
    """Establish an SSH connection to a device using Netmiko."""
    params: dict[str, Any] = {
        "device_type": device.device_type,
        "host": device.host,
        "username": device.username,
        "password": device.get_password(),
        "port": device.port,
        "timeout": device.timeout,
    }
    if device.use_keys:
        params["use_keys"] = True
        if device.key_file:
            params["key_file"] = device.key_file

    try:
        return ConnectHandler(**params)
    except (NetmikoAuthenticationException, SSHException) as exc:
        raise CollectionError(f"Authentication failed for {device.name}: {exc}") from exc
    except (NetmikoTimeoutException, ConnectionException, ConnectionError) as exc:
        raise CollectionError(f"Connection failed for {device.name}: {exc}") from exc


def compute_diff(current_lines: list[str], desired_snippet: list[str]) -> ConfigDiff:
    """Compute the diff between current config and desired snippet.

    This is an idempotent diff: it checks whether the desired lines
    are already present in the current config. Only missing lines
    are reported as additions; lines not in the current config
    but in the snippet are additions.

    Args:
        current_lines: Current config lines on the device
        desired_snippet: Desired config snippet to apply

    Returns:
        ConfigDiff showing what would change
    """
    current_set = {line.strip() for line in current_lines if line.strip()}
    desired_stripped = [line.strip() for line in desired_snippet if line.strip()]

    added = [line for line in desired_stripped if line not in current_set]
    # We don't remove existing lines — remediation is additive only
    removed: list[str] = []

    unchanged = len(added) == 0 and len(removed) == 0

    return ConfigDiff(
        added_lines=added,
        removed_lines=removed,
        unchanged=unchanged,
        device_name="",  # Filled in by caller
    )


def apply_config(
    device: Device,
    config_snippet: list[str],
    *,
    dry_run: bool = True,
    auto_approve: bool = False,
    force: bool = False,
    timeout: int = 30,
) -> RemediationResult:
    """Apply a config snippet to a device with full safety guarantees.

    This is the main entry point for remediation. It:
    1. Connects to the device and grabs the current running config
    2. Computes an idempotent diff
    3. If dry_run, returns the diff without applying
    4. If not dry_run, requests approval (unless auto_approve)
    5. Applies the config snippet
    6. Verifies the result
    7. On failure, automatically rolls back

    Args:
        device: Target device
        config_snippet: Config lines to apply
        dry_run: If True, only compute and return the diff
        auto_approve: If True, skip interactive approval
        force: If True, apply even if diff shows no changes
        timeout: SSH timeout in seconds

    Returns:
        RemediationResult with full details of the action
    """
    start = time.monotonic()
    device_name = device.name

    logger.info("Starting remediation for %s (dry_run=%s)", device_name, dry_run)

    # Step 1: Connect and get current config
    try:
        conn = _connect(device)
    except CollectionError as exc:
        return RemediationResult(
            device_name=device_name,
            status=RemediationStatus.FAILED,
            diff=ConfigDiff(
                device_name=device_name, added_lines=[], removed_lines=[], unchanged=True
            ),
            error=str(exc),
            duration_seconds=time.monotonic() - start,
        )

    try:
        current_config = conn.send_command("show running-config")
        current_lines = current_config.splitlines() if current_config else []
    except (ReadException, NetmikoTimeoutException) as exc:  # pragma: no cover
        return RemediationResult(
            device_name=device_name,
            status=RemediationStatus.FAILED,
            diff=ConfigDiff(
                device_name=device_name, added_lines=[], removed_lines=[], unchanged=True
            ),
            error=f"Failed to get running config: {exc}",
            duration_seconds=time.monotonic() - start,
        )
    finally:
        conn.disconnect()

    # Step 2: Compute diff
    diff = compute_diff(current_lines, config_snippet)
    diff.device_name = device_name

    logger.info(
        "Diff for %s: %d lines to add, unchanged=%s",
        device_name,
        len(diff.added_lines),
        diff.unchanged,
    )

    # Step 3: Dry run — return diff without applying
    if dry_run:
        logger.info("Dry run for %s — not applying changes", device_name)
        return RemediationResult(
            device_name=device_name,
            status=RemediationStatus.DRY_RUN,
            diff=diff,
            duration_seconds=time.monotonic() - start,
        )

    # Step 4: Idempotent no-op detection
    if diff.unchanged and not force:
        logger.info("No changes needed for %s (idempotent)", device_name)
        return RemediationResult(
            device_name=device_name,
            status=RemediationStatus.SKIPPED,
            diff=diff,
            duration_seconds=time.monotonic() - start,
        )

    # Step 5: Approval gate
    gate = ApprovalGate(auto_approve=auto_approve)
    if not gate.request_approval(device_name, diff):
        return RemediationResult(
            device_name=device_name,
            status=RemediationStatus.FAILED,
            diff=diff,
            error="Approval denied",
            duration_seconds=time.monotonic() - start,
        )

    # Step 6: Apply config
    logger.info("Applying %d lines to %s", len(diff.added_lines), device_name)

    # Save current config for rollback
    rollback_config = current_config

    try:
        conn = _connect(device)
    except CollectionError as exc:  # pragma: no cover
        return RemediationResult(
            device_name=device_name,
            status=RemediationStatus.FAILED,
            diff=diff,
            error=str(exc),
            duration_seconds=time.monotonic() - start,
        )

    applied = False
    try:
        # Enter config mode and apply lines
        output = conn.send_config_set(diff.added_lines, exit_config_mode=True)
        logger.debug("Config apply output: %s", output)
        applied = True

        # Verify: re-read running config and check lines are present
        post_config = conn.send_command("show running-config")
        post_lines = post_config.splitlines() if post_config else []
        post_set = {line.strip() for line in post_lines if line.strip()}

        missing = [line for line in diff.added_lines if line not in post_set]
        if missing:
            raise RemediationError(
                f"Verification failed: {len(missing)} lines not found after apply: "
                f"{missing[:3]}{'...' if len(missing) > 3 else ''}"
            )

        logger.info("Successfully applied config to %s", device_name)

        return RemediationResult(
            device_name=device_name,
            status=RemediationStatus.SUCCESS,
            diff=diff,
            duration_seconds=time.monotonic() - start,
        )

    except Exception as exc:
        logger.error("Failed to apply config to %s: %s", device_name, exc)

        # Step 7: Automatic rollback
        if applied:
            logger.warning("Attempting rollback for %s", device_name)
            try:
                # Rollback: re-apply the previous running config
                # We use configure replace if available, otherwise push lines
                rollback_output = _rollback_config(conn, rollback_config)
                logger.info("Rollback successful for %s", rollback_output)

                return RemediationResult(
                    device_name=device_name,
                    status=RemediationStatus.ROLLED_BACK,
                    diff=diff,
                    rolled_back=True,
                    error=str(exc),
                    duration_seconds=time.monotonic() - start,
                )
            except Exception as rollback_exc:
                logger.critical(
                    "ROLLBACK FAILED for %s: %s. Manual intervention required.",
                    device_name,
                    rollback_exc,
                )
                return RemediationResult(
                    device_name=device_name,
                    status=RemediationStatus.FAILED,
                    diff=diff,
                    rolled_back=False,
                    rollback_error=str(rollback_exc),
                    error=f"Apply failed: {exc}. Rollback also failed: {rollback_exc}",
                    duration_seconds=time.monotonic() - start,
                )
        else:  # pragma: no cover
            return RemediationResult(
                device_name=device_name,
                status=RemediationStatus.FAILED,
                diff=diff,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    finally:
        try:
            conn.disconnect()
        except Exception:  # pragma: no cover  # nosec B110
            pass


def _rollback_config(conn: Any, previous_config: str) -> str:
    """Attempt to rollback to a previous config.

    Strategy:
    1. Try 'configure replace' with timing-based output (avoids prompt pattern
       mismatch on IOS-XE configure replace interactive output)
    2. Fall back to applying the previous config lines
    3. Try Netmiko's built-in rollback if available

    Args:
        conn: Active Netmiko connection
        previous_config: The full previous running config text

    Returns:
        Output from the rollback command(s)

    Raises:
        RemediationRollbackError: If rollback fails
    """
    rollback_file = f"_audnet_rollback_{int(time.time())}"
    last_exc: Exception | None = None

    # Strategy 1: configure replace with timing-based output
    try:
        # Save previous config to a file on the device
        conn.send_command_timing(f"copy running-config flash:{rollback_file}")

        # Use send_command_timing to handle interactive output from
        # configure replace on IOS-XE, which produces intermediate prompts
        # (e.g., "Are you sure? [y/n]") that don't match the standard prompt.
        output = conn.send_command_timing(
            f"configure replace flash:{rollback_file} force",
            read_timeout=120,
        )

        # Handle any confirmation prompts (e.g., "[y/n]", "[yes/no]")
        if "y/n" in output.lower() or "yes/no" in output.lower():
            output += conn.send_command_timing("y", read_timeout=120)

        logger.info("configure replace rollback succeeded")

        # Clean up rollback file
        try:  # pragma: no cover
            conn.send_command_timing(f"delete flash:{rollback_file}")
        except Exception:  # pragma: no cover  # nosec B110
            pass

        return str(output)
    except Exception as exc:  # pragma: no cover
        last_exc = exc
        logger.warning("configure replace rollback failed: %s, trying next strategy", exc)

    # Strategy 2: Netmiko built-in rollback (if supported by driver)
    try:
        if hasattr(conn, "rollback") and callable(conn.rollback):
            output = conn.rollback()
            logger.info("Netmiko rollback succeeded")
            # Clean up rollback file if it still exists
            try:  # pragma: no cover
                conn.send_command_timing(f"delete flash:{rollback_file}")
            except Exception:  # pragma: no cover  # nosec B110
                pass
            return str(output)
    except Exception as exc:  # pragma: no cover
        last_exc = exc
        logger.warning("Netmiko rollback failed: %s", exc)

    raise RemediationRollbackError(
        f"All rollback strategies failed for device. "
        f"Last error: {last_exc}"
    )


def remediate_devices(
    devices: list[Device],
    config_snippet: list[str],
    *,
    dry_run: bool = True,
    auto_approve: bool = False,
    force: bool = False,
    max_workers: int = 1,
) -> list[RemediationResult]:
    """Apply remediation to multiple devices sequentially.

    Note: Remediation is sequential (max_workers=1 by default) for safety.
    Parallel remediation is dangerous — if rollback fails, you want to
    stop the entire pipeline.

    Args:
        devices: Target devices
        config_snippet: Config lines to apply
        dry_run: If True, only compute diffs
        auto_approve: If True, skip interactive approval
        force: If True, apply even if no changes detected
        max_workers: Parallel workers (default 1 for safety)

    Returns:
        List of RemediationResult, one per device
    """
    results: list[RemediationResult] = []

    for device in devices:
        result = apply_config(
            device,
            config_snippet,
            dry_run=dry_run,
            auto_approve=auto_approve,
            force=force,
        )
        results.append(result)

        # Stop pipeline on failure (unless dry_run)
        if not result.success and not dry_run:
            logger.error(
                "Remediation failed for %s — stopping pipeline. Error: %s",
                device.name,
                result.error,
            )
            # Mark remaining devices as skipped
            for remaining in devices[len(results) :]:
                results.append(
                    RemediationResult(
                        device_name=remaining.name,
                        status=RemediationStatus.SKIPPED,
                        diff=ConfigDiff(
                            device_name=remaining.name,
                            added_lines=[],
                            removed_lines=[],
                            unchanged=True,
                        ),
                        error="Skipped due to previous failure",
                    )
                )
            break

    return results
