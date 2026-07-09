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
        print(f"REMEDIATION APPROVAL REQUIRED for {device_name}")
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


def _ssh_strict_enabled() -> bool:
    """Return whether SSH host-key verification is enforced (default: on)."""
    import os

    val = os.environ.get("AUDNET_SSH_STRICT_KEY", "1").strip().lower()
    return val not in ("0", "false", "no", "off")


def _connect(device: Device) -> Any:  # pragma: no cover
    """Establish an SSH connection to a device using Netmiko."""
    params: dict[str, Any] = {
        "device_type": device.device_type,
        "host": device.host,
        "username": device.username,
        "password": device.get_password(),
        "port": device.port,
        "timeout": device.timeout,
        "conn_timeout": device.timeout,
        # Fail closed on unknown host keys unless AUDNET_SSH_STRICT_KEY=0
        "system_host_keys": True,
        "ssh_strict": _ssh_strict_enabled(),
    }
    if device.use_keys:
        params["use_keys"] = True
        if device.key_file:
            params["key_file"] = device.key_file
    secret = device.get_secret()
    if secret:
        params["secret"] = secret

    try:
        conn = ConnectHandler(**params)
        if secret:
            try:
                conn.enable()
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to enter enable mode on %s: %s", device.name, exc)
        return conn
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
        current_lines: Current config lines on the device.
        desired_snippet: Desired config snippet to apply.

    Returns:
        ConfigDiff showing what would change.
    """
    # Use a stripped set for O(1) lookups. For very large configs (>100KB),
    # this is still more memory-efficient than holding multiple copies of
    # the full config text.
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

    device = device.model_copy(update={"timeout": timeout})

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

    # Step 2: Compute diff. Use the raw config string for membership
    # checking to avoid building an intermediate list + set.
    current_text = current_config or ""
    diff = compute_diff(list(current_text.splitlines()), config_snippet)
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

    # Keep the pre-change config for rollback. Checkpoint MUST be taken
    # while running-config is still good (before apply).
    rollback_config = current_config
    checkpoint_file: str | None = None

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
        # Checkpoint the pre-apply running-config to flash BEFORE any changes.
        # Rolling back by re-copying running-config after a failed apply would
        # snapshot the broken state — which is worse than no rollback at all.
        checkpoint_file = _create_checkpoint(conn)

        # Enter config mode and apply lines.
        # Use the full config_snippet (not just diff.added_lines) so that
        # parent context commands (e.g. "interface Loopback999") are included
        # alongside sub-mode commands (e.g. "description NEW"). Sending only
        # the diff lines would place sub-mode commands in global config mode,
        # which fails silently on IOS-XE.
        output = conn.send_config_set(config_snippet, exit_config_mode=True)
        logger.debug("Config apply output: %s", output)
        applied = True

        # Verify: re-read running config and check lines are present.
        # Only verify the lines that were actually new (diff.added_lines),
        # not the full snippet — parent context lines may have been present
        # already and that is expected.
        post_config = conn.send_command("show running-config") or ""
        post_set = {line.strip() for line in post_config.splitlines() if line.strip()}

        missing = [line for line in diff.added_lines if line not in post_set]
        if missing:
            raise RemediationError(
                f"Verification failed: {len(missing)} lines not found after apply: "
                f"{missing[:3]}{'...' if len(missing) > 3 else ''}"
            )

        logger.info("Successfully applied config to %s", device_name)
        _cleanup_checkpoint(conn, checkpoint_file)

        return RemediationResult(
            device_name=device_name,
            status=RemediationStatus.SUCCESS,
            diff=diff,
            duration_seconds=time.monotonic() - start,
        )

    except Exception as exc:
        logger.error("Failed to apply config to %s: %s", device_name, exc)

        # Step 7: Automatic rollback using the *pre-apply* checkpoint
        if applied:
            logger.warning("Attempting rollback for %s", device_name)
            try:
                rollback_output = _rollback_config(
                    conn,
                    rollback_config,
                    checkpoint_file=checkpoint_file,
                )
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


def _handle_copy_prompts(conn: Any, output: str) -> str:
    """Respond to interactive copy/replace prompts (filename, overwrite, y/n)."""
    lower = output.lower()
    # Destination filename? — accept default
    if "destination filename" in lower or "filename" in lower and "?" in lower:
        output += conn.send_command_timing("\n", read_timeout=60)
        lower = output.lower()
    if "overwrite" in lower or "y/n" in lower or "yes/no" in lower or "[no]" in lower:
        output += conn.send_command_timing("y", read_timeout=60)
    return str(output)


def _create_checkpoint(conn: Any) -> str:
    """Snapshot running-config to flash *before* remediation changes.

    Returns the flash filename of the checkpoint. Raises RemediationError
    if the checkpoint cannot be created — fail closed rather than apply
    without a recovery path.
    """
    checkpoint_file = f"_audnet_cp_{int(time.time())}"
    try:
        output = conn.send_command_timing(
            f"copy running-config flash:{checkpoint_file}",
            read_timeout=120,
        )
        output = _handle_copy_prompts(conn, output)
        logger.info("Created pre-apply checkpoint flash:%s", checkpoint_file)
        return checkpoint_file
    except Exception as exc:
        raise RemediationError(
            f"Failed to create pre-apply checkpoint (refusing to apply): {exc}"
        ) from exc


def _cleanup_checkpoint(conn: Any, checkpoint_file: str | None) -> None:
    """Best-effort delete of a flash checkpoint file."""
    if not checkpoint_file:
        return
    try:
        out = conn.send_command_timing(f"delete /force flash:{checkpoint_file}")
        _handle_copy_prompts(conn, out)
    except Exception:  # nosec B110  # pragma: no cover
        logger.debug("Could not delete checkpoint flash:%s", checkpoint_file)


def _rollback_config(
    conn: Any,
    previous_config: str,
    *,
    checkpoint_file: str | None = None,
) -> str:
    """Rollback to a pre-apply checkpoint (preferred) or previous config text.

    Strategy:
    1. ``configure replace flash:<checkpoint> force`` where *checkpoint* was
       created from the **pre-apply** running-config (never re-copy running
       config after a failed apply — that would restore the broken state).
    2. Fall back to pushing the in-memory *previous_config* lines.

    Args:
        conn: Active Netmiko connection
        previous_config: The full previous running config text (in-memory)
        checkpoint_file: Flash filename created by :func:`_create_checkpoint`

    Returns:
        Output from the rollback command(s)

    Raises:
        RemediationRollbackError: If rollback fails
    """
    last_exc: Exception | None = None

    # Strategy 1: configure replace from pre-apply flash checkpoint
    if checkpoint_file:
        try:
            output = conn.send_command_timing(
                f"configure replace flash:{checkpoint_file} force",
                read_timeout=120,
            )

            # Handle any confirmation prompts (e.g., "[y/n]", "[yes/no]", "? [no]:")
            lower = output.lower()
            if "y/n" in lower or "yes/no" in lower or "[no]" in lower:
                output += conn.send_command_timing("y", read_timeout=120)

            logger.info("configure replace rollback succeeded from %s", checkpoint_file)

            # configure replace disrupts the SSH session on IOS-XE.
            try:
                conn.disconnect()
            except Exception:  # pragma: no cover  # nosec B110
                pass

            # Best-effort reconnect + cleanup of checkpoint file
            try:  # pragma: no cover
                new_conn = ConnectHandler(
                    device_type=conn.device_type,
                    host=conn.host,
                    username=conn.username,
                    password=conn.password,
                    port=conn.port,
                    timeout=conn.timeout,
                    system_host_keys=True,
                    ssh_strict=_ssh_strict_enabled(),
                )
                _cleanup_checkpoint(new_conn, checkpoint_file)
                try:
                    new_conn.disconnect()
                except Exception:  # nosec B110  # pragma: no cover
                    pass
            except Exception:  # pragma: no cover  # nosec B110
                pass

            return str(output)
        except Exception as exc:  # pragma: no cover
            last_exc = exc
            logger.warning(
                "configure replace rollback failed: %s, trying line-by-line", exc
            )

    # Strategy 2: Line-by-line rollback from in-memory previous_config
    try:
        lines = [line for line in previous_config.splitlines() if line.strip()]
        if not lines:
            raise RemediationRollbackError(
                "No previous config text available for line-by-line rollback"
            )
        output = conn.send_config_set(lines, exit_config_mode=True)
        return str(output)  # pragma: no cover
    except Exception as exc:  # pragma: no cover
        last_exc = exc
        logger.warning("line-by-line rollback failed: %s", exc)

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
    timeout: int = 30,
) -> list[RemediationResult]:
    """Apply remediation to one or more devices.

    Sequential mode (``max_workers=1``, default) stops the pipeline on the
    first live failure. Parallel mode applies to all devices concurrently.

    Args:
        devices: Target devices
        config_snippet: Config lines to apply
        dry_run: If True, only compute diffs
        auto_approve: If True, skip interactive approval
        force: If True, apply even if no changes detected
        max_workers: Parallel workers (default 1 for safe sequential pipeline)
        timeout: SSH timeout in seconds for each device connection

    Returns:
        List of RemediationResult, one per device
    """
    if max_workers > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        ordered: dict[str, RemediationResult] = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(
                    apply_config,
                    device,
                    config_snippet,
                    dry_run=dry_run,
                    auto_approve=auto_approve,
                    force=force,
                    timeout=timeout,
                ): device
                for device in devices
            }
            for future in as_completed(futures):
                device = futures[future]
                ordered[device.name] = future.result()
        return [ordered[d.name] for d in devices if d.name in ordered]

    results: list[RemediationResult] = []
    for device in devices:
        result = apply_config(
            device,
            config_snippet,
            dry_run=dry_run,
            auto_approve=auto_approve,
            force=force,
            timeout=timeout,
        )
        results.append(result)

        if not result.success and not dry_run:
            logger.error(
                "Remediation failed for %s — stopping pipeline. Error: %s",
                device.name,
                result.error,
            )
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
