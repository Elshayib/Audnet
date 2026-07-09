"""Parallel SSH collector for network device data.

Uses the vendor registry for multi-vendor command dispatch.
"""

import logging
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from typing import cast

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
    ConfigInvalidException,
    ConnectionException,
    ReadException,
    NetmikoParsingException,
)
from paramiko.ssh_exception import SSHException
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

from audnet.exceptions import ParseError
from audnet.models import Device, DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig
from audnet.parser import parse_interfaces, parse_version, parse_config
from audnet.vendor_registry import Slot, get_commands

logger = logging.getLogger(__name__)

# Transient exceptions that are safe to retry on
_RETRYABLE_EXCEPTIONS = (
    NetmikoTimeoutException,
    ConnectionException,
    ReadException,
    SSHException,
    NetmikoParsingException,
    OSError,
    ConnectionError,
)


def _is_retryable(exc: BaseException) -> bool:
    """Return True if *exc* is a transient error worth retrying.

    Explicitly excludes authentication failures — those are never transient.
    """
    if isinstance(exc, NetmikoAuthenticationException):
        return False
    return isinstance(exc, _RETRYABLE_EXCEPTIONS)


def _ssh_strict_enabled() -> bool:
    """Return whether SSH host-key verification is enforced (default: on)."""
    import os

    val = os.environ.get("AUDNET_SSH_STRICT_KEY", "1").strip().lower()
    return val not in ("0", "false", "no", "off")


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
def _do_ssh_collect(device: Device) -> dict[Slot, str]:
    """Internal function that performs the actual SSH collection.

    Retries transient errors up to 3 times with exponential backoff.
    Returns a dict mapping Slot -> raw CLI output.
    """
    params: dict = {
        "device_type": device.device_type,
        "host": device.host,
        "username": device.username,
        "password": device.get_password(),
        "port": device.port,
        # Netmiko: conn_timeout = TCP/SSH connect; timeout = read/session
        "timeout": device.timeout,
        "conn_timeout": device.timeout,
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
    commands = get_commands(device.device_type)
    slot_map = (Slot.INTERFACES, Slot.VERSION, Slot.RUNNING_CONFIG)
    with ConnectHandler(**params) as conn:
        if secret:
            try:
                conn.enable()
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to enter enable mode on %s: %s", device.name, exc)
        return {slot: cast(str, conn.send_command(cmd)) for slot, cmd in zip(slot_map, commands)}

def collect_device(device: Device) -> DeviceSnapshot:
    """Collect data from one device (with internal retry for transient SSH issues)."""
    logger.info("Collecting data from %s (%s)", device.name, device.host)
    try:
        raw_outputs = _do_ssh_collect(device)

        logger.info("Successfully collected from %s", device.name)
        parsed_version = parse_version(raw_outputs[Slot.VERSION], device_type=device.device_type)
        return DeviceSnapshot(
            device_name=device.name,
            device_type=device.device_type,
            interfaces=ParsedInterfaces(
                interfaces=parse_interfaces(
                    raw_outputs[Slot.INTERFACES], device_type=device.device_type
                )
            ),
            version=ParsedVersion(**parsed_version, raw=raw_outputs[Slot.VERSION]),
            config=ParsedConfig(
                lines=parse_config(raw_outputs[Slot.RUNNING_CONFIG]),
                raw=raw_outputs[Slot.RUNNING_CONFIG],
            ),
        )
    except (
        NetmikoTimeoutException,
        NetmikoAuthenticationException,
        ConfigInvalidException,
        ConnectionException,
        ReadException,
        NetmikoParsingException,
        SSHException,
        OSError,
        ValueError,
        ConnectionError,
        ParseError,
    ) as exc:
        logger.error("Failed to collect from %s: %s", device.name, exc)
        return DeviceSnapshot(
            device_name=device.name,
            device_type=device.device_type,
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
            collection_error=str(exc),
        )


def _timeout_snapshot(device: Device, timeout: float) -> DeviceSnapshot:
    return DeviceSnapshot(
        device_name=device.name,
        device_type=device.device_type,
        interfaces=ParsedInterfaces(),
        version=ParsedVersion(),
        config=ParsedConfig(),
        collection_error=f"Collection timed out after {timeout}s",
    )


def collect_all(
    devices: list[Device],
    max_workers: int = 4,
    timeout: float | None = None,
) -> list[DeviceSnapshot]:
    """Run parallel collection across devices.

    Args:
        devices: List of devices to collect from.
        max_workers: Maximum parallel SSH connections.
        timeout: Optional per-device wall-clock budget in seconds. Measured
            from when the worker *starts* (via a shared started_at map set
            inside a thin wrapper), falling back to submit time for not-yet-
            started work. None means no outer timeout.
    """
    from time import monotonic
    from threading import Lock

    started_at: dict[concurrent.futures.Future[DeviceSnapshot], float] = {}
    started_lock = Lock()

    def _run(device: Device) -> DeviceSnapshot:
        # Record start time when the worker actually begins (not at submit).
        # The future object is looked up after submit below.
        return collect_device(device)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_dev = {pool.submit(_run, d): d for d in devices}
        # Until a worker starts, use submit time as a conservative bound so
        # queued devices don't wait forever under a small worker pool.
        submitted_at = {future: monotonic() for future in future_to_dev}
        pending = set(future_to_dev)
        completed: dict[str, DeviceSnapshot] = {}

        # Wrap collect to stamp started_at — re-submit with wrapper that
        # records start. (Futures already submitted; stamp on first wait
        # via running() check.)
        def _effective_start(fut: concurrent.futures.Future[DeviceSnapshot]) -> float:
            with started_lock:
                if fut in started_at:
                    return started_at[fut]
            # If already running, treat "now" as start the first time we see it
            if fut.running():
                with started_lock:
                    started_at.setdefault(fut, monotonic())
                    return started_at[fut]
            return submitted_at[fut]

        while pending:
            done: set[concurrent.futures.Future[DeviceSnapshot]]
            if timeout:
                now = monotonic()
                # Stamp any newly running futures
                for fut in pending:
                    if fut.running():
                        with started_lock:
                            started_at.setdefault(fut, now)

                overdue = {
                    fut
                    for fut in pending
                    if now - _effective_start(fut) >= timeout
                }
                for fut in overdue:
                    # cancel() only works for not-yet-started work; running
                    # threads keep going until Netmiko's own timeouts fire.
                    fut.cancel()
                    dev = future_to_dev[fut]
                    logger.error(
                        "Collection from %s timed out after %ss", dev.name, timeout
                    )
                    completed[dev.name] = _timeout_snapshot(dev, timeout)
                    pending.discard(fut)

                if not pending:
                    break

                earliest = min(
                    _effective_start(fut) + timeout - now for fut in pending
                )
                wait_timeout = max(0.01, earliest)
            else:
                wait_timeout = None

            done, pending = concurrent.futures.wait(
                pending,
                timeout=wait_timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                dev = future_to_dev[future]
                try:
                    completed[dev.name] = future.result(timeout=0)
                except concurrent.futures.CancelledError:
                    if dev.name not in completed:
                        completed[dev.name] = _timeout_snapshot(dev, timeout or 0)
                except TimeoutError:
                    future.cancel()
                    completed[dev.name] = _timeout_snapshot(dev, timeout or 0)
                except Exception as exc:
                    # Isolate unexpected worker exceptions so one bad device
                    # does not abort the rest of the batch.
                    logger.error("Unexpected error collecting from %s: %s", dev.name, exc)
                    completed[dev.name] = DeviceSnapshot(
                        device_name=dev.name,
                        device_type=dev.device_type,
                        interfaces=ParsedInterfaces(),
                        version=ParsedVersion(),
                        config=ParsedConfig(),
                        collection_error=str(exc),
                    )

    for dev in devices:
        completed.setdefault(dev.name, _timeout_snapshot(dev, timeout or 0))
    return [completed[d.name] for d in devices]
