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

from net_audit.exceptions import ParseError
from net_audit.models import Device, DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig
from net_audit.parser import parse_interfaces, parse_version, parse_config
from net_audit.vendor_registry import Slot, get_commands

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
    params = {
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
    commands = get_commands(device.device_type)
    slot_map = (Slot.INTERFACES, Slot.VERSION, Slot.RUNNING_CONFIG)
    with ConnectHandler(**params) as conn:
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
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
            collection_error=str(exc),
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
        timeout: Optional per-device timeout in seconds. If a device takes
            longer than this, its collection is aborted and an error snapshot
            is returned. None means no timeout.
    """
    from time import monotonic

    deadline = monotonic() + timeout if timeout else None
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_dev = {pool.submit(collect_device, d): d for d in devices}
        pending = set(future_to_dev)
        completed: dict[str, DeviceSnapshot] = {}
        while pending:
            wait_timeout = None
            if deadline:
                wait_timeout = max(0, deadline - monotonic())
            done, pending = concurrent.futures.wait(
                pending,
                timeout=wait_timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                dev = future_to_dev[future]
                try:
                    completed[dev.name] = future.result(timeout=0)
                except TimeoutError:
                    logger.error("Collection from %s timed out after %ss", dev.name, timeout)
                    completed[dev.name] = DeviceSnapshot(
                        device_name=dev.name,
                        interfaces=ParsedInterfaces(),
                        version=ParsedVersion(),
                        config=ParsedConfig(),
                        collection_error=f"Collection timed out after {timeout}s",
                    )
            if deadline and monotonic() >= deadline:
                for fut in pending:
                    d = future_to_dev[fut]
                    completed[d.name] = DeviceSnapshot(
                        device_name=d.name,
                        interfaces=ParsedInterfaces(),
                        version=ParsedVersion(),
                        config=ParsedConfig(),
                        collection_error=f"Collection timed out after {timeout}s",
                    )
                break
    return [completed[d.name] for d in devices]
