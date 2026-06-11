"""Parallel SSH collector for network device data.

Uses the vendor registry for multi-vendor command dispatch.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import cast

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
    ConfigInvalidException,
    ConnectionException,
    ReadException,
    SSHException,
    NetmikoParsingException,
)
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

from net_audit.models import Device, DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig
from net_audit.parser import parse_interfaces, parse_version, parse_config
from net_audit.vendor_registry import get_commands

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
def _do_ssh_collect(device: Device) -> list[str]:
    """Internal function that performs the actual SSH collection.
    Retries transient errors up to 3 times with exponential backoff.
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
    with ConnectHandler(**params) as conn:
        return [cast(str, conn.send_command(cmd)) for cmd in commands]


def collect_device(device: Device) -> DeviceSnapshot:
    """Collect data from one device (with internal retry for transient SSH issues)."""
    logger.info("Collecting data from %s (%s)", device.name, device.host)
    try:
        raw_outputs = _do_ssh_collect(device)

        logger.info("Successfully collected from %s", device.name)
        parsed_version = parse_version(raw_outputs[1], device_type=device.device_type)
        return DeviceSnapshot(
            device_name=device.name,
            interfaces=ParsedInterfaces(
                interfaces=parse_interfaces(raw_outputs[0], device_type=device.device_type)
            ),
            version=ParsedVersion(**parsed_version, raw=raw_outputs[1]),
            config=ParsedConfig(lines=parse_config(raw_outputs[2]), raw=raw_outputs[2]),
        )
    except (
        NetmikoTimeoutException,
        NetmikoAuthenticationException,
        ConfigInvalidException,
        ConnectionException,
        ReadException,
        SSHException,
        NetmikoParsingException,
        OSError,
        ValueError,
        ConnectionError,
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
    results: list[DeviceSnapshot] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(collect_device, d): d for d in devices}
        for future, dev in future_map.items():
            try:
                results.append(future.result(timeout=timeout))
            except TimeoutError:
                logger.error("Collection from %s timed out after %ss", dev.name, timeout)
                results.append(
                    DeviceSnapshot(
                        device_name=dev.name,
                        interfaces=ParsedInterfaces(),
                        version=ParsedVersion(),
                        config=ParsedConfig(),
                        collection_error=f"Collection timed out after {timeout}s",
                    )
                )
    return results
