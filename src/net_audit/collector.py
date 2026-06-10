"""Parallel SSH collector for network device data."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import cast

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from net_audit.models import Device, DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig
from net_audit.parser import parse_interfaces, parse_version, parse_config

logger = logging.getLogger(__name__)

VENDOR_COMMANDS: dict[str, list[str]] = {
    "cisco_ios": [
        "show ip interface brief",
        "show version",
        "show running-config",
    ],
    # Add entries for other vendors e.g. "juniper_junos", "arista_eos" for multi-vendor support
}


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((NetmikoTimeoutException, OSError, ConnectionError)),
    reraise=True,
)
def _do_ssh_collect(device: Device) -> list[str]:
    """Internal function that performs the actual SSH collection.
    Retries transient errors (timeout, OS, connection) up to 3 times with exponential backoff.
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
    commands = VENDOR_COMMANDS.get(device.device_type, VENDOR_COMMANDS["cisco_ios"])
    with ConnectHandler(**params) as conn:
        return [cast(str, conn.send_command(cmd)) for cmd in commands]


def collect_device(device: Device) -> DeviceSnapshot:
    """Collect data from one device (with internal retry for transient SSH issues)."""
    logger.info("Collecting data from %s (%s)", device.name, device.host)
    try:
        raw_outputs = _do_ssh_collect(device)

        logger.info("Successfully collected data from %s", device.name)
        parsed_version = parse_version(raw_outputs[1])
        return DeviceSnapshot(
            device_name=device.name,
            interfaces=ParsedInterfaces(interfaces=parse_interfaces(raw_outputs[0])),
            version=ParsedVersion(**parsed_version, raw=raw_outputs[1]),
            config=ParsedConfig(lines=parse_config(raw_outputs[2]), raw=raw_outputs[2]),
        )
    except (NetmikoTimeoutException, NetmikoAuthenticationException, OSError, ValueError, ConnectionError) as exc:
        logger.error("Failed to collect from %s: %s", device.name, exc)
        return DeviceSnapshot(
            device_name=device.name,
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
            collection_error=str(exc),
        )


def collect_all(devices: list[Device], max_workers: int = 4) -> list[DeviceSnapshot]:
    """Run parallel collection across devices."""
    results: list[DeviceSnapshot] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(collect_device, d): d for d in devices}
        for future in as_completed(future_map):
            results.append(future.result())
    return results
