"""Parallel SSH collector for network device data."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import cast

from netmiko import ConnectHandler

from net_audit.models import Device, DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig
from net_audit.parser import parse_interfaces

logger = logging.getLogger(__name__)

SHOW_COMMANDS = [
    "show ip interface brief",
    "show version",
    "show running-config",
]


def collect_device(device: Device) -> DeviceSnapshot:
    logger.info("Collecting data from %s (%s)", device.name, device.host)
    try:
        params = {
            "device_type": device.device_type,
            "host": device.host,
            "username": device.username,
            "password": device.get_password(),
            "port": device.port,
            "timeout": device.timeout,
        }
        with ConnectHandler(**params) as conn:
            raw_outputs = [cast(str, conn.send_command(cmd)) for cmd in SHOW_COMMANDS]

        logger.info("Successfully collected data from %s", device.name)
        return DeviceSnapshot(
            device_name=device.name,
            interfaces=ParsedInterfaces(interfaces=parse_interfaces(raw_outputs[0])),
            version=ParsedVersion(raw=raw_outputs[1]),
            config=ParsedConfig(raw=raw_outputs[2]),
        )
    except Exception as exc:
        logger.error("Failed to collect from %s: %s", device.name, exc)
        return DeviceSnapshot(
            device_name=device.name,
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
            collection_error=str(exc),
        )


def collect_all(devices: list[Device], max_workers: int = 4) -> list[DeviceSnapshot]:
    results: list[DeviceSnapshot] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(collect_device, d): d for d in devices}
        for future in as_completed(future_map):
            results.append(future.result())
    return results
