"""Parallel SSH collector for network device data."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler

from net_audit.models import (Device, DeviceSnapshot, ParsedInterfaces,
                               ParsedVersion, ParsedConfig)


SHOW_COMMANDS = [
    "show ip interface brief",
    "show version",
    "show running-config",
]


def collect_device(device: Device) -> DeviceSnapshot:
    try:
        params = {
            "device_type": device.device_type,
            "host": device.host,
            "username": device.username,
            "password": device.password,
            "port": device.port,
            "timeout": device.timeout,
        }
        with ConnectHandler(**params) as conn:
            outputs = [conn.send_command(cmd) for cmd in SHOW_COMMANDS]

        return DeviceSnapshot(
            device_name=device.name,
            interfaces=ParsedInterfaces(raw=outputs[0]),
            version=ParsedVersion(raw=outputs[1]),
            config=ParsedConfig(raw=outputs[2]),
        )
    except Exception as exc:
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
