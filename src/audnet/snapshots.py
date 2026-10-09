"""Shared snapshot assembly for collectors.

Single path used by the sync (Netmiko), async (asyncssh), and Scrapli
collection modules to build per-Device result snapshots and failure
snapshots. Pure prefactor — no behavior change.
"""

from audnet.models import Device, DeviceSnapshot, ParsedConfig, ParsedInterfaces, ParsedVersion
from audnet.parser import parse_config, parse_interfaces, parse_version
from audnet.vendor_registry import Slot


def build_snapshot(device: Device, raw_outputs: dict[Slot, str]) -> DeviceSnapshot:
    """Assemble a successful per-Device result snapshot from raw CLI outputs."""
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


def error_snapshot(device: Device, error: str | BaseException) -> DeviceSnapshot:
    """Assemble a failure snapshot for an unexpected or expected collection error."""
    return DeviceSnapshot(
        device_name=device.name,
        device_type=device.device_type,
        interfaces=ParsedInterfaces(),
        version=ParsedVersion(),
        config=ParsedConfig(),
        collection_error=str(error),
    )


def timeout_snapshot(device: Device, timeout: float) -> DeviceSnapshot:
    """Assemble a timeout-failure snapshot for a per-device wall-clock budget."""
    return error_snapshot(device, f"Collection timed out after {timeout}s")
