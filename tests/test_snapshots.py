"""Tests for shared snapshot assembly (audnet.snapshots).

Prefactor for #203: the three collection modules (sync, async, scrapli)
must share one snapshot-assembly path with no behavior change.
"""

from audnet.models import Device
from audnet.snapshots import build_snapshot, error_snapshot, timeout_snapshot
from audnet.vendor_registry import Slot


def _make_device(name="rtr01", host="10.0.0.1"):
    return Device(name=name, host=host, username="admin", password="x")


def _raw_outputs():
    return {
        Slot.INTERFACES: (
            "Interface              IP-Address      OK? Method Status                Protocol\n"
            "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"
        ),
        Slot.VERSION: (
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
            "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
            "router uptime is 5 days, 3 hours, 22 minutes"
        ),
        Slot.RUNNING_CONFIG: "hostname rtr01\nip ssh version 2\nntp server 10.0.0.50\n",
    }


class TestBuildSnapshot:
    def test_assembles_parsed_snapshot(self):
        snap = build_snapshot(_make_device(), _raw_outputs())
        assert snap.device_name == "rtr01"
        assert snap.device_type == "cisco_ios"
        assert snap.collection_error is None
        assert snap.version.raw != ""
        assert "15.2" in snap.version.version
        assert "5 days" in snap.version.uptime
        assert len(snap.config.lines) == 3
        assert "hostname rtr01" in snap.config.lines
        assert snap.config.raw != ""
        assert len(snap.interfaces.interfaces) == 1
        assert snap.interfaces.interfaces[0]["interface"] == "GigabitEthernet0/0"

    def test_matches_collector_success_shape(self):
        """Shared path must produce the same fields as the inline collector code."""
        from audnet.models import ParsedConfig, ParsedInterfaces, ParsedVersion
        from audnet.parser import parse_config, parse_interfaces, parse_version

        device = _make_device()
        raw = _raw_outputs()
        snap = build_snapshot(device, raw)
        parsed_version = parse_version(raw[Slot.VERSION], device_type=device.device_type)
        assert snap.version == ParsedVersion(**parsed_version, raw=raw[Slot.VERSION])
        assert snap.interfaces == ParsedInterfaces(
            interfaces=parse_interfaces(raw[Slot.INTERFACES], device_type=device.device_type)
        )
        assert snap.config == ParsedConfig(
            lines=parse_config(raw[Slot.RUNNING_CONFIG]),
            raw=raw[Slot.RUNNING_CONFIG],
        )


class TestErrorSnapshot:
    def test_from_exception(self):
        snap = error_snapshot(_make_device(), ValueError("unexpected format"))
        assert snap.device_name == "rtr01"
        assert snap.device_type == "cisco_ios"
        assert snap.collection_error is not None
        assert "unexpected format" in snap.collection_error
        assert snap.interfaces.interfaces == []
        assert snap.config.lines == []
        assert snap.config.raw == ""
        assert snap.version.raw == ""

    def test_from_string(self):
        snap = error_snapshot(_make_device(), "Unknown collection result")
        assert snap.collection_error == "Unknown collection result"


class TestTimeoutSnapshot:
    def test_message_format(self):
        snap = timeout_snapshot(_make_device(), 0.5)
        assert snap.device_name == "rtr01"
        assert snap.collection_error == "Collection timed out after 0.5s"
        assert snap.interfaces.interfaces == []
        assert snap.config.lines == []
