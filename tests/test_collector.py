from unittest.mock import patch, MagicMock

from net_audit.collector import collect_device, collect_all
from net_audit.models import Device


def _make_device(name="rtr01", host="10.0.0.1"):
    return Device(name=name, host=host, username="admin", password="x")


class TestCollectDevice:
    @patch("net_audit.collector.ConnectHandler")
    def test_successful_collection(self, mock_cls):
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\nip ssh version 2",
        ]
        mock_conn.is_alive.return_value = True
        mock_cls.return_value = mock_conn

        snap = collect_device(_make_device())
        assert snap.device_name == "rtr01"
        assert snap.collection_error is None

    @patch("net_audit.collector.ConnectHandler")
    def test_connection_failure(self, mock_cls):
        mock_cls.side_effect = Exception("Connection timed out")

        snap = collect_device(_make_device())
        assert snap.collection_error is not None
        assert "Connection timed out" in snap.collection_error


class TestCollectAll:
    @patch("net_audit.collector.collect_device")
    def test_collects_all_devices(self, mock_collect):
        from net_audit.models import (DeviceSnapshot, ParsedInterfaces,
                                      ParsedVersion, ParsedConfig)
        mock_collect.return_value = DeviceSnapshot(
            device_name="rtr01",
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
        )
        devices = [_make_device("rtr01"), _make_device("rtr02", "10.0.0.2")]
        results = collect_all(devices, max_workers=2)
        assert len(results) == 2
