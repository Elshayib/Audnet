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
    def test_parser_wired_version_and_config(self, mock_cls):
        """Collector must parse version and config through TextFSM/parser."""
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            ("Interface              IP-Address      OK? Method Status                Protocol\n"
             "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"),
            ("Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
             "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
             "router uptime is 5 days, 3 hours, 22 minutes"),
            "hostname rtr01\nip ssh version 2\nntp server 10.0.0.50\n",
        ]
        mock_conn.is_alive.return_value = True
        mock_cls.return_value = mock_conn

        snap = collect_device(_make_device())
        assert snap.collection_error is None
        # Version must be parsed (not just raw)
        assert snap.version.raw != ""
        assert "15.2" in snap.version.version
        assert "5 days" in snap.version.uptime
        # Config lines must be parsed (not just raw)
        assert len(snap.config.lines) == 3
        assert "hostname rtr01" in snap.config.lines
        assert "ip ssh version 2" in snap.config.lines
        assert snap.config.raw != ""
        # Interfaces must be parsed
        assert len(snap.interfaces.interfaces) == 1
        assert snap.interfaces.interfaces[0]["interface"] == "GigabitEthernet0/0"

    @patch("net_audit.collector.ConnectHandler")
    def test_connection_failure(self, mock_cls):
        from netmiko.exceptions import NetmikoTimeoutException
        mock_cls.side_effect = NetmikoTimeoutException("Connection timed out")

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
