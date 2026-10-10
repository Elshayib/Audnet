"""Thin per-adapter smoke for the Netmiko transport (issue #207).

The shared failure contract (transient-retried, auth-never-retried,
timeout results, ordering) lives in the contract suite
(:mod:`tests.test_collection_contract`). This module only proves the real
Netmiko transport satisfies the raw-transport seam through the shared
interface — no retry matrices, no fan-out tests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from audnet.collector import collect_device
from audnet.models import Device
from audnet.netmiko_adapter import NetmikoAdapter


def _make_device(name="rtr01", host="10.0.0.1", **kwargs):
    return Device(name=name, host=host, username="admin", password="x", **kwargs)


def _mock_conn(*outputs: str) -> MagicMock:
    mock_conn = MagicMock()
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.__exit__.return_value = False
    mock_conn.send_command.side_effect = list(outputs)
    mock_conn.is_alive.return_value = True
    return mock_conn


class TestNetmikoAdapterSmoke:
    """Thin smoke: the real Netmiko transport satisfies the seam."""

    @patch("audnet.netmiko_adapter.ConnectHandler")
    def test_success_builds_snapshot_through_shared_interface(self, mock_cls):
        mock_cls.return_value = _mock_conn(
            (
                "Interface              IP-Address      OK? Method Status                Protocol\n"
                "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"
            ),
            (
                "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
                "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
                "router uptime is 5 days, 3 hours, 22 minutes"
            ),
            "hostname rtr01\nip ssh version 2\nntp server 10.0.0.50\n",
        )

        snap = collect_device(_make_device(), adapter=NetmikoAdapter())

        assert snap.device_name == "rtr01"
        assert snap.collection_error is None
        assert "15.2" in snap.version.version
        assert "hostname rtr01" in snap.config.lines

    @patch("audnet.netmiko_adapter.ConnectHandler")
    def test_key_auth_reaches_transport(self, mock_cls):
        mock_cls.return_value = _mock_conn("ifaces", "version 15.2", "hostname r1\n")

        device = Device(
            name="rtr01",
            host="10.0.0.1",
            username="admin",
            use_keys=True,
            key_file="/home/user/.ssh/id_ed25519",
        )
        snap = collect_device(device, adapter=NetmikoAdapter())

        assert snap.collection_error is None
        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["use_keys"] is True
        assert call_kwargs["key_file"] == "/home/user/.ssh/id_ed25519"

    @patch("audnet.netmiko_adapter.ConnectHandler")
    def test_enable_called_when_secret_set(self, mock_cls, monkeypatch):
        mock_conn = MagicMock()
        mock_conn.send_command.side_effect = ["ifaces", "version", "config"]
        mock_cls.return_value = mock_conn

        device = Device(
            name="r1",
            host="10.0.0.1",
            username="admin",
            password="pw",
            secret="enable-pw",
        )
        monkeypatch.setenv("AUDNET_SSH_STRICT_KEY", "0")
        conn = NetmikoAdapter().connect(device)

        assert conn is mock_conn
        mock_conn.enable.assert_called_once()
        kwargs = mock_cls.call_args.kwargs
        assert kwargs.get("secret") == "enable-pw"
        assert kwargs.get("system_host_keys") is True
