from unittest.mock import patch, MagicMock

from audnet.collector import collect_device, collect_all
from audnet.models import Device


def _make_device(name="rtr01", host="10.0.0.1"):
    return Device(name=name, host=host, username="admin", password="x")


class TestCollectDevice:
    @patch("audnet.collector.ConnectHandler")
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

    @patch("audnet.collector.ConnectHandler")
    def test_parser_wired_version_and_config(self, mock_cls):
        """Collector must parse version and config through TextFSM/parser."""
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
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

    @patch("audnet.collector.ConnectHandler")
    def test_connection_failure(self, mock_cls):
        from netmiko.exceptions import NetmikoTimeoutException

        mock_cls.side_effect = NetmikoTimeoutException("Connection timed out")

        snap = collect_device(_make_device())
        assert snap.collection_error is not None
        assert "Connection timed out" in snap.collection_error

    @patch("audnet.collector.ConnectHandler")
    def test_ssh_key_auth_passed_to_connect_handler(self, mock_cls):
        """When use_keys=True, ConnectHandler receives use_keys and key_file."""
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True
        mock_cls.return_value = mock_conn

        device = Device(
            name="rtr01",
            host="10.0.0.1",
            username="admin",
            use_keys=True,
            key_file="/home/user/.ssh/id_ed25519",
        )
        snap = collect_device(device)
        assert snap.collection_error is None
        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["use_keys"] is True
        assert call_kwargs["key_file"] == "/home/user/.ssh/id_ed25519"

    @patch("audnet.collector.ConnectHandler")
    def test_ssh_key_auth_no_key_file(self, mock_cls):
        """When use_keys=True but no key_file, only use_keys is passed."""
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True
        mock_cls.return_value = mock_conn

        device = Device(
            name="rtr01",
            host="10.0.0.1",
            username="admin",
            use_keys=True,
        )
        snap = collect_device(device)
        assert snap.collection_error is None
        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["use_keys"] is True
        assert "key_file" not in call_kwargs

    @patch("audnet.collector.ConnectHandler")
    def test_password_auth_no_key_params(self, mock_cls):
        """When use_keys=False (default), no key params are passed."""
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True
        mock_cls.return_value = mock_conn

        snap = collect_device(_make_device())
        assert snap.collection_error is None
        call_kwargs = mock_cls.call_args.kwargs
        assert "use_keys" not in call_kwargs
        assert "key_file" not in call_kwargs


class TestCollectAll:
    @patch("audnet.collector.collect_device")
    def test_collects_all_devices(self, mock_collect):
        from audnet.models import DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig

        mock_collect.return_value = DeviceSnapshot(
            device_name="rtr01",
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
        )
        devices = [_make_device("rtr01"), _make_device("rtr02", "10.0.0.2")]
        results = collect_all(devices, max_workers=2)
        assert len(results) == 2


class TestRetry:
    """Tests for tenacity retry logic on transient SSH errors."""

    @patch("audnet.collector.ConnectHandler")
    def test_retries_on_timeout_then_succeeds(self, mock_cls) -> None:
        """Transient timeout on first two attempts, success on third."""
        from netmiko.exceptions import NetmikoTimeoutException

        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True

        call_count = 0
        original_side_effect = [
            NetmikoTimeoutException("timeout 1"),
            NetmikoTimeoutException("timeout 2"),
        ]

        def side_effect(*args, **kwargs):
            nonlocal call_count
            if call_count < 2:
                call_count += 1
                raise original_side_effect[call_count - 1]
            return mock_conn

        mock_cls.side_effect = side_effect

        snap = collect_device(_make_device())
        assert snap.collection_error is None
        assert call_count == 2

    @patch("audnet.collector.ConnectHandler")
    def test_retries_exhausted_returns_error(self, mock_cls) -> None:
        """All 3 attempts fail with transient error → collection_error set."""
        from netmiko.exceptions import NetmikoTimeoutException

        mock_cls.side_effect = NetmikoTimeoutException("connection timed out")

        snap = collect_device(_make_device())
        assert snap.collection_error is not None
        assert "connection timed out" in snap.collection_error

    @patch("audnet.collector.ConnectHandler")
    def test_no_retry_on_auth_failure(self, mock_cls) -> None:
        """Authentication failure is not retried (not in retry_if_exception_type)."""
        from netmiko.exceptions import NetmikoAuthenticationException

        mock_cls.side_effect = NetmikoAuthenticationException("auth failed")

        snap = collect_device(_make_device())
        assert snap.collection_error is not None
        assert "auth failed" in snap.collection_error
        # Should have been called exactly once (no retries)
        assert mock_cls.call_count == 1

    @patch("audnet.collector.ConnectHandler")
    def test_retries_on_os_error(self, mock_cls) -> None:
        """OSError is retried as it's in the retry exception types."""
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("Network unreachable")
            return mock_conn

        mock_cls.side_effect = side_effect

        snap = collect_device(_make_device())
        assert snap.collection_error is None
        assert call_count == 2


class TestVendorCommands:
    """Tests for multi-vendor command dispatch via vendor registry."""

    @patch("audnet.collector.get_commands")
    @patch("audnet.collector.ConnectHandler")
    def test_known_device_type_uses_vendor_commands(self, mock_cls, mock_get_cmds):
        """Known device_type (cisco_ios) uses vendor registry commands."""
        mock_get_cmds.return_value = [
            "show ip interface brief",
            "show version",
            "show running-config",
        ]
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True
        mock_cls.return_value = mock_conn

        snap = collect_device(_make_device())
        assert snap.collection_error is None
        cmds = [c.args[0] for c in mock_conn.send_command.call_args_list]
        assert "show ip interface brief" in cmds
        assert "show version" in cmds
        assert "show running-config" in cmds
        mock_get_cmds.assert_called_once_with("cisco_ios")

    @patch("audnet.collector.get_commands")
    @patch("audnet.collector.ConnectHandler")
    def test_arista_eos_uses_vendor_commands(self, mock_cls, mock_get_cmds):
        """arista_eos device_type uses arista_eos commands from registry."""
        mock_get_cmds.return_value = [
            "show ip interface brief",
            "show version",
            "show running-config",
        ]
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Arista EOS, Version 4.28\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True
        mock_cls.return_value = mock_conn

        device = Device(
            name="rtr01",
            host="10.0.0.1",
            username="admin",
            password="x",
            device_type="arista_eos",
        )
        snap = collect_device(device)
        assert snap.collection_error is not None
        assert "TextFSM template not found" in snap.collection_error
        mock_get_cmds.assert_called_once_with("arista_eos")

    @patch("audnet.collector.get_commands")
    @patch("audnet.collector.ConnectHandler")
    def test_unknown_device_type_falls_back_to_cisco_ios(self, mock_cls, mock_get_cmds):
        """Unknown device_type falls back to cisco_ios commands via registry."""
        mock_get_cmds.return_value = [
            "show ip interface brief",
            "show version",
            "show running-config",
        ]
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True
        mock_cls.return_value = mock_conn

        device = Device(
            name="rtr01",
            host="10.0.0.1",
            username="admin",
            password="x",
            device_type="juniper_junos",
        )
        snap = collect_device(device)
        assert snap.collection_error is None
        mock_get_cmds.assert_called_once_with("juniper_junos")


class TestRetryBroadened:
    """Tests for broadened retry coverage on transient Netmiko exceptions."""

    @patch("audnet.collector.ConnectHandler")
    def test_retries_on_connection_exception(self, mock_cls) -> None:
        """ConnectionException is retried as it's in _RETRYABLE_EXCEPTIONS."""
        from netmiko.exceptions import ConnectionException

        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionException("Connection reset")
            return mock_conn

        mock_cls.side_effect = side_effect

        snap = collect_device(_make_device())
        assert snap.collection_error is None
        assert call_count == 2

    @patch("audnet.collector.ConnectHandler")
    def test_retries_on_read_exception(self, mock_cls) -> None:
        """ReadException is retried as it's in _RETRYABLE_EXCEPTIONS."""
        from netmiko.exceptions import ReadException

        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ReadException("Read timeout")
            return mock_conn

        mock_cls.side_effect = side_effect

        snap = collect_device(_make_device())
        assert snap.collection_error is None
        assert call_count == 2

    @patch("audnet.collector.ConnectHandler")
    def test_retries_on_ssh_exception(self, mock_cls) -> None:
        """SSHException is retried as it's in _RETRYABLE_EXCEPTIONS."""
        from paramiko.ssh_exception import SSHException

        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise SSHException("SSH negotiation failed")
            return mock_conn

        mock_cls.side_effect = side_effect

        snap = collect_device(_make_device())
        assert snap.collection_error is None
        assert call_count == 2

    @patch("audnet.collector.ConnectHandler")
    def test_retries_on_parsing_exception(self, mock_cls) -> None:
        """NetmikoParsingException is retried as it's in _RETRYABLE_EXCEPTIONS."""
        from netmiko.exceptions import NetmikoParsingException

        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = [
            "Interface  IP-Address  Status  Protocol\nGi0/0  10.0.0.1  up  up",
            "Cisco IOS Software, Version 15.2\nuptime is 5 days",
            "hostname rtr01\n",
        ]
        mock_conn.is_alive.return_value = True

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise NetmikoParsingException("Parse error")
            return mock_conn

        mock_cls.side_effect = side_effect

        snap = collect_device(_make_device())
        assert snap.collection_error is None
        assert call_count == 2

    @patch("audnet.collector.ConnectHandler")
    def test_no_retry_on_config_invalid_exception(self, mock_cls) -> None:
        """ConfigInvalidException is NOT retried (not in _RETRYABLE_EXCEPTIONS)."""
        from netmiko.exceptions import ConfigInvalidException

        mock_cls.side_effect = ConfigInvalidException("Invalid config")

        snap = collect_device(_make_device())
        assert snap.collection_error is not None
        assert "Invalid config" in snap.collection_error
        # Should have been called exactly once (no retries)
        assert mock_cls.call_count == 1


class TestCollectAllTimeout:
    """Tests for collect_all per-device timeout."""

    @patch("audnet.collector.collect_device")
    def test_collect_all_with_timeout(self, mock_collect):
        """collect_all passes timeout to future.result()."""
        from audnet.models import DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig

        mock_collect.return_value = DeviceSnapshot(
            device_name="rtr01",
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
        )
        devices = [_make_device("rtr01")]
        results = collect_all(devices, max_workers=1, timeout=30.0)
        assert len(results) == 1
        assert results[0].collection_error is None

    @patch("audnet.collector.collect_device")
    def test_collect_all_timeout_returns_error_snapshot(self, mock_collect):
        """When a device times out, an error snapshot is returned."""
        import time

        from audnet.models import DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig

        # Use a real function that sleeps, executed via the thread pool
        _sleeping = True

        def slow_collect(device):
            time.sleep(10)
            return DeviceSnapshot(
                device_name=device.name,
                interfaces=ParsedInterfaces(),
                version=ParsedVersion(),
                config=ParsedConfig(),
            )

        mock_collect.side_effect = slow_collect
        devices = [_make_device("rtr01")]
        results = collect_all(devices, max_workers=1, timeout=0.5)

        assert len(results) == 1
        assert results[0].collection_error is not None
        assert "timed out" in results[0].collection_error
        assert "0.5s" in results[0].collection_error

    @patch("audnet.collector.collect_device")
    def test_collect_all_timeout_mixed_results(self, mock_collect):
        """Timeout on one device, success on another."""
        import time

        from audnet.models import DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig

        def mixed_collect(device):
            if device.name == "slow":
                time.sleep(10)
            return DeviceSnapshot(
                device_name=device.name,
                interfaces=ParsedInterfaces(),
                version=ParsedVersion(),
                config=ParsedConfig(),
            )

        mock_collect.side_effect = mixed_collect
        devices = [_make_device("fast", "10.0.0.1"), _make_device("slow", "10.0.0.2")]
        results = collect_all(devices, max_workers=2, timeout=0.5)

        assert len(results) == 2
        by_name = {r.device_name: r for r in results}
        assert by_name["fast"].collection_error is None
        assert by_name["slow"].collection_error is not None
        assert "timed out" in by_name["slow"].collection_error

    def test_collect_all_no_timeout_by_default(self):
        """collect_all without timeout works as before (no timeout parameter)."""
        from unittest.mock import patch

        with patch("audnet.collector.collect_device") as mock_collect:
            from audnet.models import (
                DeviceSnapshot,
                ParsedInterfaces,
                ParsedVersion,
                ParsedConfig,
            )

            mock_collect.return_value = DeviceSnapshot(
                device_name="rtr01",
                interfaces=ParsedInterfaces(),
                version=ParsedVersion(),
                config=ParsedConfig(),
            )
            devices = [_make_device("rtr01"), _make_device("rtr02", "10.0.0.2")]
            results = collect_all(devices, max_workers=2)
            assert len(results) == 2


class TestCollectorEdgeCases:
    """Edge-case tests for collector retry and error handling."""

    @patch("audnet.collector.ConnectHandler")
    def test_retry_exhausted_connection_exception(self, mock_cls):
        """ConnectionException is retried 3 times then returns error snapshot."""
        from netmiko.exceptions import ConnectionException

        mock_cls.side_effect = ConnectionException("Connection refused")
        dev = _make_device("rtr01")
        result = collect_device(dev)
        assert result.collection_error is not None
        assert "Connection refused" in result.collection_error
        assert mock_cls.call_count == 3

    @patch("audnet.collector.ConnectHandler")
    def test_retry_exhausted_read_exception(self, mock_cls):
        """ReadException is retried 3 times then returns error snapshot."""
        from netmiko.exceptions import ReadException

        mock_cls.side_effect = ReadException("Read timeout")
        dev = _make_device("rtr01")
        result = collect_device(dev)
        assert result.collection_error is not None
        assert "Read timeout" in result.collection_error
        assert mock_cls.call_count == 3

    @patch("audnet.collector.ConnectHandler")
    def test_retry_exhausted_parsing_exception(self, mock_cls):
        """NetmikoParsingException is retried 3 times then returns error snapshot."""
        from netmiko.exceptions import NetmikoParsingException

        mock_cls.side_effect = NetmikoParsingException("Parse error")
        dev = _make_device("rtr01")
        result = collect_device(dev)
        assert result.collection_error is not None
        assert "Parse error" in result.collection_error
        assert mock_cls.call_count == 3

    @patch("audnet.collector.ConnectHandler")
    def test_no_retry_on_auth_failure(self, mock_cls):
        """AuthenticationException is NOT retried (not transient)."""
        from netmiko.exceptions import NetmikoAuthenticationException

        mock_cls.side_effect = NetmikoAuthenticationException("Auth failed")
        dev = _make_device("rtr01")
        result = collect_device(dev)
        assert result.collection_error is not None
        assert "Auth failed" in result.collection_error
        # Should only be called once — no retries
        assert mock_cls.call_count == 1

    @patch("audnet.collector.ConnectHandler")
    def test_no_retry_on_config_invalid(self, mock_cls):
        """ConfigInvalidException is NOT retried."""
        from netmiko.exceptions import ConfigInvalidException

        mock_cls.side_effect = ConfigInvalidException("Invalid config")
        dev = _make_device("rtr01")
        result = collect_device(dev)
        assert result.collection_error is not None
        assert "Invalid config" in result.collection_error
        assert mock_cls.call_count == 1

    @patch("audnet.collector.ConnectHandler")
    def test_retry_then_success(self, mock_cls):
        """Transient error on first attempt, success on retry."""
        from netmiko.exceptions import ReadException

        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.send_command.side_effect = [
            "show interfaces",
            "show version",
            "show running-config",
        ]
        mock_cls.side_effect = [ReadException("timeout"), mock_conn]
        dev = _make_device("rtr01")
        result = collect_device(dev)
        assert result.collection_error is None
        assert result.device_name == "rtr01"
        assert mock_cls.call_count == 2

    @patch("audnet.collector.ConnectHandler")
    def test_value_error_returns_error_snapshot(self, mock_cls):
        """ValueError during collection returns error snapshot."""
        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.send_command.side_effect = ValueError("unexpected format")
        mock_cls.return_value = mock_conn
        dev = _make_device("rtr01")
        result = collect_device(dev)
        assert result.collection_error is not None
        assert "unexpected format" in result.collection_error

    def test_collect_all_empty_device_list(self):
        """collect_all with empty device list returns empty results."""
        results = collect_all([], max_workers=2)
        assert results == []

    @patch("audnet.collector.collect_device")
    def test_collect_all_mixed_success_and_error(self, mock_collect):
        """collect_all returns both successful and error snapshots."""
        from audnet.models import DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig

        mock_collect.side_effect = [
            DeviceSnapshot(
                device_name="rtr01",
                interfaces=ParsedInterfaces(interfaces=[]),
                version=ParsedVersion(),
                config=ParsedConfig(lines=["ip ssh version 2"]),
            ),
            DeviceSnapshot(
                device_name="rtr02",
                interfaces=ParsedInterfaces(),
                version=ParsedVersion(),
                config=ParsedConfig(),
                collection_error="Connection timed out",
            ),
        ]
        devices = [_make_device("rtr01", "10.0.0.1"), _make_device("rtr02", "10.0.0.2")]
        results = collect_all(devices, max_workers=2)
        assert len(results) == 2
        by_name = {r.device_name: r for r in results}
        assert by_name["rtr01"].collection_error is None
        assert by_name["rtr02"].collection_error is not None
