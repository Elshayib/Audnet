"""Tests for the Scrapli-based async collector (scrapli_collector).

Tests mock the driver class to avoid real SSH connections.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from audnet.models import Device


def _make_device(name: str = "test-device", host: str = "10.0.0.1") -> Device:
    return Device(
        name=name,
        host=host,
        username="admin",
        password=SecretStr("test-pass"),
        device_type="cisco_ios",
    )


def _mock_raw_outputs() -> list[str]:
    return [
        "Interface  IP-Address  Status  Protocol\nGi0/0      10.0.0.1    up      up",
        "Cisco IOS Software, Version 15.2",
        "hostname test-device\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0",
    ]


def _make_mock_driver_and_conn(outputs: list[str] | None = None):
    """Create a mock Scrapli driver class and connection.

    The driver class, when instantiated and used as an async context manager,
    yields a mock connection whose send_command returns the given outputs.
    """
    if outputs is None:
        outputs = _mock_raw_outputs()

    call_count = 0

    async def _send_command_side_effect(*args, **kwargs):
        nonlocal call_count
        response = MagicMock()
        response.result = outputs[min(call_count, len(outputs) - 1)]
        call_count += 1
        return response

    mock_conn = AsyncMock()
    mock_conn.send_command = AsyncMock(side_effect=_send_command_side_effect)

    # Create a class that works as `async with MockDriver(...) as conn:`
    mock_instance = AsyncMock()
    mock_instance.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_instance.__aexit__ = AsyncMock(return_value=False)

    mock_driver_cls = MagicMock(return_value=mock_instance)

    return mock_driver_cls, mock_conn


class TestScrapliCollectorImport:
    def test_import_succeeds_with_scrapli_installed(self):
        from audnet.scrapli_collector import collect_all_scrapli, collect_device_scrapli  # noqa: F401


class TestGetScrapliPlatformMapping:
    def test_all_vendors_have_driver_mapping(self):
        from audnet.scrapli_collector import _SCRAPLI_DRIVER_MAP
        from audnet.vendor_registry import list_vendors

        for vt in list_vendors():
            assert vt in _SCRAPLI_DRIVER_MAP, f"{vt} missing from _SCRAPLI_DRIVER_MAP"

    def test_core_drivers_for_major_vendors(self):
        from scrapli.driver.core import (
            AsyncEOSDriver,
            AsyncIOSXEDriver,
            AsyncJunosDriver,
            AsyncNXOSDriver,
        )

        from audnet.scrapli_collector import _SCRAPLI_DRIVER_MAP

        assert _SCRAPLI_DRIVER_MAP["cisco_ios"] is AsyncIOSXEDriver
        assert _SCRAPLI_DRIVER_MAP["cisco_nxos"] is AsyncNXOSDriver
        assert _SCRAPLI_DRIVER_MAP["arista_eos"] is AsyncEOSDriver
        assert _SCRAPLI_DRIVER_MAP["juniper_junos"] is AsyncJunosDriver

    def test_generic_driver_for_others(self):
        from scrapli.driver.network.async_driver import AsyncNetworkDriver

        from audnet.scrapli_collector import _SCRAPLI_DRIVER_MAP

        for vt in ("fortinet_fortios", "paloalto_panos", "aruba_os", "hp_procurve"):
            assert _SCRAPLI_DRIVER_MAP[vt] is AsyncNetworkDriver


class TestCollectDeviceScrapli:
    @pytest.mark.asyncio
    async def test_successful_collection(self):
        from audnet.scrapli_collector import collect_device_scrapli

        device = _make_device()
        mock_driver_cls, _ = _make_mock_driver_and_conn()

        with patch("audnet.scrapli_collector._get_scrapli_driver", return_value=mock_driver_cls):
            snapshot = await collect_device_scrapli(device)

        assert snapshot.device_name == "test-device"
        assert snapshot.collection_error is None

    @pytest.mark.asyncio
    async def test_auth_failure(self):
        from scrapli.exceptions import ScrapliAuthenticationFailed

        from audnet.scrapli_collector import collect_device_scrapli

        device = _make_device()

        async def _fail(*a, **kw):
            raise ScrapliAuthenticationFailed("auth denied")

        mock_instance = AsyncMock()
        mock_instance.__aenter__ = _fail
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_driver_cls = MagicMock(return_value=mock_instance)

        with patch("audnet.scrapli_collector._get_scrapli_driver", return_value=mock_driver_cls):
            snapshot = await collect_device_scrapli(device)

        assert snapshot.device_name == "test-device"
        assert snapshot.collection_error is not None

    @pytest.mark.asyncio
    async def test_connection_error(self):
        from scrapli.exceptions import ScrapliConnectionError

        from audnet.scrapli_collector import collect_device_scrapli

        device = _make_device()

        async def _fail(*a, **kw):
            raise ScrapliConnectionError("conn refused")

        mock_instance = AsyncMock()
        mock_instance.__aenter__ = _fail
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_driver_cls = MagicMock(return_value=mock_instance)

        with patch("audnet.scrapli_collector._get_scrapli_driver", return_value=mock_driver_cls):
            snapshot = await collect_device_scrapli(device)

        assert snapshot.device_name == "test-device"
        assert snapshot.collection_error is not None

    @pytest.mark.asyncio
    async def test_send_command_failure(self):
        """Failure during send_command returns error snapshot."""
        from scrapli.exceptions import ScrapliConnectionError

        from audnet.scrapli_collector import collect_device_scrapli

        device = _make_device()

        async def _fail_send(*a, **kw):
            raise ScrapliConnectionError("lost connection")

        mock_conn = AsyncMock()
        mock_conn.send_command = AsyncMock(side_effect=_fail_send)

        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_driver_cls = MagicMock(return_value=mock_instance)

        with patch("audnet.scrapli_collector._get_scrapli_driver", return_value=mock_driver_cls):
            snapshot = await collect_device_scrapli(device)

        assert snapshot.device_name == "test-device"
        assert snapshot.collection_error is not None

    @pytest.mark.asyncio
    async def test_custom_port(self):
        """Device with custom port passes it to driver."""
        from audnet.scrapli_collector import collect_device_scrapli

        device = _make_device()
        device = device.model_copy(update={"port": 2222})
        mock_driver_cls, _ = _make_mock_driver_and_conn()

        with patch("audnet.scrapli_collector._get_scrapli_driver", return_value=mock_driver_cls):
            snapshot = await collect_device_scrapli(device)

        assert snapshot.collection_error is None
        # Verify port was passed to driver constructor
        mock_driver_cls.assert_called_once()
        call_kwargs = mock_driver_cls.call_args.kwargs
        assert call_kwargs["port"] == 2222


class TestCollectAllScrapli:
    @pytest.mark.asyncio
    async def test_multiple_devices(self):
        from audnet.scrapli_collector import collect_all_scrapli

        devices = [_make_device(f"dev-{i}", f"10.0.0.{i}") for i in range(4)]
        mock_driver_cls, _ = _make_mock_driver_and_conn()

        with patch("audnet.scrapli_collector._get_scrapli_driver", return_value=mock_driver_cls):
            results = await collect_all_scrapli(devices, max_workers=4)

        assert len(results) == 4
        for r in results:
            assert r.device_name.startswith("dev-")

    @pytest.mark.asyncio
    async def test_empty_list(self):
        from audnet.scrapli_collector import collect_all_scrapli

        results = await collect_all_scrapli([], max_workers=4)
        assert results == []

    @pytest.mark.asyncio
    async def test_timeout(self):
        from audnet.scrapli_collector import collect_all_scrapli

        device = _make_device()

        async def _slow(*a, **kw):
            import asyncio
            await asyncio.sleep(10)
            response = MagicMock()
            response.result = "output"
            return response

        mock_conn = AsyncMock()
        mock_conn.send_command = AsyncMock(side_effect=_slow)

        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_driver_cls = MagicMock(return_value=mock_instance)

        with patch("audnet.scrapli_collector._get_scrapli_driver", return_value=mock_driver_cls):
            results = await collect_all_scrapli([device], max_workers=1, timeout=0.1)

        assert len(results) == 1
        assert results[0].collection_error is not None

    @pytest.mark.asyncio
    async def test_mixed_results(self):
        from scrapli.exceptions import ScrapliConnectionError

        from audnet.scrapli_collector import collect_all_scrapli

        devices = [
            _make_device("good-dev", "10.0.0.1"),
            _make_device("bad-dev", "10.0.0.2"),
        ]

        call_count = 0
        outputs = _mock_raw_outputs()

        async def _send_side_effect(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                response = MagicMock()
                response.result = outputs[call_count - 1]
                return response
            raise ScrapliConnectionError("refused")

        mock_conn = AsyncMock()
        mock_conn.send_command = AsyncMock(side_effect=_send_side_effect)

        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_driver_cls = MagicMock(return_value=mock_instance)

        with patch("audnet.scrapli_collector._get_scrapli_driver", return_value=mock_driver_cls):
            results = await collect_all_scrapli(devices, max_workers=2)

        assert len(results) == 2
        errors = [r for r in results if r.collection_error]
        assert len(errors) >= 1
