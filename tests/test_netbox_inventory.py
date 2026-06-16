"""Unit tests for NetBox dynamic inventory source."""

from __future__ import annotations

import json
import os
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from audnet.exceptions import ConfigError
from audnet.inventory_sources.netbox import (
    _build_url,
    _normalize_device,
    fetch_netbox_devices,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_netbox_response(devices: list[dict]) -> bytes:
    """Build a paginated NetBox API response body."""
    return json.dumps({"count": len(devices), "results": devices}).encode("utf-8")


def _mock_urlopen(response_body: bytes, status: int = 200):
    """Return a context-manager mock that behaves like urlopen()."""
    from unittest.mock import MagicMock

    mock_resp = MagicMock()
    mock_resp.read.return_value = response_body
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)

    mock_cm = MagicMock()
    mock_cm.return_value = mock_resp
    return mock_cm


# ---------------------------------------------------------------------------
# _build_url
# ---------------------------------------------------------------------------


class TestBuildUrl:
    def test_adds_filters_to_path(self):
        url = _build_url("https://nb.example.com/api/dcim/devices/", {"status": "active"})
        assert "status=active" in url
        assert url.startswith("https://nb.example.com/api/dcim/devices/?")

    def test_merges_existing_query_params(self):
        url = _build_url(
            "https://nb.example.com/api/dcim/devices/?limit=10",
            {"status": "active"},
        )
        assert "status=active" in url
        assert "limit=10" in url

    def test_multiple_filters(self):
        url = _build_url(
            "https://nb.example.com/api/dcim/devices/",
            {"site": "dc1", "role": "router"},
        )
        assert "site=dc1" in url
        assert "role=router" in url


# ---------------------------------------------------------------------------
# _normalize_device
# ---------------------------------------------------------------------------


class TestNormalizeDevice:
    def test_basic_mapping(self):
        raw = {
            "name": "core-rtr-01",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "ios"},
        }
        kw = _normalize_device(raw)
        assert kw["name"] == "core-rtr-01"
        assert kw["host"] == "10.0.0.1"
        assert kw["device_type"] == "cisco_ios"
        assert kw["username"] == "admin"

    def test_junos_platform(self):
        raw = {
            "name": "juniper-fw",
            "primary_ip": {"address": "10.0.0.2/24"},
            "platform": {"slug": "junos"},
        }
        kw = _normalize_device(raw)
        assert kw["device_type"] == "juniper_junos"

    def test_panos_platform(self):
        raw = {
            "name": "pa-firewall",
            "primary_ip": {"address": "10.0.0.3/24"},
            "platform": {"slug": "panos"},
        }
        kw = _normalize_device(raw)
        assert kw["device_type"] == "paloalto_panos"

    def test_asa_platform(self):
        raw = {
            "name": "asa-firewall",
            "primary_ip": {"address": "10.0.0.4/24"},
            "platform": {"slug": "asa"},
        }
        kw = _normalize_device(raw)
        assert kw["device_type"] == "cisco_asa"

    def test_string_primary_ip(self):
        raw = {
            "name": "rtr01",
            "primary_ip": "10.0.0.5/24",
            "platform": "ios",
        }
        kw = _normalize_device(raw)
        assert kw["host"] == "10.0.0.5"

    def test_no_primary_ip(self):
        raw = {
            "name": "rtr02",
            "platform": {"slug": "ios"},
        }
        kw = _normalize_device(raw)
        assert kw["host"] == ""

    def test_unknown_platform_defaults_to_cisco_ios(self):
        raw = {
            "name": "custom-device",
            "primary_ip": {"address": "10.0.0.10/24"},
            "platform": {"slug": "custom_os"},
        }
        kw = _normalize_device(raw)
        assert kw["device_type"] == "cisco_ios"

    def test_config_context_credentials(self):
        raw = {
            "name": "rtr01",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "ios"},
            "config_context": {
                "audit_username": "netbox_svc",
                "audit_port": 2222,
                "audit_use_keys": True,
                "audit_key_file": "/keys/nb_svc",
            },
        }
        kw = _normalize_device(raw)
        assert kw["username"] == "netbox_svc"
        assert kw["port"] == 2222
        assert kw["use_keys"] is True
        assert kw["key_file"] == "/keys/nb_svc"

    def test_config_context_password(self):
        raw = {
            "name": "rtr01",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "ios"},
            "config_context": {
                "audit_password": "${AUDNET_DEVICE_PW}",
            },
        }
        kw = _normalize_device(raw)
        assert kw["password"] == "${AUDNET_DEVICE_PW}"


# ---------------------------------------------------------------------------
# fetch_netbox_devices
# ---------------------------------------------------------------------------


class TestFetchNetboxDevices:
    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_returns_devices(self, mock_urlopen):
        nb_device = {
            "name": "core-rtr-01",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "ios"},
        }
        mock_urlopen.side_effect = _mock_urlopen(_make_netbox_response([nb_device]))

        devices = fetch_netbox_devices("https://nb.example.com", token="test-token")
        assert len(devices) == 1
        assert devices[0].name == "core-rtr-01"
        assert devices[0].host == "10.0.0.1"
        assert devices[0].device_type == "cisco_ios"

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_multiple_devices(self, mock_urlopen):
        nb_devices = [
            {
                "name": f"rtr{i:02d}",
                "primary_ip": {"address": f"10.0.0.{i}/24"},
                "platform": {"slug": "ios"},
            }
            for i in range(1, 6)
        ]
        mock_urlopen.side_effect = _mock_urlopen(_make_netbox_response(nb_devices))

        devices = fetch_netbox_devices("https://nb.example.com", token="test-token")
        assert len(devices) == 5

    def test_missing_token_raises_config_error(self):
        with pytest.raises(ConfigError, match="NETBOX_TOKEN"):
            fetch_netbox_devices("https://nb.example.com", token=None)

    def test_empty_token_raises_config_error(self):
        with pytest.raises(ConfigError, match="NETBOX_TOKEN"):
            fetch_netbox_devices("https://nb.example.com", token="")

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_token_from_env(self, mock_urlopen):
        nb_device = {
            "name": "rtr01",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "ios"},
        }
        mock_urlopen.side_effect = _mock_urlopen(_make_netbox_response([nb_device]))

        os.environ["NETBOX_TOKEN"] = "env-token-123"
        try:
            devices = fetch_netbox_devices("https://nb.example.com")
            assert len(devices) == 1
        finally:
            del os.environ["NETBOX_TOKEN"]

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_api_error_raises_config_error(self, mock_urlopen):
        from io import BytesIO as _BIO

        error_body = json.dumps({"detail": "Invalid token."}).encode("utf-8")
        mock_error = HTTPError(
            url="https://nb.example.com/api/dcim/devices/",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=_BIO(error_body),
        )
        mock_urlopen.side_effect = mock_error

        with pytest.raises(ConfigError, match="403.*Invalid token"):
            fetch_netbox_devices("https://nb.example.com", token="bad-token")

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_connection_failure_raises_config_error(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Connection refused")

        with pytest.raises(ConfigError, match="connection failed"):
            fetch_netbox_devices("https://nb.example.com", token="test-token")

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_no_results_raises_config_error(self, mock_urlopen):
        mock_urlopen.side_effect = _mock_urlopen(_make_netbox_response([]))

        with pytest.raises(ConfigError, match="No active devices"):
            fetch_netbox_devices("https://nb.example.com", token="test-token")

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_filters_passed_as_query_params(self, mock_urlopen):
        nb_device = {
            "name": "dc1-rtr-01",
            "primary_ip": {"address": "10.0.1.1/24"},
            "platform": {"slug": "ios"},
        }
        mock_urlopen.side_effect = _mock_urlopen(_make_netbox_response([nb_device]))

        devices = fetch_netbox_devices(
            "https://nb.example.com",
            token="test-token",
            filters={"site": "dc1", "role": "router"},
        )
        assert len(devices) == 1
        # Verify the URL that was called contains our filters
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        url = req.full_url if hasattr(req, "full_url") else str(req)
        assert "site=dc1" in url
        assert "role=router" in url
        assert "status=active" in url

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_default_status_filter(self, mock_urlopen):
        nb_device = {
            "name": "rtr01",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "ios"},
        }
        mock_urlopen.side_effect = _mock_urlopen(_make_netbox_response([nb_device]))

        fetch_netbox_devices("https://nb.example.com", token="test-token")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        url = req.full_url if hasattr(req, "full_url") else str(req)
        assert "status=active" in url

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_invalid_device_skipped(self, mock_urlopen):
        nb_devices = [
            {
                "name": "good-device",
                "primary_ip": {"address": "10.0.0.1/24"},
                "platform": {"slug": "ios"},
            },
            {
                "name": "bad-device",
                # Missing host — Device validation will reject this
                "primary_ip": None,
                "platform": None,
            },
        ]
        mock_urlopen.side_effect = _mock_urlopen(_make_netbox_response(nb_devices))

        devices = fetch_netbox_devices("https://nb.example.com", token="test-token")
        assert len(devices) == 1
        assert devices[0].name == "good-device"

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_api_error_without_detail(self, mock_urlopen):
        error_body = b"plain text error"
        mock_error = HTTPError(
            url="https://nb.example.com/api/dcim/devices/",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=BytesIO(error_body),
        )
        mock_urlopen.side_effect = mock_error

        with pytest.raises(ConfigError, match="500"):
            fetch_netbox_devices("https://nb.example.com", token="test-token")

    def test_http_scheme_allowed(self):
        """http:// is accepted (for internal/test NetBox instances)."""
        with patch("audnet.inventory_sources.netbox.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = _mock_urlopen(
                _make_netbox_response([{
                    "name": "rtr01",
                    "primary_ip": {"address": "10.0.0.1/24"},
                    "platform": {"slug": "ios"},
                }])
            )
            devices = fetch_netbox_devices("http://nb.example.com", token="test-token")
            assert len(devices) == 1

    def test_file_scheme_rejected(self):
        """Non-http(s) schemes are rejected with ConfigError."""
        with pytest.raises(ConfigError, match="NetBox URL must use http or https"):
            fetch_netbox_devices("file:///etc/passwd", token="test-token")

    def test_ftp_scheme_rejected(self):
        """Non-http(s) schemes are rejected with ConfigError."""
        with pytest.raises(ConfigError, match="NetBox URL must use http or https"):
            fetch_netbox_devices("ftp://nb.example.com", token="test-token")


# ---------------------------------------------------------------------------
# load_inventory integration with netbox:// prefix
# ---------------------------------------------------------------------------


class TestLoadInventoryNetboxPrefix:
    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_netbox_prefix_returns_devices(self, mock_urlopen):
        from audnet.config import load_inventory

        nb_device = {
            "name": "nb-rtr-01",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "ios"},
        }
        mock_urlopen.side_effect = _mock_urlopen(_make_netbox_response([nb_device]))

        os.environ["NETBOX_TOKEN"] = "test-token"
        try:
            defaults, devices = load_inventory("netbox://nb.example.com")
            assert defaults == {}
            assert len(devices) == 1
            assert devices[0].name == "nb-rtr-01"
        finally:
            del os.environ["NETBOX_TOKEN"]

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_netbox_prefix_with_query_filters(self, mock_urlopen):
        from audnet.config import load_inventory

        nb_device = {
            "name": "dc1-rtr-01",
            "primary_ip": {"address": "10.0.1.1/24"},
            "platform": {"slug": "ios"},
        }
        mock_urlopen.side_effect = _mock_urlopen(_make_netbox_response([nb_device]))

        os.environ["NETBOX_TOKEN"] = "test-token"
        try:
            _, devices = load_inventory("netbox://nb.example.com?site=dc1&role=router")
            assert len(devices) == 1
            # Verify URL filters were passed
            call_args = mock_urlopen.call_args
            req = call_args[0][0]
            url = req.full_url if hasattr(req, "full_url") else str(req)
            assert "role=router" in url
            assert "site=dc1" in url
        finally:
            del os.environ["NETBOX_TOKEN"]

    def test_netbox_prefix_missing_token(self):
        from audnet.config import load_inventory

        # Ensure NETBOX_TOKEN is not set
        env_backup = os.environ.pop("NETBOX_TOKEN", None)
        try:
            with pytest.raises(ConfigError, match="NETBOX_TOKEN"):
                load_inventory("netbox://nb.example.com")
        finally:
            if env_backup is not None:
                os.environ["NETBOX_TOKEN"] = env_backup
