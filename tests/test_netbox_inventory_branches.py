"""Additional branch-coverage tests for the NetBox inventory source.

Targets defensive branches not exercised by test_netbox_inventory.py:
- _same_origin mismatch paths (scheme / host)
- _normalize_device edge types (primary_ip weird type, audnet_ctx not a dict)
- pagination guards (_MAX_PAGES cap, off-origin next URL)
- non-JSON response body
- list-shaped response body
- "no valid devices could be built" error
"""

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from audnet.exceptions import ConfigError
from audnet.inventory_sources.netbox import (
    _normalize_device,
    _same_origin,
    fetch_netbox_devices,
)


def _resp(body: bytes) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    cm = MagicMock()
    cm.return_value = mock_resp
    return cm


def _page(devices: list[dict[str, Any]], next_url: str | None = None) -> bytes:
    return json.dumps({"count": len(devices), "results": devices, "next": next_url}).encode()


# ---------------------------------------------------------------------------
# _same_origin
# ---------------------------------------------------------------------------


class TestSameOrigin:
    def test_non_http_scheme_returns_false(self) -> None:
        assert _same_origin("https://nb.example.com", "ftp://nb.example.com") is False

    def test_scheme_mismatch_returns_false(self) -> None:
        assert _same_origin("https://nb.example.com", "http://nb.example.com") is False

    def test_host_mismatch_returns_false(self) -> None:
        assert _same_origin("https://nb.example.com", "https://other.example.com") is False

    def test_port_mismatch_returns_false(self) -> None:
        assert _same_origin("https://nb.example.com:8443", "https://nb.example.com") is False

    def test_same_origin_returns_true(self) -> None:
        assert _same_origin("https://nb.example.com", "https://nb.example.com/api/") is True


# ---------------------------------------------------------------------------
# _normalize_device edge types
# ---------------------------------------------------------------------------


class TestNormalizeDeviceEdges:
    def test_weird_primary_ip_type_yields_empty_host(self) -> None:
        raw = {
            "name": "rtr01",
            "primary_ip": 12345,  # neither dict nor str
            "platform": {"slug": "ios"},
        }
        kw = _normalize_device(raw)
        assert kw["host"] == ""

    def test_audnet_ctx_not_a_dict_falls_back(self) -> None:
        raw = {
            "name": "rtr01",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "ios"},
            "config_context": {"audnet": "not-a-dict"},
        }
        kw = _normalize_device(raw)
        # Without a real audnet dict, username falls back to default "admin".
        assert kw["username"] == "admin"


# ---------------------------------------------------------------------------
# fetch_netbox_devices defensive paths
# ---------------------------------------------------------------------------


class TestFetchNetboxBranches:
    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_non_json_response_raises(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _resp(b"<!DOCTYPE html><html>oops</html>")
        with pytest.raises(ConfigError, match="non-JSON"):
            fetch_netbox_devices("https://nb.example.com", token="t")

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_list_shaped_body_extends(self, mock_urlopen: MagicMock) -> None:
        # NetBox can return a bare list instead of an envelope.
        body = json.dumps(
            [
                {
                    "name": "rtr01",
                    "primary_ip": {"address": "10.0.0.1/24"},
                    "platform": {"slug": "ios"},
                }
            ]
        ).encode()
        mock_urlopen.side_effect = _resp(body)
        devices = fetch_netbox_devices("https://nb.example.com", token="t")
        assert len(devices) == 1
        assert devices[0].name == "rtr01"

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_no_valid_devices_raises(self, mock_urlopen: MagicMock) -> None:
        # All returned devices are invalid -> "No valid devices" error.
        bad = [
            {"name": "x", "primary_ip": None, "platform": None},
            {"name": "y", "primary_ip": None, "platform": None},
        ]
        mock_urlopen.side_effect = _resp(_page(bad))
        with pytest.raises(ConfigError, match="No valid devices"):
            fetch_netbox_devices("https://nb.example.com", token="t")

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_off_origin_next_url_rejected(self, mock_urlopen: MagicMock) -> None:
        first = _page(
            [
                {
                    "name": "rtr01",
                    "primary_ip": {"address": "10.0.0.1/24"},
                    "platform": {"slug": "ios"},
                }
            ],
            next_url="https://evil.example.com/api/dcim/devices/?limit=50",
        )
        mock_urlopen.side_effect = _resp(first)
        with pytest.raises(ConfigError, match="off-origin"):
            fetch_netbox_devices("https://nb.example.com", token="t")

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_pagination_exceeds_max_pages(self, mock_urlopen: MagicMock) -> None:
        # Every page points back to the same on-origin URL -> loops until the
        # _MAX_PAGES cap is hit.
        body = _page(
            [
                {
                    "name": "rtr01",
                    "primary_ip": {"address": "10.0.0.1/24"},
                    "platform": {"slug": "ios"},
                }
            ],
            next_url="https://nb.example.com/api/dcim/devices/?limit=50&offset=50",
        )
        mock_urlopen.side_effect = _resp(body)
        with pytest.raises(ConfigError, match="pagination exceeded"):
            fetch_netbox_devices("https://nb.example.com", token="t")

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_allow_http_env_flag_suppresses_warning_path(self, mock_urlopen: MagicMock) -> None:
        # http:// URL with AUDNET_NETBOX_ALLOW_HTTP set should fetch without
        # raising (exercises the env-flag branch instead of the warning branch).
        mock_urlopen.side_effect = _resp(
            _page(
                [
                    {
                        "name": "rtr01",
                        "primary_ip": {"address": "10.0.0.1/24"},
                        "platform": {"slug": "ios"},
                    }
                ]
            )
        )
        import os

        os.environ["AUDNET_NETBOX_ALLOW_HTTP"] = "1"
        try:
            devices = fetch_netbox_devices("http://nb.example.com", token="t")
            assert len(devices) == 1
        finally:
            del os.environ["AUDNET_NETBOX_ALLOW_HTTP"]
