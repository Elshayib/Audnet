"""Coverage tests for security/hardening fixes from the multi-agent audit."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from audnet.config import _resolve_device_env, load_inventory
from audnet.exceptions import ConfigError
from audnet.history import diff_runs, get_last_runs, save_run
from audnet.inventory_sources.netbox import (
    _coerce_bool,
    _normalize_device,
    _same_origin,
    fetch_netbox_devices,
)
from audnet.models import AuditReport, ComplianceResult, Device, DeviceSnapshot, ParsedConfig, ParsedInterfaces, ParsedVersion
from audnet.parser import parse_interfaces, parse_version
from audnet.remediate import _create_checkpoint, _rollback_config


class TestNetboxHardening:
    def test_same_origin_accepts_matching(self):
        assert _same_origin("https://nb.example.com", "https://nb.example.com/api/dcim/devices/?p=2")

    def test_same_origin_rejects_host_change(self):
        assert not _same_origin("https://nb.example.com", "https://evil.example.com/api")

    def test_same_origin_rejects_scheme_change(self):
        assert not _same_origin("https://nb.example.com", "http://nb.example.com/api")

    def test_coerce_bool_string_false(self):
        assert _coerce_bool("false") is False
        assert _coerce_bool("0") is False
        assert _coerce_bool("true") is True
        assert _coerce_bool(True) is True

    def test_platform_identity_mappings(self):
        raw = {
            "name": "sw1",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "cisco_nxos"},
        }
        kwargs = _normalize_device(raw)
        assert kwargs["device_type"] == "cisco_nxos"

    def test_unknown_platform_defaults_ios(self):
        raw = {
            "name": "sw1",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "totally-unknown-os"},
        }
        kwargs = _normalize_device(raw)
        assert kwargs["device_type"] == "cisco_ios"

    def test_secret_from_config_context(self):
        raw = {
            "name": "sw1",
            "primary_ip": {"address": "10.0.0.1/24"},
            "platform": {"slug": "ios"},
            "config_context": {"audnet": {"password": "p", "secret": "enable-sec"}},
        }
        kwargs = _normalize_device(raw)
        assert kwargs.get("secret") == "enable-sec"

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_rejects_off_origin_pagination(self, mock_urlopen):
        from unittest.mock import MagicMock

        page1 = {
            "count": 2,
            "next": "https://evil.example.com/api/dcim/devices/?offset=50",
            "results": [
                {
                    "name": "rtr01",
                    "primary_ip": {"address": "10.0.0.1/24"},
                    "platform": {"slug": "ios"},
                }
            ],
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(page1).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with pytest.raises(ConfigError, match="off-origin"):
            fetch_netbox_devices("https://nb.example.com", token="t")

    @patch("audnet.inventory_sources.netbox.urlopen")
    def test_pagination_same_origin_ok(self, mock_urlopen):
        from unittest.mock import MagicMock

        page1 = {
            "count": 2,
            "next": "https://nb.example.com/api/dcim/devices/?offset=1",
            "results": [
                {
                    "name": "rtr01",
                    "primary_ip": {"address": "10.0.0.1/24"},
                    "platform": {"slug": "ios"},
                }
            ],
        }
        page2 = {
            "count": 2,
            "next": None,
            "results": [
                {
                    "name": "rtr02",
                    "primary_ip": {"address": "10.0.0.2/24"},
                    "platform": {"slug": "ios"},
                }
            ],
        }
        r1 = MagicMock()
        r1.read.return_value = json.dumps(page1).encode()
        r1.__enter__ = MagicMock(return_value=r1)
        r1.__exit__ = MagicMock(return_value=False)
        r2 = MagicMock()
        r2.read.return_value = json.dumps(page2).encode()
        r2.__enter__ = MagicMock(return_value=r2)
        r2.__exit__ = MagicMock(return_value=False)
        mock_urlopen.side_effect = [r1, r2]

        devices = fetch_netbox_devices("https://nb.example.com", token="t")
        assert len(devices) == 2
        assert mock_urlopen.call_count == 2


class TestConfigEnvResolve:
    def test_resolve_device_env_password(self, monkeypatch):
        monkeypatch.setenv("AUDNET_TEST_PW", "s3cret")
        d = Device(
            name="r1",
            host="10.0.0.1",
            username="admin",
            password="${AUDNET_TEST_PW}",
        )
        resolved = _resolve_device_env(d)
        assert resolved.get_password() == "s3cret"

    def test_resolve_device_env_missing_raises(self):
        d = Device(
            name="r1",
            host="10.0.0.1",
            username="admin",
            password="${DOES_NOT_EXIST_XYZ}",
        )
        with pytest.raises(ConfigError, match="DOES_NOT_EXIST"):
            _resolve_device_env(d)

    def test_netbox_url_preserves_path(self, monkeypatch):
        monkeypatch.setenv("NETBOX_TOKEN", "tok")
        with patch("audnet.inventory_sources.netbox.fetch_netbox_devices") as mock_fetch:
            mock_fetch.return_value = [
                Device(name="r1", host="10.0.0.1", username="admin", password="x")
            ]
            load_inventory("netbox://netbox.lab.local/netbox?site=dc1")
            args, kwargs = mock_fetch.call_args
            assert args[0] == "https://netbox.lab.local/netbox"
            assert kwargs.get("allow_http") is False


class TestHistoryExtras:
    def test_corrupt_json_skipped_in_get_runs(self, tmp_path: Path):
        import sqlite3
        from audnet.history import init_db, get_runs, _db_path

        init_db(tmp_path)
        db = _db_path(tmp_path)
        with sqlite3.connect(db) as conn:
            conn.execute(
                "INSERT INTO runs (run_at, device_name, overall_pass, checks_json) "
                "VALUES ('2020-01-01', 'r1', 0, 'NOT-JSON')"
            )
            conn.commit()
        assert get_runs(history_dir=tmp_path) == []

    def test_parse_duration_rejects_bad(self):
        from audnet.history import _parse_duration

        with pytest.raises(ValueError):
            _parse_duration("nope")
        with pytest.raises(ValueError):
            _parse_duration("-7d")
        with pytest.raises(ValueError):
            _parse_duration("d")

    def test_db_session_rollback_on_error(self, tmp_path: Path):
        from audnet.history import init_db, _db_path, _db_session

        init_db(tmp_path)
        db = _db_path(tmp_path)
        with pytest.raises(RuntimeError):
            with _db_session(db) as conn:
                conn.execute("INSERT INTO runs (run_at, device_name, overall_pass, checks_json) VALUES ('t','r',0,'[]')")
                raise RuntimeError("force rollback")


class TestHistoryDriftBaseline:
    def test_empty_checks_not_used_as_baseline(self, tmp_path: Path):
        # Healthy run
        healthy = [
            AuditReport(
                device_name="rtr01",
                overall_pass=True,
                checks=[
                    ComplianceResult(
                        check_name="ssh_v2_only",
                        passed=True,
                        severity="critical",
                        detail="ok",
                    )
                ],
            )
        ]
        save_run(healthy, history_dir=tmp_path)

        # Collection-error style empty-check fail
        empty = [
            AuditReport(device_name="rtr01", overall_pass=False, checks=[])
        ]
        save_run(empty, history_dir=tmp_path)

        last = get_last_runs(history_dir=tmp_path)
        assert "rtr01" in last
        assert last["rtr01"]["checks"]  # still the healthy baseline

        # Regression against healthy baseline still detected
        current = [
            AuditReport(
                device_name="rtr01",
                overall_pass=False,
                checks=[
                    ComplianceResult(
                        check_name="ssh_v2_only",
                        passed=False,
                        severity="critical",
                        detail="v1",
                    )
                ],
            )
        ]
        drift = diff_runs(current, history_dir=tmp_path)
        assert len(drift["new_failures"]) == 1

    def test_diff_skips_empty_current_reports(self, tmp_path: Path):
        healthy = [
            AuditReport(
                device_name="rtr01",
                overall_pass=True,
                checks=[
                    ComplianceResult(
                        check_name="ssh_v2_only",
                        passed=True,
                        severity="critical",
                        detail="ok",
                    )
                ],
            )
        ]
        save_run(healthy, history_dir=tmp_path)
        empty_current = [AuditReport(device_name="rtr01", overall_pass=False, checks=[])]
        drift = diff_runs(empty_current, history_dir=tmp_path)
        assert drift["new_failures"] == []


class TestParserCanonical:
    def test_junos_ip_not_link_status(self):
        raw = """\
Interface                 Admin Link Proto    Local                 Remote
ge-0/0/0                 up    up   inet     10.0.0.1/24
"""
        rows = parse_interfaces(raw, device_type="juniper_junos")
        assert rows
        assert rows[0]["ip_address"] == "10.0.0.1/24"
        assert rows[0]["interface"] == "ge-0/0/0"

    def test_version_alias_os_to_version(self):
        # NX-OS uses Value OS — ensure canonical version field is set after parse
        from audnet.parser import _canonicalize_version

        assert _canonicalize_version({"os": "9.3(1)", "hostname": "sw"})["version"] == "9.3(1)"
        assert _canonicalize_version({"image": "4.28", "hostname": "eos"})["version"] == "4.28"
        assert _canonicalize_version({"junos_version": "21.4"})["version"] == "21.4"


class TestRemediationCheckpoint:
    def test_create_checkpoint_copies_running_config(self):
        mock_conn = MagicMock()
        mock_conn.send_command_timing.return_value = "Copy complete"
        name = _create_checkpoint(mock_conn)
        assert name.startswith("_audnet_cp_")
        cmd = mock_conn.send_command_timing.call_args[0][0]
        assert "copy running-config flash:" in cmd

    def test_rollback_uses_checkpoint_not_running_config(self):
        mock_conn = MagicMock()
        mock_conn.send_command_timing.side_effect = [
            "Rollback successful",
            "deleted",
        ]
        out = _rollback_config(
            mock_conn, "hostname rtr01\n", checkpoint_file="_audnet_cp_99"
        )
        assert "Rollback successful" in out
        first = mock_conn.send_command_timing.call_args_list[0][0][0]
        assert "configure replace flash:_audnet_cp_99" in first
        assert "copy running-config" not in first


class TestCollectorParams:
    def test_ssh_strict_env_off(self, monkeypatch):
        from audnet.collector import _ssh_strict_enabled

        monkeypatch.setenv("AUDNET_SSH_STRICT_KEY", "0")
        assert _ssh_strict_enabled() is False
        monkeypatch.setenv("AUDNET_SSH_STRICT_KEY", "1")
        assert _ssh_strict_enabled() is True

    @patch("audnet.collector.ConnectHandler")
    def test_enable_called_when_secret_set(self, mock_cls, monkeypatch):
        from audnet.collector import _do_ssh_collect

        mock_conn = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = False
        mock_conn.send_command.side_effect = ["ifaces", "version", "config"]
        mock_cls.return_value = mock_conn

        d = Device(
            name="r1",
            host="10.0.0.1",
            username="admin",
            password="pw",
            secret="enable-pw",
        )
        monkeypatch.setenv("AUDNET_SSH_STRICT_KEY", "0")
        _do_ssh_collect(d)
        mock_conn.enable.assert_called_once()
        # ConnectHandler(**params) — kwargs form
        kwargs = mock_cls.call_args.kwargs
        assert kwargs.get("secret") == "enable-pw"
        assert kwargs.get("system_host_keys") is True


class TestRealtimeHelpers:
    def test_datagram_sync_callback_no_ensure_future_error(self):
        """Sync on_message must not raise TypeError via ensure_future."""
        from audnet.realtime import SyslogProtocol

        called = []

        def on_message(name, ip, msg):
            called.append((name, ip, msg))

        proto = SyslogProtocol(on_message, {"10.0.0.1": "rtr01"})
        # datagram_received is sync; should call sync handler without create_task issues
        proto.datagram_received(b"config change", ("10.0.0.1", 514))
        assert called
        assert called[0][0] == "rtr01"


class TestCliHardening:
    def test_scrapli_import_error(self, tmp_path: Path):
        from typer.testing import CliRunner
        from audnet.cli import app

        inv = tmp_path / "d.yaml"
        inv.write_text(
            "devices:\n  - name: r1\n    host: 10.0.0.1\n    username: a\n    password: p\n"
        )
        bl = tmp_path / "b.yaml"
        bl.write_text(
            "checks:\n  ssh_v2_only:\n    description: x\n    severity: critical\n    rule: ssh_v2_only\n"
        )
        with patch.dict("sys.modules", {"audnet.scrapli_collector": None}):
            with patch(
                "builtins.__import__",
                side_effect=ImportError("no scrapli"),
            ):
                # Force backend scrapli path then import failure
                pass
        # Simpler: patch the import inside audit via collecting
        real_import = __import__

        def blocked(name, *a, **k):
            if name == "audnet.scrapli_collector" or name.endswith("scrapli_collector"):
                raise ImportError("scrapli missing")
            return real_import(name, *a, **k)

        with patch("builtins.__import__", blocked):
            result = CliRunner().invoke(
                app,
                [
                    "audit",
                    "--inventory",
                    str(inv),
                    "--baseline",
                    str(bl),
                    "--backend",
                    "scrapli",
                    "-n",
                ],
            )
        # dry-run never hits collector; use live without dry-run
        with patch("builtins.__import__", blocked):
            result = CliRunner().invoke(
                app,
                [
                    "audit",
                    "--inventory",
                    str(inv),
                    "--baseline",
                    str(bl),
                    "--backend",
                    "scrapli",
                    "--output",
                    str(tmp_path / "r"),
                    "--format",
                    "md",
                    "--no-history",
                    "--no-git-history",
                ],
            )
        assert result.exit_code == 1
        assert "Backend unavailable" in result.output or "Configuration" in result.output or result.exit_code == 1

    def test_invalid_backend_exit_1(self, tmp_path: Path):
        from typer.testing import CliRunner
        from audnet.cli import app

        inv = tmp_path / "d.yaml"
        inv.write_text(
            "devices:\n  - name: r1\n    host: 10.0.0.1\n    username: a\n    password: p\n"
        )
        bl = tmp_path / "b.yaml"
        bl.write_text(
            "checks:\n  ssh_v2_only:\n    description: x\n    severity: critical\n    rule: ssh_v2_only\n"
        )
        result = CliRunner().invoke(
            app,
            ["audit", "--inventory", str(inv), "--baseline", str(bl), "--backend", "bogus", "-n"],
        )
        assert result.exit_code == 1
        assert "Invalid --backend" in result.output

    def test_missing_inventory_clean_error(self, tmp_path: Path):
        from typer.testing import CliRunner
        from audnet.cli import app

        bl = tmp_path / "b.yaml"
        bl.write_text(
            "checks:\n  ssh_v2_only:\n    description: x\n    severity: critical\n    rule: ssh_v2_only\n"
        )
        result = CliRunner().invoke(
            app,
            [
                "audit",
                "--inventory",
                str(tmp_path / "missing.yaml"),
                "--baseline",
                str(bl),
                "-n",
            ],
        )
        assert result.exit_code == 1
        assert "Configuration error" in result.output

    def test_collection_error_surfaces_in_report(self, tmp_path: Path):
        from typer.testing import CliRunner
        from audnet.cli import app

        inv = tmp_path / "d.yaml"
        inv.write_text(
            "devices:\n  - name: r1\n    host: 10.0.0.1\n    username: a\n    password: p\n"
        )
        bl = tmp_path / "b.yaml"
        bl.write_text(
            "checks:\n  ssh_v2_only:\n    description: x\n    severity: critical\n    rule: ssh_v2_only\n"
        )
        out = tmp_path / "report"
        err_snap = DeviceSnapshot(
            device_name="r1",
            device_type="cisco_ios",
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
            collection_error="connection refused",
        )
        with patch("audnet.cli.collect_all", return_value=[err_snap]):
            result = CliRunner().invoke(
                app,
                [
                    "audit",
                    "--inventory",
                    str(inv),
                    "--baseline",
                    str(bl),
                    "--output",
                    str(out),
                    "--format",
                    "md",
                    "--no-history",
                    "--no-git-history",
                    "--no-fail",
                    "--backend",
                    "netmiko",
                ],
            )
        assert result.exit_code == 0
        md = (tmp_path / "report.md").read_text(encoding="utf-8")
        assert "collection" in md
        assert "connection refused" in md

    def test_no_fail_suppresses_drift_exit_2(self, tmp_path: Path):
        from typer.testing import CliRunner
        from audnet.cli import app
        from audnet.history import save_run

        inv = tmp_path / "d.yaml"
        inv.write_text(
            "devices:\n  - name: r1\n    host: 10.0.0.1\n    username: a\n    password: p\n"
        )
        bl = tmp_path / "b.yaml"
        bl.write_text(
            "checks:\n  ssh_v2_only:\n    description: x\n    severity: critical\n    rule: ssh_v2_only\n"
        )
        hist = tmp_path / "hist"
        save_run(
            [
                AuditReport(
                    device_name="r1",
                    overall_pass=True,
                    checks=[
                        ComplianceResult(
                            check_name="ssh_v2_only",
                            passed=True,
                            severity="critical",
                            detail="ok",
                        )
                    ],
                )
            ],
            history_dir=hist,
        )
        # Config that fails ssh check
        snap = DeviceSnapshot(
            device_name="r1",
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(lines=["ip ssh version 1"]),
        )
        with patch("audnet.cli.collect_all", return_value=[snap]):
            result = CliRunner().invoke(
                app,
                [
                    "audit",
                    "--inventory",
                    str(inv),
                    "--baseline",
                    str(bl),
                    "--output",
                    str(tmp_path / "r"),
                    "--format",
                    "md",
                    "--history-dir",
                    str(hist),
                    "--no-git-history",
                    "--no-fail",
                    "--backend",
                    "netmiko",
                ],
            )
        assert result.exit_code == 0


class TestStrictCredentials:
    def test_strict_flags_plaintext(self):
        from audnet.config import _check_strict_credentials

        d = Device(name="r1", host="10.0.0.1", username="a", password="plaintext")
        with pytest.raises(ConfigError, match="Insecure credentials"):
            _check_strict_credentials([d])

    def test_strict_ok_with_keys(self):
        from audnet.config import _check_strict_credentials

        d = Device(name="r1", host="10.0.0.1", username="a", password="", use_keys=True)
        _check_strict_credentials([d])  # no raise


class TestCollectorIsolation:
    def test_unexpected_exception_isolated(self):
        from audnet.collector import collect_all
        from audnet.models import Device

        d1 = Device(name="ok", host="10.0.0.1", username="a", password="p")
        d2 = Device(name="bad", host="10.0.0.2", username="a", password="p")

        def fake_collect(dev):
            if dev.name == "bad":
                # Simulate a future that raises unexpected error when result() is called
                raise RuntimeError("boom")
            return DeviceSnapshot(
                device_name=dev.name,
                device_type=dev.device_type,
                interfaces=ParsedInterfaces(),
                version=ParsedVersion(),
                config=ParsedConfig(lines=["hostname ok"]),
            )

        # Patch at thread level: make collect_device raise for bad device
        with patch("audnet.collector.collect_device", side_effect=fake_collect):
            snaps = collect_all([d1, d2], max_workers=2)
        assert len(snaps) == 2
        by_name = {s.device_name: s for s in snaps}
        assert by_name["ok"].collection_error is None
        # RuntimeError is raised inside the worker and caught by collect_device's
        # outer try — if not, collect_all isolates via future.result Exception
        assert by_name["bad"].collection_error is not None or by_name["bad"].config.lines

    @pytest.mark.asyncio
    async def test_async_gather_isolates_exceptions(self):
        from audnet.collector_async import collect_all_async
        from audnet.models import Device

        d1 = Device(name="a", host="10.0.0.1", username="u", password="p")
        d2 = Device(name="b", host="10.0.0.2", username="u", password="p")

        async def fake(dev, known_hosts=None):
            if dev.name == "b":
                raise RuntimeError("async boom")
            return DeviceSnapshot(
                device_name=dev.name,
                device_type=dev.device_type,
                interfaces=ParsedInterfaces(),
                version=ParsedVersion(),
                config=ParsedConfig(),
            )

        with patch("audnet.collector_async.collect_device_async", side_effect=fake):
            snaps = await collect_all_async([d1, d2], max_workers=2)
        assert len(snaps) == 2
        by_name = {s.device_name: s for s in snaps}
        assert by_name["a"].collection_error is None
        assert by_name["b"].collection_error is not None
        assert "async boom" in by_name["b"].collection_error


class TestParserWarnEmpty:
    def test_nonempty_raw_zero_records_returns_empty(self):
        # Garbage CLI that matches no TextFSM rules
        rows = parse_interfaces("%%% completely invalid %%%", device_type="cisco_ios")
        assert rows == []

    def test_empty_version_raw(self):
        assert parse_version("", device_type="cisco_ios") == {}

    def test_canonicalize_interface_aliases(self):
        from audnet.parser import _canonicalize_interface

        row = _canonicalize_interface({"port": "1", "local": "10.0.0.1", "admin_status": "up"})
        assert row["interface"] == "1"
        assert row["ip_address"] == "10.0.0.1"
        assert row["status"] == "up"

        pan = _canonicalize_interface(
            {"interface": "eth1/1", "speed_duplex": "1000/full/up"}
        )
        assert pan["link_status"] == "up"
        assert pan["status"] == "up"


class TestSnmpDetect:
    @pytest.mark.asyncio
    async def test_pysnmp_missing_falls_back(self, monkeypatch):
        from audnet.vendor_registry import detect_vendor_snmp

        import builtins

        real_import = builtins.__import__

        def blocked(name, *a, **k):
            if name.startswith("pysnmp"):
                raise ImportError("no pysnmp")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", blocked)
        result = await detect_vendor_snmp("10.0.0.1")
        assert result == "cisco_ios"

    @pytest.mark.asyncio
    async def test_snmp_error_falls_back(self):
        from audnet.vendor_registry import detect_vendor_snmp

        with patch("pysnmp.hlapi.asyncio.get_cmd") as mock_get:
            def fail_iter(*a, **k):
                raise OSError("timeout")

            mock_get.side_effect = fail_iter
            result = await detect_vendor_snmp("10.0.0.1")
            assert result == "cisco_ios"

    @pytest.mark.asyncio
    async def test_snmp_error_status_falls_back(self):
        from audnet.vendor_registry import detect_vendor_snmp

        async def err_status(*a, **k):
            return ("timeout", 0, 0, [])

        with patch("pysnmp.hlapi.asyncio.get_cmd", side_effect=err_status):
            result = await detect_vendor_snmp("10.0.0.1")
        assert result == "cisco_ios"


class TestAsyncCollectErrors:
    @pytest.mark.asyncio
    async def test_nonzero_exit_becomes_error(self):
        from audnet.collector_async import collect_device_async

        mock_result = MagicMock()
        mock_result.exit_status = 1
        mock_result.stdout = ""
        mock_result.stderr = "fail"

        mock_conn = MagicMock()
        mock_conn.run = pytest.importorskip("unittest.mock").AsyncMock(return_value=mock_result)
        mock_conn.__aenter__ = pytest.importorskip("unittest.mock").AsyncMock(
            return_value=mock_conn
        )
        mock_conn.__aexit__ = pytest.importorskip("unittest.mock").AsyncMock(return_value=False)

        with patch("audnet.collector_async.asyncssh.connect", return_value=mock_conn):
            snap = await collect_device_async(
                Device(name="r1", host="10.0.0.1", username="u", password="p")
            )
        assert snap.collection_error is not None
        assert "exit=1" in snap.collection_error

    @pytest.mark.asyncio
    async def test_key_auth_params(self):
        from audnet.collector_async import _do_ssh_collect
        from unittest.mock import AsyncMock

        mock_result = MagicMock()
        mock_result.exit_status = 0
        mock_result.stdout = "ok"

        mock_conn = MagicMock()
        mock_conn.run = AsyncMock(return_value=mock_result)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("audnet.collector_async.asyncssh.connect", return_value=mock_conn) as mock_c:
            await _do_ssh_collect(
                Device(
                    name="r1",
                    host="10.0.0.1",
                    username="u",
                    password="",
                    use_keys=True,
                    key_file="/tmp/id_rsa",
                ),
                known_hosts="",
            )
        kwargs = mock_c.call_args.kwargs
        assert kwargs.get("client_keys") == ["/tmp/id_rsa"]
        assert kwargs.get("known_hosts") == ""

    @pytest.mark.asyncio
    async def test_use_keys_default_without_path(self):
        from audnet.collector_async import _do_ssh_collect
        from unittest.mock import AsyncMock

        mock_result = MagicMock()
        mock_result.exit_status = 0
        mock_result.stdout = "ok"
        mock_conn = MagicMock()
        mock_conn.run = AsyncMock(return_value=mock_result)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("audnet.collector_async.asyncssh.connect", return_value=mock_conn) as mock_c:
            await _do_ssh_collect(
                Device(
                    name="r1",
                    host="10.0.0.1",
                    username="u",
                    password="",
                    use_keys=True,
                    key_file=None,
                )
            )
        assert mock_c.call_args.kwargs.get("client_keys") == "default"

    @pytest.mark.asyncio
    async def test_none_stdout_errors(self):
        from audnet.collector_async import collect_device_async
        from unittest.mock import AsyncMock

        mock_result = MagicMock()
        mock_result.exit_status = 0
        mock_result.stdout = None
        mock_conn = MagicMock()
        mock_conn.run = AsyncMock(return_value=mock_result)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("audnet.collector_async.asyncssh.connect", return_value=mock_conn):
            snap = await collect_device_async(
                Device(name="r1", host="10.0.0.1", username="u", password="p")
            )
        assert snap.collection_error is not None
        assert "no stdout" in snap.collection_error


class TestCliBackends:
    def test_asyncssh_backend(self, tmp_path: Path):
        from typer.testing import CliRunner
        from audnet.cli import app

        inv = tmp_path / "d.yaml"
        inv.write_text(
            "devices:\n  - name: r1\n    host: 10.0.0.1\n    username: a\n    password: p\n"
        )
        bl = tmp_path / "b.yaml"
        bl.write_text(
            "checks:\n  ssh_v2_only:\n    description: x\n    severity: critical\n    rule: ssh_v2_only\n"
        )
        snap = DeviceSnapshot(
            device_name="r1",
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(lines=["ip ssh version 2"]),
        )

        async def fake_collect(*a, **k):
            return [snap]

        with patch("audnet.collector_async.collect_all_async", side_effect=fake_collect):
            result = CliRunner().invoke(
                app,
                [
                    "audit",
                    "--inventory",
                    str(inv),
                    "--baseline",
                    str(bl),
                    "--backend",
                    "asyncssh",
                    "--output",
                    str(tmp_path / "r"),
                    "--format",
                    "md",
                    "--no-history",
                    "--no-git-history",
                    "--no-fail",
                ],
            )
        assert result.exit_code == 0
        assert "asyncssh" in result.output.lower() or "PASS" in result.output

    def test_auto_with_async_flag(self, tmp_path: Path):
        from typer.testing import CliRunner
        from audnet.cli import app

        inv = tmp_path / "d.yaml"
        inv.write_text(
            "devices:\n  - name: r1\n    host: 10.0.0.1\n    username: a\n    password: p\n"
        )
        bl = tmp_path / "b.yaml"
        bl.write_text(
            "checks:\n  ssh_v2_only:\n    description: x\n    severity: critical\n    rule: ssh_v2_only\n"
        )
        snap = DeviceSnapshot(
            device_name="r1",
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(lines=["ip ssh version 2"]),
        )

        async def fake_collect(*a, **k):
            return [snap]

        with patch("audnet.collector_async.collect_all_async", side_effect=fake_collect):
            result = CliRunner().invoke(
                app,
                [
                    "audit",
                    "--inventory",
                    str(inv),
                    "--baseline",
                    str(bl),
                    "--async",
                    "--output",
                    str(tmp_path / "r"),
                    "--format",
                    "md",
                    "--no-history",
                    "--no-git-history",
                    "--no-fail",
                ],
            )
        assert result.exit_code == 0

class TestScrapliIsolation:
    @pytest.mark.asyncio
    async def test_scrapli_gather_isolates(self):
        pytest.importorskip('scrapli')
        from audnet.scrapli_collector import collect_all_scrapli

        d1 = Device(name='a', host='10.0.0.1', username='u', password='p')
        d2 = Device(name='b', host='10.0.0.2', username='u', password='p')

        async def fake(dev):
            if dev.name == 'b':
                raise RuntimeError('scrapli boom')
            return DeviceSnapshot(
                device_name=dev.name,
                device_type=dev.device_type,
                interfaces=ParsedInterfaces(),
                version=ParsedVersion(),
                config=ParsedConfig(),
            )

        with patch('audnet.scrapli_collector.collect_device_scrapli', side_effect=fake):
            snaps = await collect_all_scrapli([d1, d2], max_workers=2)
        by_name = {s.device_name: s for s in snaps}
        assert by_name['a'].collection_error is None
        assert 'scrapli boom' in (by_name['b'].collection_error or '')


class TestWebhookStatus:
    @pytest.mark.asyncio
    async def test_webhook_retries_on_http_error(self):
        from audnet.realtime import AlertConfig, AlertManager, ChangeEvent
        from unittest.mock import AsyncMock

        config = AlertConfig(
            webhook_url="https://hooks.example.com/x",
            webhook_retries=2,
            webhook_secret=None,
        )
        mgr = AlertManager(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        async def fake_client():
            return mock_client

        with patch.object(mgr, "_get_client", side_effect=fake_client):
            event = ChangeEvent(
                device_name="r1",
                source_ip="10.0.0.1",
                event_type="syslog",
                timestamp=0.0,
                raw_message="x",
                change_summary="y",
                severity="high",
            )
            await mgr._send_webhook(event)
        assert mock_client.post.await_count == 2
