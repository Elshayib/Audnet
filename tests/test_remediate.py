"""Tests for the remediation / safe push module."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from audnet.remediate import (
    ApprovalGate,
    ConfigDiff,
    RemediationResult,
    RemediationRollbackError,
    RemediationStatus,
    apply_config,
    compute_diff,
    remediate_devices,
)


# ---------------------------------------------------------------------------
# ConfigDiff
# ---------------------------------------------------------------------------


class TestConfigDiff:
    def test_unchanged_diff(self):
        current = ["hostname rtr01", "interface Gig0/0", " ip address 10.0.0.1 255.255.255.0"]
        snippet = ["hostname rtr01", "interface Gig0/0"]
        diff = compute_diff(current, snippet)
        assert diff.unchanged is True
        assert diff.added_lines == []
        assert diff.removed_lines == []

    def test_added_lines(self):
        current = ["hostname rtr01"]
        snippet = ["hostname rtr01", "ntp server 10.0.0.1", "ntp server 10.0.0.2"]
        diff = compute_diff(current, snippet)
        assert diff.unchanged is False
        assert len(diff.added_lines) == 2
        assert "ntp server 10.0.0.1" in diff.added_lines
        assert "ntp server 10.0.0.2" in diff.added_lines

    def test_empty_current(self):
        diff = compute_diff([], ["hostname rtr01", "ntp server 10.0.0.1"])
        assert diff.unchanged is False
        assert len(diff.added_lines) == 2

    def test_empty_snippet(self):
        diff = compute_diff(["hostname rtr01"], [])
        assert diff.unchanged is True
        assert diff.added_lines == []

    def test_whitespace_lines_ignored(self):
        diff = compute_diff(["hostname rtr01", ""], ["hostname rtr01", "   ", ""])
        assert diff.unchanged is True

    def test_str_representation_unchanged(self):
        diff = ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True)
        s = str(diff)
        assert "rtr01" in s
        assert "No changes" in s

    def test_str_representation_with_additions(self):
        diff = ConfigDiff(
            device_name="rtr01",
            added_lines=["ntp server 10.0.0.1"],
            removed_lines=[],
            unchanged=False,
        )
        s = str(diff)
        assert "rtr01" in s
        assert "ntp server 10.0.0.1" in s
        assert "+++" in s

    def test_str_representation_with_removals(self):
        diff = ConfigDiff(
            device_name="rtr01",
            added_lines=[],
            removed_lines=["no ntp server 10.0.0.1"],
            unchanged=False,
        )
        s = str(diff)
        assert "---" in s
        assert "no ntp server 10.0.0.1" in s

    def test_str_representation_with_both(self):
        diff = ConfigDiff(
            device_name="rtr01",
            added_lines=["ntp server 10.0.0.1"],
            removed_lines=["no ntp server 10.0.0.1"],
            unchanged=False,
        )
        s = str(diff)
        assert "+++" in s
        assert "---" in s


# ---------------------------------------------------------------------------
# RemediationResult
# ---------------------------------------------------------------------------


class TestRemediationResult:
    def test_success_status(self):
        r = RemediationResult(
            device_name="rtr01",
            status=RemediationStatus.SUCCESS,
            diff=ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True),
        )
        assert r.success is True

    def test_dry_run_status(self):
        r = RemediationResult(
            device_name="rtr01",
            status=RemediationStatus.DRY_RUN,
            diff=ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True),
        )
        assert r.success is True

    def test_skipped_status(self):
        r = RemediationResult(
            device_name="rtr01",
            status=RemediationStatus.SKIPPED,
            diff=ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True),
        )
        assert r.success is True

    def test_failed_status(self):
        r = RemediationResult(
            device_name="rtr01",
            status=RemediationStatus.FAILED,
            diff=ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True),
            error="Connection refused",
        )
        assert r.success is False

    def test_rolled_back_status(self):
        r = RemediationResult(
            device_name="rtr01",
            status=RemediationStatus.ROLLED_BACK,
            diff=ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True),
            rolled_back=True,
            error="Apply failed",
        )
        assert r.success is False

    def test_timestamp_auto_set(self):
        r = RemediationResult(
            device_name="rtr01",
            status=RemediationStatus.SUCCESS,
            diff=ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True),
        )
        assert r.timestamp != ""
        assert "T" in r.timestamp  # ISO format


# ---------------------------------------------------------------------------
# ApprovalGate
# ---------------------------------------------------------------------------


class TestApprovalGate:
    def test_auto_approve(self):
        gate = ApprovalGate(auto_approve=True)
        diff = ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True)
        assert gate.request_approval("rtr01", diff) is True

    def test_interactive_approve(self):
        gate = ApprovalGate(auto_approve=False)
        diff = ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True)
        with patch("builtins.input", return_value="y"):
            assert gate.request_approval("rtr01", diff) is True

    def test_interactive_deny(self):
        gate = ApprovalGate(auto_approve=False)
        diff = ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True)
        with patch("builtins.input", return_value="n"):
            assert gate.request_approval("rtr01", diff) is False

    def test_interactive_empty_response(self):
        gate = ApprovalGate(auto_approve=False)
        diff = ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True)
        with patch("builtins.input", return_value=""):
            assert gate.request_approval("rtr01", diff) is False

    def test_interactive_eof(self):
        gate = ApprovalGate(auto_approve=False)
        diff = ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True)
        with patch("builtins.input", side_effect=EOFError):
            assert gate.request_approval("rtr01", diff) is False

    def test_interactive_keyboard_interrupt(self):
        gate = ApprovalGate(auto_approve=False)
        diff = ConfigDiff(device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True)
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            assert gate.request_approval("rtr01", diff) is False


# ---------------------------------------------------------------------------
# apply_config (mocked SSH)
# ---------------------------------------------------------------------------


class TestApplyConfig:
    """Tests for the apply_config function with mocked Netmiko."""

    @pytest.fixture
    def device(self):
        from audnet.models import Device

        return Device(
            name="rtr01",
            host="10.0.0.1",
            device_type="cisco_ios",
            username="admin",
            password="secret",
        )

    @pytest.fixture
    def config_snippet(self):
        return [
            "ntp server 10.0.0.1",
            "ntp server 10.0.0.2",
        ]

    def test_dry_run_returns_diff(self, device, config_snippet):
        """Dry run should return diff without applying."""
        mock_conn = MagicMock()
        mock_conn.send_command.return_value = "hostname rtr01\ninterface Gig0/0\n"

        with patch("audnet.remediate._connect", return_value=mock_conn):
            result = apply_config(device, config_snippet, dry_run=True)

        assert result.status == RemediationStatus.DRY_RUN
        assert result.success is True
        assert len(result.diff.added_lines) == 2
        mock_conn.disconnect.assert_called_once()

    def test_idempotent_skip(self, device):
        """If config already present, should skip."""
        mock_conn = MagicMock()
        mock_conn.send_command.return_value = (
            "hostname rtr01\nntp server 10.0.0.1\nntp server 10.0.0.2\n"
        )

        with patch("audnet.remediate._connect", return_value=mock_conn):
            result = apply_config(
                device, ["ntp server 10.0.0.1", "ntp server 10.0.0.2"], dry_run=False
            )

        assert result.status == RemediationStatus.SKIPPED
        assert result.success is True

    def test_force_apply_even_if_unchanged(self, device):
        """Force flag should apply even if config is already present."""
        mock_conn = MagicMock()
        mock_conn.send_command.return_value = "hostname rtr01\nntp server 10.0.0.1\n"

        with (
            patch("audnet.remediate._connect", return_value=mock_conn),
            patch("audnet.remediate.ApprovalGate.request_approval", return_value=True),
        ):
            result = apply_config(
                device,
                ["ntp server 10.0.0.1"],
                dry_run=False,
                force=True,
                auto_approve=True,
            )

        # Should not be skipped — force=True means we proceed
        assert result.status != RemediationStatus.SKIPPED

    def test_connection_failure(self, device, config_snippet):
        """Connection failure should return FAILED."""
        from audnet.exceptions import CollectionError

        with patch("audnet.remediate._connect", side_effect=CollectionError("Connection refused")):
            result = apply_config(device, config_snippet, dry_run=True)

        assert result.status == RemediationStatus.FAILED
        assert result.success is False
        assert "Connection refused" in result.error

    def test_approval_denied(self, device, config_snippet):
        """If approval is denied, should return FAILED."""
        mock_conn = MagicMock()
        mock_conn.send_command.return_value = "hostname rtr01\n"

        with (
            patch("audnet.remediate._connect", return_value=mock_conn),
            patch("audnet.remediate.ApprovalGate.request_approval", return_value=False),
        ):
            result = apply_config(device, config_snippet, dry_run=False)

        assert result.status == RemediationStatus.FAILED
        assert "Approval denied" in result.error

    def test_successful_apply(self, device, config_snippet):
        """Successful apply should return SUCCESS."""
        mock_conn = MagicMock()
        # First call: show running-config (pre), second: config set, third: show running-config (post)
        mock_conn.send_command.side_effect = [
            "hostname rtr01\ninterface Gig0/0\n",  # pre
            "hostname rtr01\ninterface Gig0/0\nntp server 10.0.0.1\nntp server 10.0.0.2\n",  # post
        ]
        mock_conn.send_config_set.return_value = "Config applied"

        with (
            patch("audnet.remediate._connect", return_value=mock_conn),
            patch("audnet.remediate.ApprovalGate.request_approval", return_value=True),
        ):
            result = apply_config(device, config_snippet, dry_run=False, auto_approve=True)

        assert result.status == RemediationStatus.SUCCESS
        assert result.success is True
        assert result.duration_seconds > 0

    def test_verification_failure_triggers_rollback(self, device, config_snippet):
        """If verification fails, should attempt rollback."""
        mock_conn = MagicMock()
        # Pre-config doesn't have the lines
        # Post-config also doesn't have them (verification fails)
        mock_conn.send_command.side_effect = [
            "hostname rtr01\n",  # pre
            "hostname rtr01\n",  # post — lines missing
        ]
        mock_conn.send_config_set.return_value = "Config applied"

        with (
            patch("audnet.remediate._connect", return_value=mock_conn),
            patch("audnet.remediate.ApprovalGate.request_approval", return_value=True),
            patch("audnet.remediate._rollback_config", return_value="Rolled back"),
        ):
            result = apply_config(device, config_snippet, dry_run=False, auto_approve=True)

        assert result.status == RemediationStatus.ROLLED_BACK
        assert result.rolled_back is True

    def test_rollback_failure(self, device, config_snippet):
        """If both apply and rollback fail, should return FAILED with rollback_error."""
        mock_conn = MagicMock()
        # Pre-config doesn't have the lines
        # send_config_set succeeds (applied=True)
        # Post-config doesn't have lines (verification fails)
        mock_conn.send_command.side_effect = [
            "hostname rtr01\n",  # pre
            "hostname rtr01\n",  # post — verification fails (lines missing)
        ]
        mock_conn.send_config_set.return_value = "Config applied"

        with (
            patch("audnet.remediate._connect", return_value=mock_conn),
            patch("audnet.remediate.ApprovalGate.request_approval", return_value=True),
            patch(
                "audnet.remediate._rollback_config",
                side_effect=RemediationRollbackError("Rollback also failed"),
            ),
        ):
            result = apply_config(device, config_snippet, dry_run=False, auto_approve=True)

        assert result.status == RemediationStatus.FAILED
        assert result.rollback_error is not None


# ---------------------------------------------------------------------------
# remediate_devices (multi-device orchestration)
# ---------------------------------------------------------------------------


class TestRemediateDevices:
    """Tests for the remediate_devices orchestration function."""

    @pytest.fixture
    def devices(self):
        from audnet.models import Device

        return [
            Device(
                name="rtr01",
                host="10.0.0.1",
                device_type="cisco_ios",
                username="admin",
                password="secret",
            ),
            Device(
                name="rtr02",
                host="10.0.0.2",
                device_type="cisco_ios",
                username="admin",
                password="secret",
            ),
        ]

    def test_dry_run_all_devices(self, devices):
        """Dry run should process all devices."""
        with patch("audnet.remediate.apply_config") as mock_apply:
            mock_apply.return_value = RemediationResult(
                device_name="rtr01",
                status=RemediationStatus.DRY_RUN,
                diff=ConfigDiff(
                    device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True
                ),
            )
            results = remediate_devices(devices, ["ntp server 10.0.0.1"], dry_run=True)

        assert len(results) == 2
        assert mock_apply.call_count == 2

    def test_failure_stops_pipeline(self, devices):
        """On failure, remaining devices should be skipped."""
        with patch("audnet.remediate.apply_config") as mock_apply:
            mock_apply.side_effect = [
                RemediationResult(
                    device_name="rtr01",
                    status=RemediationStatus.FAILED,
                    diff=ConfigDiff(
                        device_name="rtr01", added_lines=[], removed_lines=[], unchanged=True
                    ),
                    error="Connection refused",
                ),
                # rtr02 should be skipped
            ]
            results = remediate_devices(devices, ["ntp server 10.0.0.1"], dry_run=False)

        assert len(results) == 2
        assert results[0].status == RemediationStatus.FAILED
        assert results[1].status == RemediationStatus.SKIPPED
        assert results[1].error == "Skipped due to previous failure"
        # apply_config should only be called once (for rtr01)
        assert mock_apply.call_count == 1

    def test_success_continues_to_next(self, devices):
        """On success, should continue to next device."""
        with patch("audnet.remediate.apply_config") as mock_apply:
            mock_apply.return_value = RemediationResult(
                device_name="rtr01",
                status=RemediationStatus.SUCCESS,
                diff=ConfigDiff(
                    device_name="rtr01",
                    added_lines=["ntp server 10.0.0.1"],
                    removed_lines=[],
                    unchanged=False,
                ),
            )
            results = remediate_devices(
                devices, ["ntp server 10.0.0.1"], dry_run=False, auto_approve=True
            )

        assert len(results) == 2
        assert all(r.status == RemediationStatus.SUCCESS for r in results)
        assert mock_apply.call_count == 2


# ---------------------------------------------------------------------------
# _rollback_config
# ---------------------------------------------------------------------------


class TestRollbackConfig:
    """Tests for the _rollback_config function."""

    def test_configure_replace_success(self):
        """Should try configure replace first with timing-based output."""
        mock_conn = MagicMock()
        mock_conn.send_command_timing.side_effect = [
            "Copy successful",  # copy running-config flash:...
            "Rollback successful",  # configure replace flash:... force
            "Delete successful",  # delete flash:...
        ]

        from audnet.remediate import _rollback_config

        result = _rollback_config(mock_conn, "hostname rtr01\n")
        assert "Rollback successful" in result

    def test_configure_replace_with_confirmation(self):
        """Should handle [y/n] confirmation prompt from configure replace."""
        mock_conn = MagicMock()
        mock_conn.send_command_timing.side_effect = [
            "Copy successful",  # copy running-config flash:...
            "This will apply the following configuration:\nAre you sure? [y/n]",  # configure replace
            "Confirmed",  # send y
            "Delete successful",  # delete flash:...
        ]

        from audnet.remediate import _rollback_config

        result = _rollback_config(mock_conn, "hostname rtr01\n")
        assert "Confirmed" in result

    def test_configure_replace_with_no_prompt(self):
        """Should handle '? [no]:' confirmation prompt from configure replace."""
        mock_conn = MagicMock()
        mock_conn.send_command_timing.side_effect = [
            "Copy successful",  # copy running-config flash:...
            "This will apply the following configuration:\n? [no]:",  # configure replace
            "Confirmed",  # send y
            "Delete successful",  # delete flash:...
        ]

        from audnet.remediate import _rollback_config

        result = _rollback_config(mock_conn, "hostname rtr01\n")
        assert "Confirmed" in result

    def test_netmiko_rollback_fallback(self):
        """Should try Netmiko built-in rollback if configure replace fails."""
        mock_conn = MagicMock()
        # configure replace fails
        mock_conn.send_command.side_effect = Exception("copy failed")
        mock_conn.send_command_timing.side_effect = Exception("timing failed")
        # Netmiko rollback succeeds
        mock_conn.rollback.return_value = "Netmiko rollback ok"

        from audnet.remediate import _rollback_config

        result = _rollback_config(mock_conn, "hostname rtr01\n")
        assert "Netmiko rollback ok" in result

    def test_fallback_to_line_by_line(self):
        """If all strategies fail, should raise RemediationRollbackError."""
        mock_conn = MagicMock()
        # All strategies fail
        mock_conn.send_command.side_effect = Exception("copy failed")
        mock_conn.send_command_timing.side_effect = Exception("timing failed")
        mock_conn.rollback.side_effect = Exception("rollback not supported")
        mock_conn.send_config_set.side_effect = Exception("line-by-line failed")

        from audnet.remediate import _rollback_config

        with pytest.raises(RemediationRollbackError):
            _rollback_config(mock_conn, "hostname rtr01\n")
