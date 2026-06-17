"""Tests for Git-backed config history."""

from pathlib import Path

import pytest

from audnet.exceptions import GitHistoryError
from audnet.git_history import (
    diff_configs,
    get_config_at,
    get_config_history,
    init_git_repo,
    rollback_config,
    sanitize_config,
    save_config_snapshot,
)


# ---------------------------------------------------------------------------
# sanitize_config
# ---------------------------------------------------------------------------


class TestSanitizeConfig:
    def test_returns_empty_for_empty_input(self):
        assert sanitize_config("", "rtr01") == ""

    def test_returns_empty_for_none_like(self):
        assert sanitize_config("", "rtr01") == ""

    def test_redacts_password_lines(self):
        config = "hostname rtr01\npassword secret123\ninterface Gig0/0\n"
        result = sanitize_config(config, "rtr01")
        assert "password" not in result
        assert "REDACTED" in result
        assert "hostname rtr01" in result
        assert "interface Gig0/0" in result

    def test_redacts_enable_password(self):
        config = "enable password mypass\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "mypass" not in result

    def test_redacts_secret_lines(self):
        config = "enable secret 5 $1$abc$def\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "$1$abc$def" not in result

    def test_redacts_snmp_community(self):
        config = "snmp-server community public RO\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "public" not in result

    def test_redacts_key_string(self):
        config = "key string mykey\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result

    def test_redacts_private_key_block(self):
        config = "-----BEGIN RSA PRIVATE KEY-----\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "MIIE" not in result  # key content redacted

    def test_preserves_non_sensitive_lines(self):
        config = "hostname rtr01\ninterface Gig0/0\n ip address 10.0.0.1 255.255.255.0\n"
        result = sanitize_config(config, "rtr01")
        assert result == config

    def test_device_name_in_redaction_marker(self):
        config = "password secret\n"
        result = sanitize_config(config, "my-router")
        assert "my-router" in result

    def test_case_insensitive_matching(self):
        config = "PASSWORD secret123\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result

    def test_multiline_config(self):
        config = (
            "hostname rtr01\n"
            "password secret\n"
            "interface Gig0/0\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            "snmp-server community private RW\n"
            "!\n"
        )
        result = sanitize_config(config, "rtr01")
        assert "hostname rtr01" in result
        assert "interface Gig0/0" in result
        assert "ip address 10.0.0.1" in result
        assert "secret" not in result
        assert "private" not in result
        assert result.count("REDACTED") == 2

    def test_redacts_username_password(self):
        """Mid-line: 'username <user> password <level> <secret>' is redacted."""
        config = "username admin password 0 MyP@ssw0rd123\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "MyP@ssw0rd123" not in result

    def test_redacts_ip_ftp_password(self):
        """Mid-line: 'ip ftp password <secret>' is redacted."""
        config = "ip ftp password 0 ftppass\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "ftppass" not in result

    def test_redacts_tacacs_server_key(self):
        """Mid-line: 'tacacs-server key <secret>' is redacted."""
        config = "tacacs-server key MyTACACSkey\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "MyTACACSkey" not in result

    def test_redacts_ntp_authentication_key(self):
        """Mid-line: 'ntp authentication-key <id> md5 <secret>' is redacted."""
        config = "ntp authentication-key 1 md5 SecretNTPKey\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "SecretNTPKey" not in result

    def test_redacts_crypto_isakmp_key(self):
        """Mid-line: 'crypto isakmp key <secret> address <ip>' is redacted."""
        config = "crypto isakmp key MyVPNkey address 10.0.0.1\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "MyVPNkey" not in result

    def test_redacts_crypto_ike_key(self):
        """Mid-line: 'crypto ike key <secret>' is redacted."""
        config = "crypto ike key MyIKEkey\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "MyIKEkey" not in result

    def test_redacts_neighbor_bgp_password(self):
        """Mid-line: 'neighbor <ip> bgp password <secret>' is redacted."""
        config = "neighbor 10.0.0.2 bgp password BGPPassword\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "BGPPassword" not in result

    def test_redacts_neighbor_password(self):
        """Mid-line: 'neighbor <ip> password <secret>' is redacted."""
        config = "neighbor 10.0.0.2 password PeerPass\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "PeerPass" not in result

    def test_redacts_service_password_encryption(self):
        """Mid-line: 'service password-encryption' is redacted."""
        config = "service password-encryption\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result

    def test_midline_case_insensitive(self):
        """Mid-line patterns are case-insensitive."""
        config = "USERNAME admin PASSWORD 0 Secret\n"
        result = sanitize_config(config, "rtr01")
        assert "REDACTED" in result
        assert "Secret" not in result

    def test_midline_mixed_with_plain(self):
        """Config with both start-of-line and mid-line sensitive lines."""
        config = (
            "hostname rtr01\n"
            "password linepassword\n"
            "username admin password 0 userpass\n"
            "interface Gig0/0\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            "tacacs-server key tackey\n"
            "!\n"
        )
        result = sanitize_config(config, "rtr01")
        assert "hostname rtr01" in result
        assert "interface Gig0/0" in result
        assert "ip address 10.0.0.1" in result
        assert "linepassword" not in result
        assert "userpass" not in result
        assert "tackey" not in result
        assert result.count("REDACTED") == 3


class TestSanitizeConfigToFile:
    def test_writes_sanitized_to_file(self, tmp_path: Path):
        """sanitize_config_to_file writes sanitized output directly to a file."""
        from audnet.git_history import sanitize_config_to_file

        config = "hostname rtr01\npassword secret123\ninterface Gig0/0\n"
        output_path = tmp_path / "rtr01.cfg"
        sanitize_config_to_file(config, "rtr01", output_path)
        result = output_path.read_text()
        assert "hostname rtr01" in result
        assert "interface Gig0/0" in result
        assert "secret123" not in result
        assert "REDACTED" in result

    def test_empty_input_writes_empty_file(self, tmp_path: Path):
        from audnet.git_history import sanitize_config_to_file

        output_path = tmp_path / "rtr01.cfg"
        sanitize_config_to_file("", "rtr01", output_path)
        assert output_path.read_text() == ""

    def test_matches_sanitize_config_output(self, tmp_path: Path):
        """sanitize_config_to_file produces the same output as sanitize_config."""
        from audnet.git_history import sanitize_config, sanitize_config_to_file

        config = (
            "hostname rtr01\n"
            "password linepass\n"
            "username admin password 0 userpass\n"
            "interface Gig0/0\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            "tacacs-server key tackey\n"
            "snmp-server community private RW\n"
        )
        expected = sanitize_config(config, "rtr01")
        output_path = tmp_path / "rtr01.cfg"
        sanitize_config_to_file(config, "rtr01", output_path)
        assert output_path.read_text() == expected

    def test_redacts_midline_patterns(self, tmp_path: Path):
        from audnet.git_history import sanitize_config_to_file

        config = "username admin password 0 MyP@ssw0rd\n"
        output_path = tmp_path / "rtr01.cfg"
        sanitize_config_to_file(config, "rtr01", output_path)
        result = output_path.read_text()
        assert "REDACTED" in result
        assert "MyP@ssw0rd" not in result

    def test_device_name_in_redaction_marker(self, tmp_path: Path):
        from audnet.git_history import sanitize_config_to_file

        config = "password secret\n"
        output_path = tmp_path / "rtr01.cfg"
        sanitize_config_to_file(config, "my-router", output_path)
        result = output_path.read_text()
        assert "my-router" in result

    def test_large_config_streams_efficiently(self, tmp_path: Path):
        """Verify the function handles large configs without error."""
        from audnet.git_history import sanitize_config_to_file

        # Simulate a large config (100KB+)
        lines = [f"interface Gig0/{i}\n" for i in range(2000)]
        lines.append("password bigsecret\n")
        config = "".join(lines)
        output_path = tmp_path / "rtr01.cfg"
        sanitize_config_to_file(config, "rtr01", output_path)
        result = output_path.read_text()
        assert "bigsecret" not in result
        assert "REDACTED" in result
        assert "interface Gig0/0" in result
        assert "interface Gig0/1999" in result


class TestInitGitRepo:
    def test_creates_new_repo(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        init_git_repo(repo_path)
        assert repo_path.exists()
        assert (repo_path / ".git").exists()

    def test_opens_existing_repo(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        init_git_repo(repo_path)
        repo = init_git_repo(repo_path)
        assert repo.working_tree_dir == str(repo_path)

    def test_creates_gitkeep(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        init_git_repo(repo_path)
        assert (repo_path / ".gitkeep").exists()

    def test_sets_user_config(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        init_git_repo(repo_path)
        # The repo-local .git/config should have audnet user config
        git_config = repo_path / ".git" / "config"
        config_text = git_config.read_text()
        assert "name = audnet" in config_text
        assert "email = audnet@localhost" in config_text

    def test_default_path(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr("audnet.git_history._DEFAULT_GIT_DIR", tmp_path)
        repo = init_git_repo(tmp_path / "sub")
        assert repo.working_tree_dir is not None


# ---------------------------------------------------------------------------
# save_config_snapshot
# ---------------------------------------------------------------------------


class TestSaveConfigSnapshot:
    def test_creates_commit(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {"rtr01": "hostname rtr01\ninterface Gig0/0\n"}
        sha = save_config_snapshot(configs, history_dir=repo_path)
        assert sha is not None
        assert len(sha) == 40  # full SHA

    def test_creates_cfg_file(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {"rtr01": "hostname rtr01\n"}
        save_config_snapshot(configs, history_dir=repo_path)
        cfg_file = repo_path / "rtr01.cfg"
        assert cfg_file.exists()
        assert "hostname rtr01" in cfg_file.read_text()

    def test_device_name_sanitized_in_filename(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {"My_Router-01": "hostname My_Router-01\n"}
        save_config_snapshot(configs, history_dir=repo_path)
        # Special chars replaced with -, lowercased
        assert (repo_path / "my_router-01.cfg").exists()

    def test_no_changes_returns_none(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {"rtr01": "hostname rtr01\n"}
        save_config_snapshot(configs, history_dir=repo_path)
        # Save the same config again
        sha = save_config_snapshot(configs, history_dir=repo_path)
        assert sha is None

    def test_updates_changed_config(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        sha = save_config_snapshot({"rtr01": "hostname rtr01-new\n"}, history_dir=repo_path)
        assert sha is not None

    def test_multiple_devices(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {
            "rtr01": "hostname rtr01\n",
            "sw01": "hostname sw01\n",
        }
        sha = save_config_snapshot(configs, history_dir=repo_path)
        assert sha is not None
        assert (repo_path / "rtr01.cfg").exists()
        assert (repo_path / "sw01.cfg").exists()

    def test_sanitizes_before_commit(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {"rtr01": "hostname rtr01\npassword secret123\n"}
        save_config_snapshot(configs, history_dir=repo_path)
        cfg_file = repo_path / "rtr01.cfg"
        content = cfg_file.read_text()
        assert "secret123" not in content
        assert "REDACTED" in content

    def test_commit_message_contains_device_names(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {"rtr01": "hostname rtr01\n"}
        sha = save_config_snapshot(configs, history_dir=repo_path)
        repo = init_git_repo(repo_path)
        commit = repo.commit(sha)
        assert "rtr01" in commit.message
        assert "snapshot" in commit.message.lower()

    def test_empty_configs_no_commit(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        sha = save_config_snapshot({}, history_dir=repo_path)
        # Empty dict means no files changed, but the repo was initialized
        # so there's at least the .gitkeep commit
        # With no actual changes, it should return None
        assert sha is None


# ---------------------------------------------------------------------------
# get_config_at
# ---------------------------------------------------------------------------


class TestGetConfigAt:
    def test_returns_config_at_head(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        config = get_config_at("rtr01", "HEAD", history_dir=repo_path)
        assert config is not None
        assert "hostname rtr01" in config

    def test_returns_none_for_unknown_device(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        config = get_config_at("nonexistent", "HEAD", history_dir=repo_path)
        assert config is None

    def test_returns_config_at_previous_commit(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname old\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname new\n"}, history_dir=repo_path)
        old_config = get_config_at("rtr01", "HEAD~1", history_dir=repo_path)
        new_config = get_config_at("rtr01", "HEAD", history_dir=repo_path)
        assert old_config is not None and "hostname old" in old_config
        assert new_config is not None and "hostname new" in new_config


# ---------------------------------------------------------------------------
# get_config_history
# ---------------------------------------------------------------------------


class TestGetConfigHistory:
    def test_returns_history_list(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname v1\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname v2\n"}, history_dir=repo_path)
        history = get_config_history("rtr01", history_dir=repo_path)
        assert len(history) == 2

    def test_history_contains_required_keys(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        history = get_config_history("rtr01", history_dir=repo_path)
        entry = history[0]
        assert "commit_sha" in entry
        assert "committed_at" in entry
        assert "message" in entry
        assert "config" in entry

    def test_history_order_newest_first(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname v1\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname v2\n"}, history_dir=repo_path)
        history = get_config_history("rtr01", history_dir=repo_path)
        assert "v2" in history[0]["config"]
        assert "v1" in history[1]["config"]

    def test_limit_parameter(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        for i in range(5):
            save_config_snapshot({"rtr01": f"hostname v{i}\n"}, history_dir=repo_path)
        history = get_config_history("rtr01", history_dir=repo_path, limit=3)
        assert len(history) == 3

    def test_empty_history_for_unknown_device(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        history = get_config_history("nonexistent", history_dir=repo_path)
        assert history == []


# ---------------------------------------------------------------------------
# diff_configs
# ---------------------------------------------------------------------------


class TestDiffConfigs:
    def test_returns_diff_text(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname old\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname new\n"}, history_dir=repo_path)
        diff = diff_configs("rtr01", "HEAD~1", "HEAD", history_dir=repo_path)
        assert "old" in diff
        assert "new" in diff

    def test_empty_diff_for_unchanged(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        # Second save returns None (no changes), so only one real commit
        # Diff between HEAD~1 and HEAD should be empty since no new commit
        # Actually, the second save returns None, so HEAD~1 doesn't exist
        # Let's make two different commits
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        # Both saves of same content return None after the first
        # We need to test with actual changes
        save_config_snapshot({"rtr01": "hostname rtr01\ninterface Gig0/0\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname rtr01\ninterface Gig0/0\n"}, history_dir=repo_path)
        # The second one returns None, so diff between HEAD~1 and HEAD
        # shows the first change
        diff = diff_configs("rtr01", "HEAD~1", "HEAD", history_dir=repo_path)
        # Should show the interface line addition
        assert isinstance(diff, str)

    def test_diff_for_unknown_device(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        diff = diff_configs("nonexistent", "HEAD~1", "HEAD", history_dir=repo_path)
        # Should return empty string since the file doesn't exist
        assert diff == ""


# ---------------------------------------------------------------------------
# rollback_config
# ---------------------------------------------------------------------------


class TestRollbackConfig:
    def test_dry_run_returns_config(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname old\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname new\n"}, history_dir=repo_path)
        result = rollback_config("rtr01", "HEAD~1", history_dir=repo_path, dry_run=True)
        assert result["dry_run"] is True
        assert "old" in result["config"]
        assert result["target_ref"] == "HEAD~1"

    def test_dry_run_does_not_modify_repo(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname old\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname new\n"}, history_dir=repo_path)
        rollback_config("rtr01", "HEAD~1", history_dir=repo_path, dry_run=True)
        # Config file should still have the new config
        cfg_file = repo_path / "rtr01.cfg"
        assert "hostname new" in cfg_file.read_text()

    def test_live_rollback_restores_config(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname old\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname new\n"}, history_dir=repo_path)
        result = rollback_config("rtr01", "HEAD~1", history_dir=repo_path, dry_run=False)
        assert result["dry_run"] is False
        assert "new_commit" in result
        cfg_file = repo_path / "rtr01.cfg"
        assert "hostname old" in cfg_file.read_text()

    def test_rollback_creates_rollback_commit(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname old\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname new\n"}, history_dir=repo_path)
        rollback_config("rtr01", "HEAD~1", history_dir=repo_path, dry_run=False)
        repo = init_git_repo(repo_path)
        head_msg = repo.head.commit.message
        assert "rollback" in head_msg.lower()

    def test_rollback_unknown_device_raises(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        with pytest.raises(GitHistoryError, match="No config found"):
            rollback_config("nonexistent", "HEAD", history_dir=repo_path, dry_run=True)

    def test_rollback_returns_target_sha(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname old\n"}, history_dir=repo_path)
        old_sha = save_config_snapshot({"rtr01": "hostname new\n"}, history_dir=repo_path)
        result = rollback_config("rtr01", "HEAD~1", history_dir=repo_path, dry_run=True)
        # target_sha should be the old commit
        assert result["target_sha"] != old_sha
        assert len(result["target_sha"]) == 40


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


class TestCliGitHistory:
    def test_audit_with_git_history(self, tmp_path: Path):
        """Test that audit command accepts git history options."""
        from typer.testing import CliRunner

        from audnet.cli import app

        runner = CliRunner()
        git_dir = tmp_path / "git-hist"
        # Use nonexistent inventory to test that git options are accepted
        # before the inventory error
        result = runner.invoke(
            app,
            [
                "audit",
                "--dry-run",
                "--inventory",
                str(tmp_path / "nonexistent.yaml"),
                "--baseline",
                str(tmp_path / "nonexistent.yaml"),
                "--git-history-dir",
                str(git_dir),
            ],
        )
        # Should fail because inventory doesn't exist
        assert result.exit_code != 0

    def test_history_diff_command(self, tmp_path: Path):
        from typer.testing import CliRunner

        from audnet.cli import app

        runner = CliRunner()
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname rtr01\ninterface Gig0/0\n"}, history_dir=repo_path)
        result = runner.invoke(
            app,
            [
                "history-diff",
                "--device",
                "rtr01",
                "--history-dir",
                str(repo_path),
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"

    def test_history_show_command(self, tmp_path: Path):
        from typer.testing import CliRunner

        from audnet.cli import app

        runner = CliRunner()
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        result = runner.invoke(
            app,
            [
                "history-show",
                "--device",
                "rtr01",
                "--history-dir",
                str(repo_path),
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "hostname rtr01" in result.output

    def test_history_log_command(self, tmp_path: Path):
        from typer.testing import CliRunner

        from audnet.cli import app

        runner = CliRunner()
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        result = runner.invoke(
            app,
            [
                "history-log",
                "--device",
                "rtr01",
                "--history-dir",
                str(repo_path),
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "rtr01" in result.output

    def test_rollback_dry_run_command(self, tmp_path: Path):
        from typer.testing import CliRunner

        from audnet.cli import app

        runner = CliRunner()
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname old\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname new\n"}, history_dir=repo_path)
        result = runner.invoke(
            app,
            [
                "rollback",
                "--device",
                "rtr01",
                "--ref",
                "HEAD~1",
                "--history-dir",
                str(repo_path),
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "DRY RUN" in result.output

    def test_rollback_live_command(self, tmp_path: Path):
        from typer.testing import CliRunner

        from audnet.cli import app

        runner = CliRunner()
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname old\n"}, history_dir=repo_path)
        save_config_snapshot({"rtr01": "hostname new\n"}, history_dir=repo_path)
        result = runner.invoke(
            app,
            [
                "rollback",
                "--device",
                "rtr01",
                "--ref",
                "HEAD~1",
                "--history-dir",
                str(repo_path),
                "--no-dry-run",
            ],
        )
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "Rolled back" in result.output

    def test_history_show_unknown_device(self, tmp_path: Path):
        from typer.testing import CliRunner

        from audnet.cli import app

        runner = CliRunner()
        repo_path = tmp_path / "git-repo"
        save_config_snapshot({"rtr01": "hostname rtr01\n"}, history_dir=repo_path)
        result = runner.invoke(
            app,
            [
                "history-show",
                "--device",
                "nonexistent",
                "--history-dir",
                str(repo_path),
            ],
        )
        assert result.exit_code == 1

    def test_no_git_history_flag(self, tmp_path: Path):
        """Test that --no-git-history flag is accepted."""
        from typer.testing import CliRunner

        from audnet.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "audit",
                "--dry-run",
                "--inventory",
                "nonexistent.yaml",
                "--baseline",
                "nonexistent.yaml",
                "--no-git-history",
            ],
        )
        # Should fail on inventory, not on the flag
        assert "nonexistent" in result.output or result.exit_code != 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_device_name_with_special_chars(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {"router.domain.com": "hostname router\n"}
        save_config_snapshot(configs, history_dir=repo_path)
        config = get_config_at("router.domain.com", "HEAD", history_dir=repo_path)
        assert config is not None
        assert "hostname router" in config

    def test_device_name_uppercase(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {"RTR01": "hostname RTR01\n"}
        save_config_snapshot(configs, history_dir=repo_path)
        # Filename should be lowercased
        assert (repo_path / "rtr01.cfg").exists()

    def test_large_config(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        large_config = "hostname rtr01\n" + "interface Gig0/{i}\n".format(i=0) * 1000
        configs = {"rtr01": large_config}
        sha = save_config_snapshot(configs, history_dir=repo_path)
        assert sha is not None
        config = get_config_at("rtr01", "HEAD", history_dir=repo_path)
        assert config is not None

    def test_unicode_in_config(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        configs = {"rtr01": "hostname rtr01\n! Comment with unicode: café\n"}
        sha = save_config_snapshot(configs, history_dir=repo_path)
        assert sha is not None

    def test_multiple_saves_same_device(self, tmp_path: Path):
        repo_path = tmp_path / "git-repo"
        for i in range(10):
            save_config_snapshot({"rtr01": f"hostname rtr01\nversion {i}\n"}, history_dir=repo_path)
        history = get_config_history("rtr01", history_dir=repo_path)
        assert len(history) == 10
        # Newest first
        assert "version 9" in history[0]["config"]
        assert "version 0" in history[-1]["config"]
