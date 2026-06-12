import os
import pytest
from audnet.config import load_inventory, load_baseline, _is_plaintext
from audnet.exceptions import ConfigError


class TestLoadInventory:
    def test_loads_devices(self, tmp_path):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
defaults:
  device_type: cisco_ios
  port: 22
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: secret
""")
        defaults, devices = load_inventory(str(inv))
        assert len(devices) == 1
        assert devices[0].name == "rtr01"

    def test_env_var_resolution(self, tmp_path):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: "${MY_PASS}"
""")
        os.environ["MY_PASS"] = "resolved_secret"
        try:
            _, devices = load_inventory(str(inv))
            assert devices[0].get_password() == "resolved_secret"
        finally:
            del os.environ["MY_PASS"]

    def test_file_not_found_raises_config_error(self):
        with pytest.raises(ConfigError, match="not found"):
            load_inventory("/nonexistent/path.yaml")

    def test_invalid_yaml_raises_config_error(self, tmp_path):
        inv = tmp_path / "bad.yaml"
        inv.write_text("{{invalid yaml content")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_inventory(str(inv))

    def test_non_dict_yaml_raises_config_error(self, tmp_path):
        inv = tmp_path / "list.yaml"
        inv.write_text("- just\n- a\n- list\n")
        with pytest.raises(ConfigError, match="mapping"):
            load_inventory(str(inv))


class TestLoadBaseline:
    def test_loads_checks(self, tmp_path):
        bl = tmp_path / "baseline.yaml"
        bl.write_text("""
checks:
  ssh_v2_only:
    description: "SSHv2 must be enabled"
    severity: critical
    rule: ssh_v2_only
""")
        baseline = load_baseline(str(bl))
        assert "ssh_v2_only" in baseline["checks"]
        assert baseline["checks"]["ssh_v2_only"]["rule"] == "ssh_v2_only"

    def test_invalid_schema_raises_config_error(self, tmp_path):
        """Missing required fields (description, rule) raise ConfigError."""
        bl = tmp_path / "bad.yaml"
        bl.write_text("""
checks:
  bad_check:
    severity: critical
""")
        with pytest.raises(ConfigError, match="Invalid baseline schema"):
            load_baseline(str(bl))

    def test_file_not_found_raises_config_error(self):
        with pytest.raises(ConfigError, match="not found"):
            load_baseline("/nonexistent/baseline.yaml")

    def test_invalid_yaml_raises_config_error(self, tmp_path):
        bl = tmp_path / "bad.yaml"
        bl.write_text("{{invalid yaml content")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_baseline(str(bl))

    def test_non_dict_yaml_raises_config_error(self, tmp_path):
        bl = tmp_path / "list.yaml"
        bl.write_text("- just\n- a\n- list\n")
        with pytest.raises(ConfigError, match="mapping"):
            load_baseline(str(bl))


class TestIsPlaintext:
    def test_plain_string_is_plaintext(self):
        assert _is_plaintext("supersecret") is True

    def test_env_var_reference_is_not_plaintext(self):
        assert _is_plaintext("${AUDNET_PASSWORD}") is False

    def test_empty_string_is_not_plaintext(self):
        assert _is_plaintext("") is False

    def test_resolved_env_var_is_plaintext(self):
        """After resolution, the value is plaintext (env var was substituted)."""
        assert _is_plaintext("resolved_value") is True


class TestStrictMode:
    def test_strict_raises_on_plaintext_password(self, tmp_path):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: supersecret
""")
        with pytest.raises(ConfigError, match="Plaintext secrets"):
            load_inventory(str(inv), strict=True)

    def test_strict_passes_with_env_var_password(self, tmp_path):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: "${AUDNET_PASSWORD}"
""")
        os.environ["AUDNET_PASSWORD"] = "resolved"
        try:
            _, devices = load_inventory(str(inv), strict=True)
            assert len(devices) == 1
        finally:
            del os.environ["AUDNET_PASSWORD"]

    def test_non_strict_warns_on_plaintext_password(self, tmp_path, caplog):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: supersecret
""")
        with caplog.at_level("WARNING"):
            _, devices = load_inventory(str(inv), strict=False)
        assert len(devices) == 1
        assert "Plaintext secrets" in caplog.text

    def test_strict_multiple_devices_plaintext(self, tmp_path):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: secret1
  - name: rtr02
    host: 10.0.0.2
    username: admin
    password: secret2
""")
        with pytest.raises(ConfigError, match="rtr01 \\(password\\), rtr02 \\(password\\)"):
            load_inventory(str(inv), strict=True)

    def test_strict_mixed_plaintext_and_env_var(self, tmp_path):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: "${AUDNET_PASSWORD}"
  - name: rtr02
    host: 10.0.0.2
    username: admin
    password: plaintext_secret
""")
        os.environ["AUDNET_PASSWORD"] = "resolved"
        try:
            with pytest.raises(ConfigError, match="rtr02"):
                load_inventory(str(inv), strict=True)
        finally:
            del os.environ["AUDNET_PASSWORD"]

    def test_strict_no_password_field(self, tmp_path):
        """Devices without a password field should not trigger strict mode."""
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    use_keys: true
""")
        _, devices = load_inventory(str(inv), strict=True)
        assert len(devices) == 1


class TestStrictModeSecretField:
    """Strict mode checks password, secret, passwd, and token fields."""

    def test_strict_raises_on_plaintext_secret(self, tmp_path):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: ${DEVICE_PASSWORD}
    secret: mySuperSecretEnablePass
""")
        with pytest.raises(ConfigError, match="rtr01 \\(secret\\)"):
            load_inventory(str(inv), strict=True)

    def test_strict_raises_on_plaintext_passwd(self, tmp_path):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: ${DEVICE_PASSWORD}
    passwd: some_plaintext_passwd
""")
        with pytest.raises(ConfigError, match="rtr01 \\(passwd\\)"):
            load_inventory(str(inv), strict=True)

    def test_non_strict_warns_on_plaintext_secret(self, tmp_path, caplog):
        inv = tmp_path / "devices.yaml"
        inv.write_text("""
devices:
  - name: rtr01
    host: 10.0.0.1
    username: admin
    password: ${DEVICE_PASSWORD}
    secret: mySuperSecretEnablePass
""")
        with caplog.at_level("WARNING"):
            _, devices = load_inventory(str(inv), strict=False)
        assert len(devices) == 1
        assert "Plaintext secrets" in caplog.text
        assert "rtr01 (secret)" in caplog.text
