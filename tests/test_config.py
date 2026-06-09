import os
import pytest
from net_audit.config import load_inventory, load_baseline
from net_audit.exceptions import ConfigError


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
  ssh_version:
    severity: critical
    rule: ssh_v2_only
""")
        baseline = load_baseline(str(bl))
        assert "ssh_version" in baseline["checks"]

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
