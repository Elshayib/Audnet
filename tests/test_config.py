import os
import pytest
from net_audit.config import load_inventory, load_baseline


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
            assert devices[0].password == "resolved_secret"
        finally:
            del os.environ["MY_PASS"]


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
