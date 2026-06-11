import pytest
from net_audit.models import Device


@pytest.fixture
def sample_device():
    return Device(name="rtr01", host="10.0.0.1", username="admin", password="x")


@pytest.fixture
def sample_baseline():
    return {
        "checks": {
            "ssh_v2_only": {"severity": "critical", "rule": "ssh_v2_only", "description": ""},
            "inactive_ports": {
                "severity": "high",
                "rule": "no_open_ports",
                "allowed_vlans": [10, 20],
                "description": "",
            },
            "ntp_config": {
                "severity": "medium",
                "rule": "ntp_approved",
                "approved_servers": ["10.0.0.50"],
                "description": "",
            },
            "syslog_config": {
                "severity": "medium",
                "rule": "syslog_approved",
                "approved_servers": ["10.0.0.60"],
                "description": "",
            },
        }
    }
