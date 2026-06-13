import pytest
from audnet.models import Device


@pytest.fixture(autouse=True)
def _clean_default_history(tmp_path, monkeypatch):
    """Isolate each test from the default ~/.net-audit/history.db.

    Tests that explicitly pass --history-dir manage their own DB.
    All others get a fresh temp dir so history from one test never
    leaks into the next.
    """
    hist = tmp_path / "default_history"
    hist.mkdir(exist_ok=True)
    monkeypatch.setattr("audnet.history._DEFAULT_HISTORY_DIR", hist)


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
