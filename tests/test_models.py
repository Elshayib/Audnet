import pytest
from pydantic import ValidationError
from audnet.models import Device, ComplianceResult, AuditReport, ParsedVersion


class TestDevice:
    def test_valid_device(self):
        d = Device(
            name="rtr01",
            host="10.0.0.1",
            device_type="cisco_ios",
            username="admin",
            password="s3cret",
        )
        assert d.name == "rtr01"
        assert d.port == 22

    def test_invalid_port(self):
        with pytest.raises(ValidationError):
            Device(
                name="rtr01",
                host="10.0.0.1",
                device_type="cisco_ios",
                username="admin",
                password="x",
                port=0,
            )

    def test_password_is_secret_str(self):
        d = Device(name="rtr01", host="10.0.0.1", password="s3cret")
        assert d.password.get_secret_value() == "s3cret"
        # SecretStr should not expose the password in repr
        assert "s3cret" not in repr(d.password)

    def test_get_password(self):
        d = Device(name="rtr01", host="10.0.0.1", password="s3cret")
        assert d.get_password() == "s3cret"

    def test_host_validation_rejects_empty(self):
        with pytest.raises(ValidationError):
            Device(name="rtr01", host="", password="x")

    def test_host_validation_rejects_spaces(self):
        with pytest.raises(ValidationError):
            Device(name="rtr01", host="has spaces", password="x")

    def test_host_validation_accepts_ip(self):
        d = Device(name="rtr01", host="192.168.1.1", password="x")
        assert d.host == "192.168.1.1"

    def test_host_validation_accepts_fqdn(self):
        d = Device(name="rtr01", host="router1.example.com", password="x")
        assert d.host == "router1.example.com"

    def test_host_validation_accepts_localhost(self):
        d = Device(name="rtr01", host="localhost", password="x")
        assert d.host == "localhost"

    def test_host_validation_accepts_short_hostname(self):
        d = Device(name="rtr01", host="router1", password="x")
        assert d.host == "router1"

    def test_host_validation_rejects_special_chars(self):
        with pytest.raises(ValidationError):
            Device(name="rtr01", host="router1;rm -rf", password="x")

    def test_host_validation_accepts_ipv6(self):
        d = Device(name="rtr01", host="::1", password="x")
        assert d.host == "::1"

    def test_ssh_key_defaults(self):
        d = Device(name="rtr01", host="10.0.0.1", password="x")
        assert d.use_keys is False
        assert d.key_file is None

    def test_ssh_key_with_key_file(self):
        d = Device(
            name="rtr01",
            host="10.0.0.1",
            username="admin",
            use_keys=True,
            key_file="/home/user/.ssh/id_ed25519",
        )
        assert d.use_keys is True
        assert d.key_file == "/home/user/.ssh/id_ed25519"

    def test_ssh_key_without_key_file(self):
        d = Device(
            name="rtr01",
            host="10.0.0.1",
            username="admin",
            use_keys=True,
        )
        assert d.use_keys is True
        assert d.key_file is None


class TestComplianceResult:
    def test_result_pass(self):
        r = ComplianceResult(
            check_name="ssh_v2_only", passed=True, severity="critical", detail="SSHv2 enabled"
        )
        assert r.passed is True

    def test_result_fail(self):
        r = ComplianceResult(
            check_name="inactive_ports", passed=False, severity="high", detail="Gi0/3 in VLAN 999"
        )
        assert r.passed is False


class TestAuditReport:
    def test_report_counts(self):
        report = AuditReport(
            device_name="rtr01",
            overall_pass=True,
            checks=[
                ComplianceResult(
                    check_name="ssh_v2_only", passed=True, severity="critical", detail="OK"
                ),
                ComplianceResult(
                    check_name="inactive_ports", passed=True, severity="high", detail="OK"
                ),
            ],
        )
        assert report.pass_count == 2
        assert report.fail_count == 0

    def test_report_fail_overall(self):
        report = AuditReport(
            device_name="rtr01",
            overall_pass=False,
            checks=[
                ComplianceResult(
                    check_name="ssh_v2_only", passed=False, severity="critical", detail="SSHv1 only"
                ),
                ComplianceResult(
                    check_name="inactive_ports", passed=True, severity="high", detail="OK"
                ),
            ],
        )
        assert report.pass_count == 1
        assert report.fail_count == 1


class TestParsedVersion:
    def test_extra_fields_ignored(self):
        """Extra TextFSM fields (e.g. model, platform) must not crash."""
        v = ParsedVersion(
            version="15.2(4)",
            hostname="router",
            uptime="5 days",
            serial="ABC123",
            raw="test",
            model="C9300",
            platform="IOS-XE",
        )
        assert v.version == "15.2(4)"
        assert v.hostname == "router"
        assert v.serial == "ABC123"
