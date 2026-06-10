from net_audit.reporter import render_markdown, render_html
from net_audit.models import AuditReport, ComplianceResult


def _make_report(name, overall, checks):
    return AuditReport(device_name=name, overall_pass=overall, checks=checks)


class TestRenderMarkdown:
    def test_contains_device_name(self):
        report = _make_report("rtr01", True, [
            ComplianceResult(check_name="ssh_v2_only", passed=True,
                             severity="critical", detail="OK"),
        ])
        md = render_markdown([report])
        assert "rtr01" in md
        assert "PASS" in md

    def test_contains_fail(self):
        report = _make_report("rtr01", False, [
            ComplianceResult(check_name="ssh_v2_only", passed=False,
                             severity="critical", detail="SSHv1 only"),
        ])
        md = render_markdown([report])
        assert "FAIL" in md


class TestRenderHtml:
    def test_contains_device_name(self):
        report = _make_report("rtr01", True, [
            ComplianceResult(check_name="ssh_v2_only", passed=True,
                             severity="critical", detail="OK"),
        ])
        html = render_html([report])
        assert "rtr01" in html
        assert "<html" in html

    def test_contains_fail_class(self):
        report = _make_report("rtr01", False, [
            ComplianceResult(check_name="ssh_v2_only", passed=False,
                             severity="critical", detail="SSHv1 only"),
        ])
        html = render_html([report])
        assert "fail" in html
