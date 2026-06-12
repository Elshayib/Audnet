import pytest
from net_audit.reporter import render_markdown, render_html
from net_audit.exceptions import ReportError
from net_audit.models import AuditReport, ComplianceResult


def _make_report(name, overall, checks):
    return AuditReport(device_name=name, overall_pass=overall, checks=checks)


class TestRenderMarkdown:
    def test_contains_device_name(self):
        report = _make_report(
            "rtr01",
            True,
            [
                ComplianceResult(
                    check_name="ssh_v2_only", passed=True, severity="critical", detail="OK"
                ),
            ],
        )
        md = render_markdown([report])
        assert "rtr01" in md
        assert "PASS" in md

    def test_contains_fail(self):
        report = _make_report(
            "rtr01",
            False,
            [
                ComplianceResult(
                    check_name="ssh_v2_only", passed=False, severity="critical", detail="SSHv1 only"
                ),
            ],
        )
        md = render_markdown([report])
        assert "FAIL" in md


class TestRenderHtml:
    def test_contains_device_name(self):
        report = _make_report(
            "rtr01",
            True,
            [
                ComplianceResult(
                    check_name="ssh_v2_only", passed=True, severity="critical", detail="OK"
                ),
            ],
        )
        html = render_html([report])
        assert "rtr01" in html
        assert "<html" in html

    def test_contains_fail_class(self):
        report = _make_report(
            "rtr01",
            False,
            [
                ComplianceResult(
                    check_name="ssh_v2_only", passed=False, severity="critical", detail="SSHv1 only"
                ),
            ],
        )
        html = render_html([report])
        assert "fail" in html


class TestReportErrorHandling:
    """Template loading errors should produce ReportError, not raw FileNotFoundError."""

    def test_missing_template_raises_report_error(self, tmp_path, monkeypatch):
        """If a template file is missing, render should raise ReportError."""
        import net_audit.reporter as reporter_mod

        # Point the template package at an empty dir so templates are missing
        monkeypatch.setattr(reporter_mod, "_TEMPLATE_PACKAGE", tmp_path)
        # Reset cached sources
        reporter_mod._md_source = None
        reporter_mod._html_source = None

        from net_audit.models import AuditReport, ComplianceResult

        report = AuditReport(
            device_name="rtr01",
            overall_pass=True,
            checks=[
                ComplianceResult(
                    check_name="ssh_v2_only", passed=True, severity="critical", detail="OK"
                )
            ],
        )
        with pytest.raises(ReportError, match="not found"):
            reporter_mod.render_markdown([report])

    def test_lazy_load_does_not_crash_on_import(self):
        """Importing reporter should not crash even if templates are missing."""
        import net_audit.reporter as reporter_mod

        # If we got here without error, lazy loading works
        assert reporter_mod._md_source is None
        assert reporter_mod._html_source is None
