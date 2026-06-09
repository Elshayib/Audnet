"""Report generator — renders audit results to Markdown and HTML."""

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from net_audit.models import AuditReport


TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent / "templates"

_jinja = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))


def render_markdown(reports: list[AuditReport]) -> str:
    template = _jinja.get_template("audit_report.md.j2")
    return template.render(
        reports=reports,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def render_html(reports: list[AuditReport]) -> str:
    template = _jinja.get_template("audit_report.html.j2")
    return template.render(
        reports=reports,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
