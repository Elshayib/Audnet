"""Report generator — renders audit results to Markdown and HTML."""

import logging
from datetime import datetime, timezone
from importlib.resources import files

from jinja2 import Environment, BaseLoader

from net_audit.models import AuditReport

logger = logging.getLogger(__name__)

_TEMPLATE_PACKAGE = files("net_audit.templates")


def _load_template(name: str) -> str:
    return (_TEMPLATE_PACKAGE / name).read_text()


_jinja = Environment(loader=BaseLoader())

_md_source = _load_template("audit_report.md.j2")
_html_source = _load_template("audit_report.html.j2")


def render_markdown(reports: list[AuditReport]) -> str:
    template = _jinja.from_string(_md_source)
    return template.render(
        reports=reports,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def render_html(reports: list[AuditReport]) -> str:
    template = _jinja.from_string(_html_source)
    return template.render(
        reports=reports,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
