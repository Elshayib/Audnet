"""Report generator — renders audit results to Markdown and HTML."""

import logging
from datetime import datetime, timezone
from importlib.resources import files

from jinja2 import Environment, BaseLoader

from net_audit.exceptions import ReportError
from net_audit.models import AuditReport

logger = logging.getLogger(__name__)

_TEMPLATE_PACKAGE = files("net_audit.templates")


def _load_template(name: str) -> str:
    path = _TEMPLATE_PACKAGE / name
    try:
        return path.read_text()
    except (FileNotFoundError, OSError) as exc:
        raise ReportError(
            f"Template '{name}' not found — is net-audit correctly installed? "
            f"Try: uv pip install -e ."
        ) from exc


_jinja = Environment(loader=BaseLoader(), autoescape=True)

_md_source: str | None = None
_html_source: str | None = None


def _get_md_source() -> str:
    global _md_source
    if _md_source is None:
        _md_source = _load_template("audit_report.md.j2")
    return _md_source


def _get_html_source() -> str:
    global _html_source
    if _html_source is None:
        _html_source = _load_template("audit_report.html.j2")
    return _html_source


def render_markdown(reports: list[AuditReport]) -> str:
    template = _jinja.from_string(_get_md_source())
    return template.render(
        reports=reports,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def render_html(reports: list[AuditReport]) -> str:
    template = _jinja.from_string(_get_html_source())
    return template.render(
        reports=reports,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
