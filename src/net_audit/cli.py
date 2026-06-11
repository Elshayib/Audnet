"""CLI entry point for net-audit."""

import json
import logging
from pathlib import Path
from typing import Any

import structlog
import typer
from rich.console import Console
from rich.table import Table

from net_audit import __version__
from net_audit.collector import collect_all
from net_audit.compliance import run_checks
from net_audit.config import load_inventory, load_baseline
from net_audit.models import AuditReport
from net_audit.reporter import render_markdown, render_html

app = typer.Typer(help="Network Security & Compliance State Auditor")
console = Console()
logger = structlog.get_logger("net_audit")

_SECRET_KEYS = frozenset({"password", "key_file", "secret", "passwd", "token"})


def _redact_secrets(
    _logger: logging.Logger, _method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Structlog processor that redacts sensitive values from log events."""
    for key in event_dict:
        if key.lower() in _SECRET_KEYS and event_dict[key] is not None:
            event_dict[key] = "***REDACTED***"
    return event_dict


def _setup_logging(verbose: bool = False) -> None:
    """Configure structlog with JSON or console output and secret redaction."""
    level = logging.DEBUG if verbose else logging.INFO
    shared_processors: list[Any] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        _redact_secrets,
    ]
    renderer: Any
    if verbose:
        renderer = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(
        format="%(message)s",
        level=level,
    )


@app.command()
def audit(
    inventory: str = typer.Option("inventories/devices.yaml", help="Device inventory YAML"),
    baseline: str = typer.Option("baselines/security_baseline.yaml", help="Security baseline YAML"),
    output: str = typer.Option("audit_report", help="Output file prefix"),
    format: str = typer.Option("both", help="Output format: md, html, or both"),
    workers: int = typer.Option(4, help="Max parallel SSH connections"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable debug logging"),
    device: str | None = typer.Option(None, "--device", help="Filter to single device by name"),
    check: list[str] = typer.Option(
        [],
        "--check",
        help="Filter to specific checks (repeatable; supports comma-separated in one arg)",
    ),
    json_out: bool = typer.Option(False, "--json", help="Output JSON summary to stdout"),
    dry_run: bool = typer.Option(
        False,
        "-n",
        "--dry-run",
        help="Validate config and show what would be audited without connecting to devices",
    ),
) -> None:
    """Run a full compliance audit against all (or filtered) devices.

    Supports device/check filters, JSON output, and dry-run mode for CI/automation.
    """
    _setup_logging(verbose)
    console.print(f"[bold blue]net-audit v{__version__} — Starting audit...[/bold blue]")

    _, devices = load_inventory(inventory)
    baseline_data = load_baseline(baseline)

    if device:
        devices = [d for d in devices if d.name == device]
        if not devices:
            console.print(f"[red]Device '{device}' not found in inventory[/red]")
            return

    check_names = set(baseline_data.get("checks", {}).keys())
    console.print(f"Loaded {len(devices)} devices, {len(check_names)} checks")

    if dry_run:
        console.print("[bold yellow]DRY RUN — no device connections will be made[/bold yellow]")
        console.print("[yellow]Devices that would be audited:[/yellow]")
        for d in devices:
            console.print(f"  • {d.name} ({d.host}) — {d.device_type}")
        console.print("[yellow]Checks that would be run:[/yellow]")
        for name in sorted(check_names):
            console.print(f"  • {name}")
        if check:
            check_set = {c.strip() for item in check for c in item.split(",")}
            unknown = check_set - check_names
            if unknown:
                console.print(
                    f"[yellow]Warning: unknown check(s) {', '.join(sorted(unknown))} — "
                    f"available: {', '.join(sorted(check_names))}[/yellow]"
                )
        console.print("[green]Dry run complete — config and baseline are valid[/green]")
        return

    # Collect with status
    console.print("[yellow]Collecting device data...[/yellow]")
    snapshots = collect_all(devices, max_workers=workers)

    # Resolve check filter
    if check:
        check_set = {c.strip() for item in check for c in item.split(",")}
        unknown = check_set - check_names
        if unknown:
            console.print(
                f"[yellow]Warning: unknown check(s) {', '.join(sorted(unknown))} — "
                f"available: {', '.join(sorted(check_names))}[/yellow]"
            )
    else:
        check_set = set()

    # Audit
    reports = []
    for snap in snapshots:
        if snap.collection_error:
            console.print(f"[red]ERROR {snap.device_name}: {snap.collection_error}[/red]")
            reports.append(AuditReport(device_name=snap.device_name, overall_pass=False, checks=[]))
            continue

        results = run_checks(snap, baseline_data)
        if check_set:
            results = [r for r in results if r.check_name in check_set]
        overall = all(r.passed for r in results) if results else False
        reports.append(
            AuditReport(device_name=snap.device_name, overall_pass=overall, checks=results)
        )

    # Terminal summary
    table = Table(title="Audit Results")
    table.add_column("Device")
    table.add_column("Status")
    table.add_column("Passed")
    table.add_column("Failed")
    for r in reports:
        status = "[green]PASS[/green]" if r.overall_pass else "[red]FAIL[/red]"
        table.add_row(r.device_name, status, str(r.pass_count), str(r.fail_count))
    console.print(table)

    # Write reports
    if format in ("md", "both"):
        md_path = Path(f"{output}.md")
        md_path.write_text(render_markdown(reports))
        console.print(f"[green]Markdown report: {md_path}[/green]")

    if format in ("html", "both"):
        html_path = Path(f"{output}.html")
        html_path.write_text(render_html(reports))
        console.print(f"[green]HTML report: {html_path}[/green]")

    if json_out:
        json_data = [r.model_dump(mode="json") for r in reports]
        console.print_json(json.dumps(json_data))


@app.command()
def version() -> None:
    """Show the net-audit version."""
    console.print(f"net-audit {__version__}")


if __name__ == "__main__":
    app()
