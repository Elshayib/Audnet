"""CLI entry point for audnet."""

import json
import logging
from pathlib import Path
from typing import Any

import structlog
import typer
from rich.console import Console
from rich.table import Table

from audnet import __version__
from audnet.collector import collect_all
from audnet.compliance import run_checks
from audnet.config import load_inventory, load_baseline
from audnet.models import AuditReport
from audnet.reporter import render_markdown, render_html
from audnet.history import save_run, diff_runs, get_runs
from audnet.remediate import RemediationStatus

# Async collector is imported lazily to avoid requiring asyncssh unless --async is used.
_collect_all_async = None

app = typer.Typer(help="Network Security & Compliance State Auditor")
console = Console()
logger = structlog.get_logger("audnet")

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
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Fail if any device has a plaintext password (no ${ENV_VAR} reference)",
    ),
    no_fail: bool = typer.Option(
        False,
        "--no-fail",
        help="Always exit 0 even on compliance failures (informational mode)",
    ),
    async_mode: bool = typer.Option(
        False,
        "--async",
        help="Use asyncio-based SSH collector (recommended for >20 devices)",
    ),
    connect_timeout: int = typer.Option(
        30,
        "--connect-timeout",
        help="SSH connection timeout in seconds",
    ),
    timeout: float | None = typer.Option(
        None,
        "--timeout",
        help="Per-device collection wall-clock timeout in seconds (None = no limit)",
    ),
    history_dir: Path | None = typer.Option(
        None,
        "--history-dir",
        help="Directory for the SQLite history DB (default: ~/.net-audit)",
    ),
    no_history: bool = typer.Option(
        False,
        "--no-history",
        help="Skip writing audit results to the history database",
    ),
    no_drift: bool = typer.Option(
        False,
        "--no-drift",
        help="Skip drift/regression detection between audit runs",
    ),
    git_history_dir: Path | None = typer.Option(
        None,
        "--git-history-dir",
        help="Directory for Git-backed config history (default: ~/.net-audit/git-config-history)",
    ),
    no_git_history: bool = typer.Option(
        False,
        "--no-git-history",
        help="Skip Git-backed config snapshot commits",
    ),
    git_push: bool = typer.Option(
        False,
        "--git-push",
        help="Push Git config history to remote after committing (requires remote to be configured)",
    ),
) -> None:
    """Run a full compliance audit against all (or filtered) devices.

    Supports device/check filters, JSON output, dry-run mode, and strict secret handling for CI/automation.
    """
    _setup_logging(verbose)
    console.print(f"[bold blue]audnet v{__version__} — Starting audit...[/bold blue]")

    _, devices = load_inventory(inventory, strict=strict)
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

    # Apply SSH connection timeout to each device before collection
    for d in devices:
        d.timeout = connect_timeout

    # Collect with status
    console.print("[yellow]Collecting device data...[/yellow]")
    if async_mode:
        import asyncio

        global _collect_all_async
        if _collect_all_async is None:
            from audnet.collector_async import collect_all_async

            _collect_all_async = collect_all_async
        snapshots = asyncio.run(_collect_all_async(devices, max_workers=workers, timeout=timeout))
    else:
        snapshots = collect_all(devices, max_workers=workers, timeout=timeout)

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

    # Drift detection (before saving current run, so we compare against prior state)
    has_new_regressions = False
    if not no_drift and not no_history:
        try:
            drift = diff_runs(reports, history_dir=history_dir)
            new_failures = drift["new_failures"]
            resolved = drift["resolved"]
            unchanged = drift["unchanged"]
            if new_failures or resolved or unchanged:
                drift_table = Table(title="Drift / Regression Detection")
                drift_table.add_column("Status")
                drift_table.add_column("Device")
                drift_table.add_column("Check")
                for entry in new_failures:
                    drift_table.add_row("[red]NEW FAILURE[/red]", entry["device"], entry["check"])
                for entry in resolved:
                    drift_table.add_row("[green]RESOLVED[/green]", entry["device"], entry["check"])
                for entry in unchanged:
                    drift_table.add_row("[dim]UNCHANGED[/dim]", entry["device"], entry["check"])
                console.print(drift_table)
            if new_failures:
                has_new_regressions = True
        except Exception as exc:
            logger.warning("Failed to compute drift: %s", exc)

    # Save to history (after drift detection so current run isn't its own baseline)
    if not no_history:
        try:
            save_run(reports, history_dir=history_dir)
        except Exception as exc:
            logger.warning("Failed to save audit history: %s", exc)

    # Git-backed config snapshot
    if not no_git_history:
        try:
            from audnet.git_history import save_config_snapshot

            device_configs = {
                snap.device_name: snap.config.raw
                for snap in snapshots
                if not snap.collection_error and snap.config.raw
            }
            if device_configs:
                commit_sha = save_config_snapshot(
                    device_configs,
                    history_dir=git_history_dir,
                    push=git_push,
                )
                if commit_sha:
                    console.print(
                        f"[green]Git config snapshot: {commit_sha[:12]}[/green]"
                    )
                else:
                    console.print("[dim]No config changes to commit to Git history[/dim]")
        except Exception as exc:
            logger.warning("Failed to save Git config history: %s", exc)

    if has_new_regressions:
        raise typer.Exit(code=2)

    if not no_fail and reports and not all(r.overall_pass for r in reports):
        raise typer.Exit(code=1)


@app.command()
def history(
    device: str | None = typer.Option(None, "--device", help="Filter to a single device by name"),
    last: int = typer.Option(20, "--last", help="Show last N runs"),
    since: str | None = typer.Option(
        None, "--since", help="Show runs from last N days/hours (e.g. 7d, 24h)"
    ),
    status: str | None = typer.Option(None, "--status", help="Filter by status: pass or fail"),
    format: str = typer.Option("table", "--format", help="Output format: table or json"),
    history_dir: Path | None = typer.Option(
        None,
        "--history-dir",
        help="Directory for the SQLite history DB (default: ~/.net-audit)",
    ),
) -> None:
    """Query audit history from the SQLite store.

    Shows past audit runs with optional filtering by device, time window, and status.
    """
    runs = get_runs(
        device_name=device,
        history_dir=history_dir,
        limit=last,
        since=since,
        status=status,
    )

    if not runs:
        console.print("[yellow]No history records found[/yellow]")
        return

    if format == "json":
        console.print_json(json.dumps(runs))
        return

    table = Table(title="Audit History")
    table.add_column("ID", style="dim")
    table.add_column("Timestamp")
    table.add_column("Device")
    table.add_column("Status")
    table.add_column("Checks", style="dim")
    for run in runs:
        status_str = "[green]PASS[/green]" if run["overall_pass"] else "[red]FAIL[/red]"
        check_count = len(run.get("checks", []))
        fail_count = sum(1 for c in run.get("checks", []) if not c.get("passed", True))
        checks_str = f"{check_count - fail_count}/{check_count} passed"
        table.add_row(
            str(run["id"]),
            run["run_at"],
            run["device_name"],
            status_str,
            checks_str,
        )
    console.print(table)


@app.command(name="history-diff")
def history_diff(
    device: str = typer.Option(..., "--device", help="Device name"),
    from_ref: str = typer.Option("HEAD~1", "--from", help="Older Git ref (default: HEAD~1)"),
    to_ref: str = typer.Option("HEAD", "--to", help="Newer Git ref (default: HEAD)"),
    history_dir: Path | None = typer.Option(
        None,
        "--history-dir",
        help="Git config history directory (default: ~/.net-audit/git-config-history)",
    ),
) -> None:
    """Show Git diff between two config snapshots for a device.

    Requires Git-backed config history to be enabled (run at least one audit
    without --no-git-history).
    """
    from audnet.git_history import diff_configs

    diff_text = diff_configs(
        device_name=device,
        from_ref=from_ref,
        to_ref=to_ref,
        history_dir=history_dir,
    )
    if diff_text:
        console.print(diff_text)
    else:
        console.print(f"[yellow]No changes for '{device}' between {from_ref} and {to_ref}[/yellow]")


@app.command(name="history-show")
def history_show(
    device: str = typer.Option(..., "--device", help="Device name"),
    commit_ref: str = typer.Option("HEAD", "--ref", help="Git ref to show (default: HEAD)"),
    history_dir: Path | None = typer.Option(
        None,
        "--history-dir",
        help="Git config history directory (default: ~/.net-audit/git-config-history)",
    ),
) -> None:
    """Show a device's config at a specific Git ref."""
    from audnet.git_history import get_config_at

    config = get_config_at(
        device_name=device,
        commit_ref=commit_ref,
        history_dir=history_dir,
    )
    if config is None:
        console.print(
            f"[red]No config found for '{device}' at ref '{commit_ref}'[/red]"
        )
        raise typer.Exit(code=1)
    console.print(config)


@app.command(name="history-log")
def history_log(
    device: str = typer.Option(..., "--device", help="Device name"),
    limit: int = typer.Option(20, "--limit", help="Max number of commits to show"),
    history_dir: Path | None = typer.Option(
        None,
        "--history-dir",
        help="Git config history directory (default: ~/.net-audit/git-config-history)",
    ),
) -> None:
    """Show Git commit history for a device's config."""
    from audnet.git_history import get_config_history

    entries = get_config_history(
        device_name=device,
        history_dir=history_dir,
        limit=limit,
    )
    if not entries:
        console.print(f"[yellow]No Git config history for '{device}'[/yellow]")
        return

    table = Table(title=f"Config History — {device}")
    table.add_column("Commit", style="dim")
    table.add_column("Timestamp")
    table.add_column("Message")
    for entry in entries:
        table.add_row(
            entry["commit_sha"][:12],
            entry["committed_at"],
            entry["message"].splitlines()[0] if entry["message"] else "",
        )
    console.print(table)


@app.command()
def rollback(
    device: str = typer.Option(..., "--device", help="Device name to roll back"),
    commit_ref: str = typer.Option("HEAD~1", "--ref", help="Git ref to roll back to"),
    history_dir: Path | None = typer.Option(
        None,
        "--history-dir",
        help="Git config history directory (default: ~/.net-audit/git-config-history)",
    ),
    dry_run: bool = typer.Option(
        True,
        "--dry-run/--no-dry-run",
        help="Preview the rollback without writing (default: dry-run)",
    ),
    push: bool = typer.Option(
        False,
        "--push",
        help="Push to remote after committing rollback (requires remote to be configured)",
    ),
) -> None:
    """Roll back a device's config to a previous Git commit.

    By default runs in dry-run mode showing what would be restored.
    Use --no-dry-run to actually write the config and commit.
    """
    from audnet.git_history import rollback_config

    result = rollback_config(
        device_name=device,
        commit_ref=commit_ref,
        history_dir=history_dir,
        push=push,
        dry_run=dry_run,
    )

    if dry_run:
        console.print(
            f"[bold yellow]DRY RUN — would rollback {device} to {commit_ref} "
            f"({result['target_sha'][:12]})[/bold yellow]"
        )
        console.print("[dim]Use --no-dry-run to apply the rollback[/dim]")
        console.print("\n[bold]Config preview:[/bold]")
        console.print(result["config"][:500] + ("..." if len(result["config"]) > 500 else ""))
    else:
        console.print(
            f"[green]Rolled back {device} to {commit_ref} "
            f"({result['target_sha'][:12]})[/green]"
        )
        if "new_commit" in result:
            console.print(f"New commit: {result['new_commit'][:12]}")


@app.command(name="list-vendors")
def list_vendors_cmd(
    json_out: bool = typer.Option(False, "--json", help="Output JSON"),
) -> None:
    """List all registered vendor device types with descriptions."""
    from audnet.vendor_registry import list_vendors, VENDOR_PROFILES

    vendors = list_vendors()
    if json_out:
        data = [{"device_type": v, "description": VENDOR_PROFILES[v].description} for v in vendors]
        console.print_json(json.dumps(data))
    else:
        for v in vendors:
            desc = VENDOR_PROFILES[v].description or v
            console.print(f"{v:<20} — {desc}")


@app.command(name="list-checks")
def list_checks_cmd(
    json_out: bool = typer.Option(False, "--json", help="Output JSON"),
) -> None:
    """List all available compliance rule names."""
    from audnet.compliance import list_checks

    checks = list_checks()
    if json_out:
        console.print_json(json.dumps([{"rule": c} for c in checks]))
    else:
        for c in checks:
            console.print(f"{c:<20} (rule: {c})")


# ---------------------------------------------------------------------------
# Remediation — safe push with dry-run + rollback
# ---------------------------------------------------------------------------


@app.command()
def remediate(
    inventory: str = typer.Option(
        "inventories/devices.yaml",
        help="Device inventory YAML",
    ),
    config_file: str = typer.Option(
        ...,
        "--config",
        "-c",
        help="Config snippet file to apply (YAML or plain text)",
    ),
    dry_run: bool = typer.Option(
        True,
        "--dry-run/--no-dry-run",
        help="Show diff without applying (default: dry-run)",
    ),
    auto_approve: bool = typer.Option(
        False,
        "--auto-approve",
        help="Skip interactive approval (automation mode)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Apply even if config is already present (no-op)",
    ),
    device: list[str] = typer.Option(
        [],
        "--device",
        "-d",
        help="Target specific device(s). Default: all from inventory",
    ),
) -> None:
    """Apply remediation config to devices with safety guarantees.

    Safety model:
    - Always dry-run first (mandatory unless --no-dry-run)
    - Shows diff before applying
    - Requires interactive approval (unless --auto-approve)
    - Idempotent: skips if config already present
    - Automatic rollback on failure
    - Full audit logging of every action
    """
    import time as _time
    from pathlib import Path

    from audnet.remediate import remediate_devices

    # Load inventory
    inv_path = Path(inventory)
    if not inv_path.exists():
        console.print(f"[red]Inventory file not found: {inventory}[/red]")
        raise typer.Exit(1)

    _meta, all_devices = load_inventory(str(inv_path))

    # Filter to specific devices if requested
    if device:
        target_devices = [d for d in all_devices if d.name in device]
        missing = set(device) - {d.name for d in target_devices}
        if missing:
            console.print(f"[red]Device(s) not in inventory: {', '.join(missing)}[/red]")
            raise typer.Exit(1)
    else:
        target_devices = all_devices

    if not target_devices:
        console.print("[red]No devices to remediate[/red]")
        raise typer.Exit(1)

    # Load config snippet
    config_path = Path(config_file)
    if not config_path.exists():
        console.print(f"[red]Config file not found: {config_file}[/red]")
        raise typer.Exit(1)

    config_text = config_path.read_text()

    # Try YAML first (config_snippet: [...] format), fall back to plain text
    try:
        import yaml
        config_data = yaml.safe_load(config_text)
        if isinstance(config_data, dict) and "config_snippet" in config_data:
            config_snippet = config_data["config_snippet"]
            if isinstance(config_snippet, str):
                config_snippet = config_snippet.splitlines()
        elif isinstance(config_data, list):
            config_snippet = [str(line) for line in config_data]
        else:
            config_snippet = config_text.splitlines()
    except Exception:
        config_snippet = config_text.splitlines()

    console.print("[bold]Remediation Summary[/bold]")
    console.print(f"  Devices: {', '.join(d.name for d in target_devices)}")
    console.print(f"  Config lines: {len(config_snippet)}")
    console.print(f"  Mode: {'DRY RUN' if dry_run else 'LIVE'}")
    console.print()

    results = remediate_devices(
        target_devices,
        config_snippet,
        dry_run=dry_run,
        auto_approve=auto_approve,
        force=force,
    )

    # Display results
    table = Table(title="Remediation Results")
    table.add_column("Device", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Added", justify="right")
    table.add_column("Details")

    for r in results:
        status_style = {
            RemediationStatus.SUCCESS: "green",
            RemediationStatus.DRY_RUN: "yellow",
            RemediationStatus.SKIPPED: "blue",
            RemediationStatus.ROLLED_BACK: "red",
            RemediationStatus.FAILED: "red",
        }.get(r.status, "white")

        details = ""
        if r.rolled_back:
            details = f"Rolled back (error: {r.error})"
        elif r.error:
            details = r.error
        elif r.status == RemediationStatus.SKIPPED:
            details = "Already compliant (idempotent)"
        elif r.status == RemediationStatus.DRY_RUN:
            details = "Dry run — no changes made"
        else:
            details = f"Applied {len(r.diff.added_lines)} lines"

        table.add_row(
            r.device_name,
            f"[{status_style}]{r.status.value}[/{status_style}]",
            str(len(r.diff.added_lines)),
            details,
        )

    console.print(table)

    # Exit code based on results
    if any(r.status == RemediationStatus.FAILED for r in results):
        raise typer.Exit(1)

    # Audit log
    log_data = {
        "action": "remediate",
        "dry_run": dry_run,
        "timestamp": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        "results": [
            {
                "device": r.device_name,
                "status": r.status.value,
                "added": len(r.diff.added_lines),
                "rolled_back": r.rolled_back,
                "error": r.error,
                "duration_s": round(r.duration_seconds, 2),
            }
            for r in results
        ],
    }

    audit_dir = Path.home() / ".net-audit" / "remediation_logs"
    audit_dir.mkdir(parents=True, exist_ok=True)
    log_file = audit_dir / f"remediate_{int(_time.time())}.json"
    log_file.write_text(json.dumps(log_data, indent=2))
    console.print(f"\n[dim]Audit log: {log_file}[/dim]")


@app.command()
def version() -> None:
    """Show the audnet version."""
    console.print(f"audnet {__version__}")


if __name__ == "__main__":
    app()
