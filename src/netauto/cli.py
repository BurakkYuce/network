import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from netauto.audit.log import AuditLog
from netauto.audit.verify import verify_chain
from netauto.collector.runner import Collector, CollectorError
from netauto.detection.engine import EvalContext, eval_rules
from netauto.detection.rule import load_rules_from_dir
from netauto.inventory import load_testbed
from netauto.settings import settings
from netauto.state.diff import diff_states
from netauto.state.ephemeral import load_ephemeral_patterns
from netauto.state.store import StateStore

app = typer.Typer(
    name="netauto",
    help="Cisco network drift detection — blue-team platform.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

inventory_app = typer.Typer(help="Inventory commands.", no_args_is_help=True)
state_app = typer.Typer(help="State commands.", no_args_is_help=True)
audit_app = typer.Typer(help="Audit log commands.", no_args_is_help=True)
app.add_typer(inventory_app, name="inventory")
app.add_typer(state_app, name="state")
app.add_typer(audit_app, name="audit")

console = Console()


@inventory_app.command("list")
def inventory_list(
    testbed: Path | None = typer.Option(  # noqa: B008
        None, "--testbed", "-t", help="Path to testbed.yaml."
    ),
) -> None:
    """List devices from the testbed."""
    path = testbed or settings.testbed_path
    devices = load_testbed(path)

    table = Table(title=f"Inventory ({len(devices)} devices)")
    table.add_column("Hostname", style="cyan")
    table.add_column("Platform")
    table.add_column("Role")
    table.add_column("Tier", justify="right")
    table.add_column("Crit", justify="right")
    table.add_column("Site")
    table.add_column("Tags", style="dim")
    table.add_column("Maint", justify="center")

    for d in devices:
        maint_marker = "Y" if d.is_in_maintenance() else "-"
        table.add_row(
            d.hostname,
            d.platform,
            d.role,
            str(d.tier),
            str(d.criticality),
            d.site or "-",
            ",".join(d.tags) if d.tags else "-",
            maint_marker,
        )
    console.print(table)


@app.command("collect")
def collect(
    device: str = typer.Argument(..., help="Device hostname from testbed."),
    testbed: Path | None = typer.Option(  # noqa: B008
        None, "--testbed", "-t", help="Path to testbed.yaml."
    ),
    db_url: str | None = typer.Option(None, "--db-url", help="Override settings.db_url."),
) -> None:
    """Collect state from a device and persist to store + audit log."""
    path = testbed or settings.testbed_path
    devices = load_testbed(path)
    by_name = {d.hostname: d for d in devices}
    if device not in by_name:
        console.print(f"[red]device not in testbed:[/red] {device}", style="bold")
        raise typer.Exit(1)

    store = StateStore(db_url or settings.db_url, create_schema=True)
    audit = AuditLog(settings.audit_log_path)
    collector = Collector(
        store=store,
        audit=audit,
        snapshots_dir=settings.snapshots_dir,
        fixtures_dir=settings.fixtures_dir,
    )

    try:
        state, snapshot_id = collector.collect(by_name[device])
    except CollectorError as exc:
        console.print(f"[red]collect failed:[/red] {exc}", style="bold")
        raise typer.Exit(2) from exc

    console.print(
        f"[green]✓ collected[/green] device=[cyan]{device}[/cyan] "
        f"snapshot_id=[yellow]{snapshot_id}[/yellow] "
        f"schema=v{state.schema_version} "
        f"interfaces={len(state.interfaces)} "
        f"users={len(state.users)} "
        f"acls={len(state.acls)}"
    )


@state_app.command("show")
def state_show(
    device: str = typer.Argument(..., help="Device hostname."),
    db_url: str | None = typer.Option(None, "--db-url", help="Override settings.db_url."),
) -> None:
    """Print the latest state snapshot for a device as JSON."""
    store = StateStore(db_url or settings.db_url, create_schema=True)
    device_id = store.get_device_id(device)
    if device_id is None:
        console.print(f"[red]device not found:[/red] {device}")
        raise typer.Exit(1)
    state = store.latest_snapshot(device_id)
    if state is None:
        console.print(f"[yellow]no snapshot yet for:[/yellow] {device}")
        raise typer.Exit(1)
    typer.echo(state.model_dump_json(indent=2))


@state_app.command("list")
def state_list(
    device: str = typer.Argument(..., help="Device hostname."),
    db_url: str | None = typer.Option(None, "--db-url", help="Override settings.db_url."),
) -> None:
    """List snapshots for a device (newest first)."""
    store = StateStore(db_url or settings.db_url, create_schema=True)
    device_id = store.get_device_id(device)
    if device_id is None:
        console.print(f"[red]device not found:[/red] {device}")
        raise typer.Exit(1)

    snapshots = store.list_snapshots(device_id)
    if not snapshots:
        console.print(f"[yellow]no snapshots for:[/yellow] {device}")
        return

    table = Table(title=f"Snapshots for {device} ({len(snapshots)})")
    table.add_column("ID", justify="right", style="cyan")
    table.add_column("Captured at")
    table.add_column("Schema", justify="right")
    for s in snapshots:
        table.add_row(str(s.id), s.captured_at.isoformat(), str(s.schema_version))
    console.print(table)


@app.command("diff")
def diff(
    device: str = typer.Argument(..., help="Device hostname."),
    from_id: int | None = typer.Option(
        None, "--from", help="Source snapshot id (default: second-latest)."
    ),
    to_id: int | None = typer.Option(None, "--to", help="Target snapshot id (default: latest)."),
    db_url: str | None = typer.Option(None, "--db-url", help="Override settings.db_url."),
    ephemeral_file: Path | None = typer.Option(  # noqa: B008
        None, "--ephemeral", help="Path to ephemeral_paths.yaml."
    ),
    show_ops: bool = typer.Option(True, "--ops/--no-ops", help="Print JSON Patch ops to stdout."),
) -> None:
    """Show drift (RFC 6902 JSON Patch) between two state snapshots."""
    store = StateStore(db_url or settings.db_url, create_schema=True)
    device_id = store.get_device_id(device)
    if device_id is None:
        console.print(f"[red]device not found:[/red] {device}")
        raise typer.Exit(1)

    snapshots = store.list_snapshots(device_id)
    if from_id is None or to_id is None:
        if len(snapshots) < 2:
            console.print(f"[yellow]need 2+ snapshots; have {len(snapshots)} for {device}[/yellow]")
            raise typer.Exit(1)
        if from_id is None:
            from_id = snapshots[1].id
        if to_id is None:
            to_id = snapshots[0].id

    old = store.get_snapshot(from_id)
    new = store.get_snapshot(to_id)
    if old is None:
        console.print(f"[red]snapshot not found:[/red] #{from_id}")
        raise typer.Exit(1)
    if new is None:
        console.print(f"[red]snapshot not found:[/red] #{to_id}")
        raise typer.Exit(1)

    ep_path = ephemeral_file or settings.ephemeral_paths_file
    patterns = load_ephemeral_patterns(ep_path)
    result = diff_states(old, new, patterns)

    if result.is_empty:
        console.print(f"[green]no drift[/green] device={device} from=#{from_id} to=#{to_id}")
        return

    summary_parts = [f"{op}={n}" for op, n in sorted(result.summary.items())]
    console.print(
        f"[yellow]drift[/yellow] device={device} from=#{from_id} to=#{to_id} "
        f"ops={len(result.ops)} ({', '.join(summary_parts)})"
    )
    if show_ops:
        typer.echo(json.dumps(result.ops, indent=2))


@app.command("detect")
def detect(
    device: str = typer.Argument(..., help="Device hostname."),
    from_id: int | None = typer.Option(
        None, "--from", help="Source snapshot id (default: second-latest)."
    ),
    to_id: int | None = typer.Option(None, "--to", help="Target snapshot id (default: latest)."),
    rules_dir: Path | None = typer.Option(  # noqa: B008
        None, "--rules-dir", help="Directory containing rule YAMLs."
    ),
    db_url: str | None = typer.Option(None, "--db-url", help="Override settings.db_url."),
    ephemeral_file: Path | None = typer.Option(  # noqa: B008
        None, "--ephemeral", help="Path to ephemeral_paths.yaml."
    ),
) -> None:
    """Run detection rules over the diff between two snapshots."""
    store = StateStore(db_url or settings.db_url, create_schema=True)
    device_id = store.get_device_id(device)
    if device_id is None:
        console.print(f"[red]device not found:[/red] {device}")
        raise typer.Exit(1)

    snapshots = store.list_snapshots(device_id)
    if from_id is None or to_id is None:
        if len(snapshots) < 2:
            console.print(f"[yellow]need 2+ snapshots; have {len(snapshots)} for {device}[/yellow]")
            raise typer.Exit(1)
        if from_id is None:
            from_id = snapshots[1].id
        if to_id is None:
            to_id = snapshots[0].id

    old = store.get_snapshot(from_id)
    new = store.get_snapshot(to_id)
    if old is None or new is None:
        console.print("[red]snapshot not found[/red]")
        raise typer.Exit(1)

    ep_path = ephemeral_file or settings.ephemeral_paths_file
    patterns = load_ephemeral_patterns(ep_path)
    diff = diff_states(old, new, patterns)

    rules = load_rules_from_dir(rules_dir or settings.rules_dir)
    if not rules:
        console.print(f"[yellow]no rules found in[/yellow] {rules_dir or settings.rules_dir}")
        raise typer.Exit(1)

    ctx = EvalContext(device_hostname=device, timestamp=datetime.now(UTC))
    events = eval_rules(diff.ops, rules, ctx)

    audit = AuditLog(settings.audit_log_path)
    audit.append(
        "detection.evaluated",
        {
            "device": device,
            "from_snapshot_id": from_id,
            "to_snapshot_id": to_id,
            "diff_ops": len(diff.ops),
            "rules_evaluated": len(rules),
            "events_emitted": len(events),
        },
    )

    if not events:
        console.print(
            f"[green]no detections[/green] device={device} from=#{from_id} to=#{to_id} "
            f"rules={len(rules)} diff_ops={len(diff.ops)}"
        )
        return

    table = Table(title=f"Detections ({len(events)})")
    table.add_column("Rule", style="cyan")
    table.add_column("Severity")
    table.add_column("ATT&CK")
    table.add_column("Path")
    table.add_column("Op")
    table.add_column("Actions", style="dim")
    for e in events:
        attack_str = e.attack.subtechnique or e.attack.technique
        sev_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(e.severity, "white")
        table.add_row(
            e.rule_id,
            f"[{sev_color}]{e.severity}[/{sev_color}]",
            attack_str,
            e.diff_op.get("path", ""),
            e.diff_op.get("op", ""),
            ",".join(e.response_actions),
        )
        audit.append(
            "detection.event",
            {
                "rule_id": e.rule_id,
                "rule_version": e.rule_version,
                "severity": e.severity,
                "device": e.device_hostname,
                "fingerprint": e.fingerprint,
                "attack_technique": e.attack.technique,
                "attack_subtechnique": e.attack.subtechnique,
                "diff_op_path": e.diff_op.get("path"),
                "response_actions": e.response_actions,
            },
        )
    console.print(table)


@audit_app.command("verify")
def audit_verify(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", help="Path to audit.jsonl (default: settings.audit_log_path)."
    ),
) -> None:
    """Recompute and check the SHA-256 hash chain of the audit log."""
    p = path or settings.audit_log_path
    result = verify_chain(p)
    if result.ok:
        console.print(f"[green]✓ chain valid[/green] events={result.total_events} path={p}")
        return
    console.print(
        f"[red]✗ chain INVALID[/red] events={result.total_events} "
        f"issues={len(result.issues)} path={p}"
    )
    for issue in result.issues:
        console.print(f"  [red]•[/red] {issue}")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
