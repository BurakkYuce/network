from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from netauto.audit.log import AuditLog
from netauto.collector.runner import Collector, CollectorError
from netauto.inventory import load_testbed
from netauto.settings import settings
from netauto.state.store import StateStore

app = typer.Typer(
    name="netauto",
    help="Cisco network drift detection — blue-team platform.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

inventory_app = typer.Typer(help="Inventory commands.", no_args_is_help=True)
state_app = typer.Typer(help="State commands.", no_args_is_help=True)
app.add_typer(inventory_app, name="inventory")
app.add_typer(state_app, name="state")

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


if __name__ == "__main__":
    app()
