"""sentryd command-line interface."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentryd import __version__
from sentryd.config import load_config
from sentryd.core.alerts import Alert, Severity
from sentryd.core.engine import RuleEngine
from sentryd.rules.base import build_rules
from sentryd.sources.base import SourceError
from sentryd.sources.pcap import PcapFileSource
from sentryd.storage.store import DEFAULT_DB_PATH, AlertStore
from sentryd.triage.base import NullTriage, TriageProvider, create_provider

app = typer.Typer(
    name="sentryd",
    help="Network anomaly detection: deterministic rules, optional AI triage.",
    no_args_is_help=True,
)
alerts_app = typer.Typer(help="Query stored alerts.", no_args_is_help=True)
app.add_typer(alerts_app, name="alerts")

console = Console()

SEVERITY_STYLE = {
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold white on red",
}

DbOption = typer.Option(DEFAULT_DB_PATH, "--db", help="SQLite database path.")
ConfigOption = typer.Option(
    None, "--config", help="Config file (defaults to ./config/signatures.yaml if present)."
)


class ConsoleSink:
    """Engine sink that prints each new alert as a severity-colored line."""

    def emit(self, alert: Alert) -> None:
        style = SEVERITY_STYLE[alert.severity]
        console.print(
            f"[{style}]{alert.severity.value.upper():>8}[/{style}] "
            f"[dim]{_fmt_ts(alert.ts)}[/dim] "
            f"[bold]{alert.rule_id}[/bold] {alert.title} "
            f"[dim](confidence {alert.confidence:.2f})[/dim]"
        )

    def update(self, alert: Alert) -> None:
        pass  # duplicate merges are reflected in storage, not re-printed


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _build_engine(config_path: Path | None, store: AlertStore) -> RuleEngine:
    config = load_config(config_path)
    return RuleEngine(
        rules=build_rules(config),
        sinks=[store, ConsoleSink()],
        cooldown_seconds=config.get("engine", {}).get("cooldown_seconds", 60),
    )


def _triage_alerts(store: AlertStore, alerts: list[Alert]) -> None:
    """Run AI triage over freshly stored alerts; a missing key is a no-op."""
    provider = create_provider()
    if isinstance(provider, NullTriage):
        console.print(
            "[dim]AI triage skipped — set OPENROUTER_API_KEY in .env to enable it. "
            "All alerts are fully recorded without it.[/dim]"
        )
        return
    for alert in alerts:
        result = provider.triage(alert)
        if result is None:
            console.print(f"[yellow]AI triage failed for alert #{alert.id} (see logs)[/yellow]")
            continue
        store.set_ai_summary(alert.id, result.summary)
        console.print(Panel(result.summary, title=f"AI triage — alert #{alert.id} ({result.model})"))


class CollectorSink:
    """Engine sink that remembers every new alert (for post-run triage)."""

    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def emit(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def update(self, alert: Alert) -> None:
        pass


@app.command()
def replay(
    pcap: Path = typer.Argument(..., help="pcap/pcapng file to replay."),
    db: Path = DbOption,
    config: Optional[Path] = ConfigOption,
    triage: bool = typer.Option(
        False, "--triage", help="Generate AI writeups for detected alerts afterwards."
    ),
) -> None:
    """Replay a capture file through the detection engine (primary demo mode)."""
    store = AlertStore(db)
    collector = CollectorSink()
    engine = _build_engine(config, store)
    engine.sinks.append(collector)
    console.print(f"[bold]sentryd[/bold] v{__version__} — replaying [cyan]{pcap}[/cyan]")
    console.print(f"rules: {', '.join(r.rule_id for r in engine.rules)}\n")
    try:
        stats = engine.run(PcapFileSource(pcap).events())
        if triage and collector.alerts:
            console.print()
            _triage_alerts(store, collector.alerts)
    except SourceError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1)
    finally:
        store.close()

    console.print(
        f"\n[bold]done[/bold] — {stats.events_processed} events, "
        f"{stats.alerts_emitted} alerts "
        f"({stats.alerts_deduplicated} duplicates merged)"
    )
    for sev in Severity:
        n = stats.by_severity.get(sev.value)
        if n:
            style = SEVERITY_STYLE[sev]
            console.print(f"  [{style}]{sev.value}[/{style}]: {n}")
    console.print(f"alerts stored in [cyan]{db}[/cyan] — inspect with `sentryd alerts list`")


@alerts_app.command("list")
def alerts_list(
    db: Path = DbOption,
    severity: Optional[str] = typer.Option(None, help="Filter: low|medium|high|critical."),
    rule: Optional[str] = typer.Option(None, help="Filter by rule id."),
    status: Optional[str] = typer.Option(None, help="Filter: new|triaged|dismissed."),
    limit: int = typer.Option(50, help="Max rows."),
) -> None:
    """List stored alerts, newest first."""
    store = AlertStore(db)
    try:
        rows = store.list(severity=severity, rule_id=rule, status=status, limit=limit)
    finally:
        store.close()

    if not rows:
        console.print("no alerts found")
        return

    table = Table(title=f"alerts ({len(rows)})")
    table.add_column("id", justify="right")
    table.add_column("time")
    table.add_column("severity")
    table.add_column("rule")
    table.add_column("src")
    table.add_column("dst")
    table.add_column("title", overflow="fold")
    table.add_column("count", justify="right")
    table.add_column("status")
    table.add_column("AI", justify="center")
    for a in rows:
        style = SEVERITY_STYLE[a.severity]
        table.add_row(
            str(a.id),
            _fmt_ts(a.ts),
            f"[{style}]{a.severity.value}[/{style}]",
            a.rule_id,
            a.src or "-",
            a.dst or "-",
            a.title,
            str(a.count),
            a.status.value,
            "yes" if a.ai_summary else "-",
        )
    console.print(table)


@alerts_app.command("show")
def alerts_show(
    alert_id: int = typer.Argument(..., help="Alert id (see `alerts list`)."),
    db: Path = DbOption,
) -> None:
    """Show one alert in full: metadata, raw evidence, and AI writeup if any."""
    store = AlertStore(db)
    try:
        alert = store.get(alert_id)
    finally:
        store.close()

    if alert is None:
        console.print(f"[red]error:[/red] no alert with id {alert_id}")
        raise typer.Exit(code=1)

    style = SEVERITY_STYLE[alert.severity]
    header = (
        f"[{style}]{alert.severity.value.upper()}[/{style}] {alert.title}\n\n"
        f"rule:       {alert.rule_id}\n"
        f"time:       {_fmt_ts(alert.ts)} UTC\n"
        f"source:     {alert.src or '-'}\n"
        f"target:     {alert.dst or '-'}\n"
        f"confidence: {alert.confidence:.2f}\n"
        f"count:      {alert.count}\n"
        f"status:     {alert.status.value}"
    )
    console.print(Panel(header, title=f"alert #{alert.id}"))
    console.print(Panel(json.dumps(alert.evidence, indent=2), title="evidence"))
    if alert.ai_summary:
        console.print(Panel(alert.ai_summary, title="AI triage"))
    else:
        console.print("[dim]no AI triage yet — run `sentryd triage " f"{alert.id}`[/dim]")


@app.command()
def dash(
    db: Path = DbOption,
    pcap: Optional[Path] = typer.Option(
        None, "--pcap", help="Replay this capture live in the dashboard (timed playback)."
    ),
    config: Optional[Path] = ConfigOption,
    speed: float = typer.Option(
        1.0, "--speed", help="Playback speed multiplier for --pcap (0 = as fast as possible)."
    ),
) -> None:
    """Terminal dashboard: live alert table with drill-down detail view.

    Without --pcap it browses the alert store (and picks up new alerts as
    they land); with --pcap it replays the capture paced by packet
    timestamps — ideal for a screen-recorded demo.
    """
    from sentryd.dashboard.app import DashboardApp

    DashboardApp(db_path=db, pcap=pcap, config_path=config, speed=speed).run()


@app.command()
def web(
    db: Path = DbOption,
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8000, "--port", help="Listen port."),
) -> None:
    """Serve the web UI: filterable alert table, detail view, stats."""
    import uvicorn

    from sentryd.web.api import create_app

    console.print(f"[bold]sentryd[/bold] web UI on [cyan]http://{host}:{port}[/cyan] (db: {db})")
    uvicorn.run(create_app(db), host=host, port=port, log_level="warning")


@app.command()
def triage(
    alert_id: int = typer.Argument(..., help="Alert id to triage (see `alerts list`)."),
    db: Path = DbOption,
    force: bool = typer.Option(False, "--force", help="Regenerate even if a writeup exists."),
) -> None:
    """Generate (or regenerate) the AI analyst writeup for a stored alert.

    Detection never depends on this — it annotates an alert that already
    exists. Requires OPENROUTER_API_KEY in the environment or .env.
    """
    store = AlertStore(db)
    try:
        alert = store.get(alert_id)
        if alert is None:
            console.print(f"[red]error:[/red] no alert with id {alert_id}")
            raise typer.Exit(code=1)
        if alert.ai_summary and not force:
            console.print(Panel(alert.ai_summary, title=f"AI triage — alert #{alert.id} (cached)"))
            console.print("[dim]use --force to regenerate[/dim]")
            return

        provider: TriageProvider = create_provider()
        if isinstance(provider, NullTriage):
            console.print(
                "[yellow]AI triage is not configured.[/yellow] Set OPENROUTER_API_KEY "
                "in .env (see .env.example). The alert itself is complete without it."
            )
            raise typer.Exit(code=2)

        result = provider.triage(alert)
        if result is None:
            console.print("[red]error:[/red] triage request failed — alert left unannotated")
            raise typer.Exit(code=1)
        store.set_ai_summary(alert.id, result.summary)
        console.print(Panel(result.summary, title=f"AI triage — alert #{alert.id} ({result.model})"))
    finally:
        store.close()


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging."),
) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)


if __name__ == "__main__":
    app()
